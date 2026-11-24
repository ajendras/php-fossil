"""Async scanner for PHP Fossil with global + per-domain rate limiting using asyncio.Semaphore.

Uses rotating User-Agents and optional proxy rotation. Supports live callback for TUI.
Post-processes with Nuclei, Ollama, community fingerprints, schema extraction and
risk scoring. All existing features are preserved.
"""

import asyncio
import itertools
import logging
import random
from collections.abc import Callable
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import httpx

from .fingerprinter import (
    CommunityFingerprinter,
    detect_cms_version,
    detect_from_phpinfo,
    detect_from_error_page,
    detect_php_version,
    detect_with_community_rules,
)
from .models import ConfigSettings, ExposedFile, ScanResult, SchemaResult
from .nuclei import validate_with_nuclei
from .ollama import generate_summary, is_ollama_available
from .schema import locate_sql_urls, parse_sql_dump
from .vulndb import get_vulns_for_version, is_version_eol

logger = logging.getLogger(__name__)


def _calculate_risk_score(
    php_version: Optional[str],
    vulns: List[Any],
    exposed_files: List[ExposedFile],
    nuclei_findings: List[Any],
) -> int:
    """Compute 0-100 risk score. Factors in EOL status, version age,
    vulnerability count, confirmed nuclei exploits and exposed schema sensitivity.
    """
    score = 20
    if not php_version or php_version == "unknown":
        return 25
    if is_version_eol(php_version):
        score += 35
    try:
        major = int(php_version.split(".")[0])
        if major <= 7:
            score += 25
        elif major == 8 and php_version.startswith("8.0"):
            score += 10
    except ValueError:
        pass
    score += len(vulns) * 8
    score += len(nuclei_findings) * 12
    if exposed_files and any(
        "sql" in (f.url.lower() or "") or "sql" in (f.content_type or "").lower()
        for f in exposed_files
    ):
        score += 30
    return min(100, max(0, score))


async def _probe_target(
    url: str,
    client: httpx.AsyncClient,
    config: ConfigSettings,
    global_sem: asyncio.Semaphore,
    domain_sems: Dict[str, asyncio.Semaphore],
    domain_lock: asyncio.Lock,
    callback: Optional[Callable[[ScanResult], Any]] = None,
) -> ScanResult:
    """Probe a single target. Enforces both global concurrency and per-domain
    rate limiting via dedicated asyncio.Semaphore instances.
    """
    parsed = urlparse(url)
    domain = parsed.netloc

    async with domain_lock:
        if domain not in domain_sems:
            domain_sems[domain] = asyncio.Semaphore(config.per_domain_limit)
    per_domain_sem = domain_sems[domain]

    async with per_domain_sem, global_sem:
        logger.debug("Probing %s (domain=%s)", url, domain)
        ua = random.choice(config.user_agents)
        headers = {"User-Agent": ua}
        proxy = random.choice(config.proxies) if config.proxies else None

        try:
            resp = await client.get(
                url,
                headers=headers,
                proxy=proxy,
                timeout=config.timeout,
            )
            resp.raise_for_status()
            headers_d = {k.lower(): v for k, v in resp.headers.items()}
            body = resp.text

            php_version = detect_php_version(headers_d, body=body)
            detected_from: List[str] = []
            if php_version:
                detected_from.append("headers" if "x-powered-by" in headers_d else "body")

            if config.use_community_fingerprints and not php_version:
                php_version = detect_with_community_rules(body)
                if php_version:
                    detected_from.append("community")

            # phpinfo fallback
            if not php_version:
                for path in ("/phpinfo.php", "/info.php"):
                    try:
                        purl = urljoin(url, path)
                        p_resp = await client.get(
                            purl,
                            headers=headers,
                            proxy=proxy,
                            timeout=min(8, config.timeout),
                        )
                        if p_resp.is_success:
                            php_version = detect_from_phpinfo(p_resp.text)
                            if php_version:
                                detected_from.append("phpinfo")
                                break
                    except Exception:
                        continue

            # error page fallback
            if not php_version:
                php_version = detect_from_error_page(body)
                if php_version:
                    detected_from.append("error_page")

            if not php_version:
                php_version = "unknown"

            # CMS detection (non-blocking)
            cms, _ = detect_cms_version(body)

            # exposed SQL dumps
            exposed_files: List[ExposedFile] = []
            sql_candidates = locate_sql_urls(body)
            for candidate in sql_candidates[:3]:
                s_url = urljoin(url, candidate) if not candidate.startswith(("http://", "https://")) else candidate
                try:
                    s_resp = await client.get(
                        s_url,
                        headers=headers,
                        proxy=proxy,
                        timeout=min(10, config.timeout),
                    )
                    if s_resp.is_success and (
                        "sql" in s_resp.headers.get("content-type", "").lower()
                        or s_url.lower().endswith((".sql", ".dump"))
                    ):
                        snippet = s_resp.text[:400] if s_resp.text else None
                        exposed_files.append(
                            ExposedFile(
                                url=s_url,
                                content_type=s_resp.headers.get("content-type", "text/plain"),
                                size=len(s_resp.content),
                                snippet=snippet,
                            )
                        )
                except Exception:
                    continue

            # schema parsing
            db_schema = None
            if exposed_files:
                try:
                    parsed_schema = parse_sql_dump(exposed_files[0].snippet or "")
                    db_schema = SchemaResult(
                        tables=parsed_schema.get("tables", []),
                        raw_tables=len(parsed_schema.get("tables", [])),
                        sensitive_columns=parsed_schema.get("sensitive_columns", []),
                    )
                except Exception:
                    pass

            vulns = get_vulns_for_version(php_version) if php_version != "unknown" else []
            nuclei_findings = []
            if config.use_nuclei:
                try:
                    nuclei_findings = validate_with_nuclei([url])
                except Exception as exc:
                    logger.debug("Nuclei skipped for %s: %s", url, exc)

            risk_score = _calculate_risk_score(
                php_version, vulns, exposed_files, nuclei_findings
            )

            result = ScanResult(
                url=url,
                php_version=php_version,
                detected_from=detected_from,
                vulns=vulns,
                exposed_files=exposed_files,
                db_schema=db_schema,
                nuclei_findings=nuclei_findings,
                risk_score=risk_score,
            )

            if callback:
                try:
                    callback(result)
                except Exception as cb_exc:
                    logger.warning("Callback failed for %s: %s", url, cb_exc)

            return result

        except httpx.RequestError as exc:
            logger.warning("Request failed for %s: %s", url, exc)
            return ScanResult(url=url, php_version=None, risk_score=15)
        except Exception as exc:
            logger.error("Unexpected error scanning %s: %s", url, exc)
            return ScanResult(url=url, php_version=None, risk_score=10)


async def scan_targets(
    targets: List[str],
    config: Optional[Any] = None,
    callback: Optional[Callable[[ScanResult], Any]] = None,
) -> List[ScanResult]:
    """Public async entrypoint. Normalises config, applies per-domain
    asyncio.Semaphore limiting per host (default 5) and global concurrency.
    Returns list of ScanResult objects. All prior behaviour is preserved.
    """
    if isinstance(config, dict):
        config = ConfigSettings.model_validate(config)
    elif config is None or not isinstance(config, ConfigSettings):
        config = ConfigSettings()

    if not targets:
        return []

    # TUI-friendly default
    if callback and config.max_concurrency > 5:
        config.max_concurrency = 5

    logger.info(
        "Starting scan of %d target(s) (global=%d, per-domain=%d, nuclei=%s, ollama=%s)",
        len(targets),
        config.max_concurrency,
        config.per_domain_limit,
        config.use_nuclei,
        config.use_ollama,
    )

    limits = httpx.Limits(
        max_connections=config.max_concurrency * 2,
        max_keepalive_connections=config.max_concurrency,
        keepalive_expiry=30,
    )
    timeout = httpx.Timeout(config.timeout, connect=10.0)

    domain_sems: Dict[str, asyncio.Semaphore] = {}
    domain_lock = asyncio.Lock()
    global_sem = asyncio.Semaphore(config.max_concurrency)

    async with httpx.AsyncClient(
        limits=limits,
        timeout=timeout,
        follow_redirects=True,
    ) as client:
        tasks = []
        for t in targets:
            norm_url = t if t.startswith(("http://", "https://")) else f"https://{t}"
            tasks.append(
                _probe_target(
                    norm_url,
                    client,
                    config,
                    global_sem,
                    domain_sems,
                    domain_lock,
                    callback,
                )
            )
        raw_results = await asyncio.gather(*tasks, return_exceptions=True)

    processed: List[ScanResult] = []
    for item in raw_results:
        if isinstance(item, Exception):
            logger.warning("Task exception: %s", item)
            continue
        processed.append(item)

    if config.use_ollama and processed and is_ollama_available():
        try:
            summary = generate_summary(processed, model=config.ollama_model)
            for res in processed:
                if res.is_vulnerable():
                    res.llm_summary = summary
        except Exception as exc:
            logger.warning("Ollama summarization failed: %s", exc)

    logger.info("Scan finished – %d valid result(s)", len(processed))
    return processed
