"""Async scanner for PHP Fossil.

Handles concurrent, rate-limited scanning of targets with:
- Rotating User-Agent pool (built-in default or custom)
- Optional proxy rotation
- Multi-source PHP version fingerprinting (headers, body, phpinfo, community rules)
- Vulnerability mapping from embedded VulnDB
- Detection of exposed SQL dumps + schema parsing
- Optional Nuclei validation for confirmed exploits
- Optional Ollama LLM summarization
- Live callback support (for TUI/real-time UI updates)
- Automatic storage of results

All tests in test_scanner.py now pass with realistic mocks.
"""

import asyncio
from collections.abc import Callable
from itertools import cycle
from typing import Any, Dict, List, Optional, Union

import httpx

from .fingerprinter import (
    detect_from_body,
    detect_from_headers,
    detect_php_version,
    load_community_fingerprints,
)
from .models import (
    ConfigSettings,
    ExposedFile,
    NucleiFinding,
    ScanResult,
    SchemaResult,
    DEFAULT_USER_AGENTS,
)
from .nuclei import validate_with_nuclei
from .ollama import generate_summary, is_ollama_available
from .schema import locate_sql_urls, parse_sql_dump
from .store import store_results
from .vulndb import get_vulns_for_version, is_version_eol


def _compute_risk_score(result: ScanResult) -> int:
    """Compute risk score (0-100) based on PHP version age, vulns, exposed assets,
    nuclei findings, schema sensitivity and EOL status.
    """
    if not result.php_version:
        return 0
    score = 0
    major_minor = result.php_version.split(".")[:2]
    major = int(major_minor[0])
    if major <= 5:
        score += 80
    elif major == 7:
        score += 50
    elif major == 8 and (len(major_minor) > 1 and major_minor[1] == "0"):
        score += 30
    else:
        score += 10
    score += len(result.vulns) * 12
    score += len(result.exposed_files) * 20
    score += len(result.nuclei_findings) * 25
    if result.db_schema and result.db_schema.sensitive_columns:
        score += 25
    if is_version_eol(result.php_version):
        score += 15
    return min(score, 100)


async def scan_targets(
    targets: List[str],
    config: Optional[Union[ConfigSettings, Dict[str, Any]]] = None,
    callback: Optional[Callable[[ScanResult], None]] = None,
) -> List[ScanResult]:
    """Scan list of targets concurrently and return ScanResult objects.

    Accepts config as dict (validated to ConfigSettings) or ConfigSettings instance.
    Supports UA rotation, proxies, community fingerprints, nuclei, ollama and live callbacks.
    Results are automatically stored to SQLite.
    """
    if not targets:
        return []

    if config is None:
        config = ConfigSettings()
    elif isinstance(config, dict):
        config = ConfigSettings.model_validate(config)
    elif not isinstance(config, ConfigSettings):
        config = ConfigSettings.model_validate(config.model_dump())

    community_rules = (
        load_community_fingerprints(config.community_repo_url)
        if config.use_community_fingerprints
        else None
    )

    semaphore = asyncio.Semaphore(config.max_concurrency)
    ua_cycle = cycle(config.user_agents)
    proxy_cycle = cycle(config.proxies or [None])

    results: List[ScanResult] = []

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(config.timeout),
        limits=httpx.Limits(max_connections=config.max_concurrency, max_keepalive_connections=10),
        follow_redirects=True,
    ) as client:

        async def _probe_target(url: str) -> ScanResult:
            async with semaphore:
                ua = next(ua_cycle)
                proxy = next(proxy_cycle)
                headers = {"User-Agent": ua}
                try:
                    response = await client.get(url, headers=headers, proxy=proxy)
                    version = detect_php_version(
                        headers=response.headers,
                        body=response.text,
                        community_rules=community_rules,
                    )
                    detected_from: List[str] = []
                    if version:
                        if detect_from_headers(response.headers):
                            detected_from.append("headers")
                        elif detect_from_body(response.text):
                            detected_from.append("body")
                        else:
                            detected_from.append("community")

                    vulns = get_vulns_for_version(version) if version else []
                    exposed_files: List[ExposedFile] = []
                    db_schema: Optional[SchemaResult] = None
                    sql_urls = locate_sql_urls(response.text)
                    for s_url in sql_urls[:3]:
                        try:
                            s_resp = await client.get(
                                s_url,
                                headers=headers,
                                proxy=proxy,
                                timeout=httpx.Timeout(8.0),
                            )
                            if s_resp.is_success:
                                content = s_resp.text
                                parsed_schema = parse_sql_dump(content)
                                exposed_files.append(
                                    ExposedFile(
                                        url=s_url,
                                        content_type=s_resp.headers.get(
                                            "content-type", "text/plain"
                                        ),
                                        size=len(content),
                                        snippet=content[:400] if content else None,
                                    )
                                )
                                if parsed_schema.tables:
                                    db_schema = parsed_schema
                        except Exception:  # noqa: BLE001
                            continue

                    nuclei_findings: List[NucleiFinding] = []
                    if config.use_nuclei and version:
                        try:
                            nuclei_findings = validate_with_nuclei([url])
                        except Exception:  # noqa: BLE001
                            pass

                    result = ScanResult(
                        url=url,
                        php_version=version,
                        detected_from=detected_from,
                        vulns=vulns,
                        exposed_files=exposed_files,
                        db_schema=db_schema,
                        nuclei_findings=nuclei_findings,
                        llm_summary=None,
                        risk_score=0,
                    )
                    result.risk_score = _compute_risk_score(result)

                    if callback:
                        callback(result)
                    return result

                except httpx.RequestError:
                    result = ScanResult(
                        url=url,
                        php_version=None,
                        detected_from=[],
                        vulns=[],
                        risk_score=20,
                    )
                    if callback:
                        callback(result)
                    return result
                except Exception:  # noqa: BLE001
                    result = ScanResult(
                        url=url,
                        php_version=None,
                        detected_from=[],
                        vulns=[],
                        risk_score=0,
                    )
                    if callback:
                        callback(result)
                    return result

        probe_tasks = [asyncio.create_task(_probe_target(t)) for t in targets]
        for completed in asyncio.as_completed(probe_tasks):
            res = await completed
            results.append(res)

    # Ollama summarization (one summary for the whole batch)
    if (
        config.use_ollama
        and results
        and any(r.php_version for r in results)
        and is_ollama_available()
    ):
        try:
            summary_text = generate_summary(
                [r for r in results if r.php_version], model=config.ollama_model
            )
            for r in results:
                r.llm_summary = summary_text
        except Exception:  # noqa: BLE001
            for r in results:
                r.llm_summary = "LLM summarization unavailable at this time."

    # Persist to SQLite (non-fatal if store fails)
    try:
        store_results(results)
    except Exception:  # noqa: BLE001
        pass

    return results


__all__ = ["scan_targets"]
