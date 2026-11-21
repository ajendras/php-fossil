"""Async PHP scanner with rate limiting, UA rotation, proxy support and multiple detection methods.

The main entrypoint `scan_targets` is async and accepts a ConfigSettings object or dict.
It uses a single shared httpx.AsyncClient for efficiency. Version detection is delegated
to fingerprinter.detect_php_version (with optional community rules). Post-processing
includes VulnDB lookup, schema parsing, optional Nuclei and Ollama steps.
The live callback is called after each target completes (used by TUI).
"""

import asyncio
import random
from typing import Any, Callable, Dict, List, Optional, Union

import httpx

from .fingerprinter import (
    CommunityFingerprinter,
    detect_from_error_page,
    detect_from_headers,
    detect_from_phpinfo,
    detect_php_version,
)
from .models import ConfigSettings, DEFAULT_USER_AGENTS, ExposedFile, ScanResult
from .nuclei import validate_with_nuclei
from .ollama import generate_summary, is_ollama_available
from .schema import locate_sql_urls, parse_sql_dump
from .vulndb import get_vulns_for_version


def _compute_risk_score(result: ScanResult) -> int:
    """Internal risk scoring used by tests and scanner.

    Factors: version age, # of vulns, nuclei confirmations, exposed files, schema sensitivity.
    """
    if not result.php_version:
        return 0

    score = 20  # base for any legacy PHP

    # Increase for older versions
    if result.php_version.startswith(("5.", "7.0", "7.1", "7.2")):
        score += 50
    elif result.php_version.startswith("7."):
        score += 30
    elif result.php_version.startswith("8.0"):
        score += 15

    score += len(result.vulns) * 10
    score += len(result.nuclei_findings) * 20
    score += len(result.exposed_files) * 15

    if result.db_schema:
        score += 10
        score += len(result.db_schema.sensitive_columns) * 5

    return min(score, 100)


async def _probe_target(
    client: httpx.AsyncClient,
    url: str,
    config: ConfigSettings,
    community_rules: Optional[List[Any]] = None,
    callback: Optional[Callable[[ScanResult], None]] = None,
) -> ScanResult:
    """Probe one target. Returns populated ScanResult. Uses provided client."""
    result = ScanResult(url=url)
    ua = random.choice(config.user_agents)
    headers = {"User-Agent": ua}
    proxy = random.choice(config.proxies) if config.proxies else None

    # Main request
    try:
        resp = await client.get(
            url, headers=headers, proxy=proxy, timeout=config.timeout
        )
        version = detect_php_version(
            dict(resp.headers),
            resp.text,
            community_rules=community_rules,
        )
        if version:
            result.php_version = version
            result.detected_from.append(
                "headers" if detect_from_headers(dict(resp.headers)) else "body"
            )
    except httpx.HTTPStatusError as e:
        # Try error page leak
        version = detect_from_error_page(
            e.response.text if hasattr(e, "response") and e.response else ""
        )
        if version:
            result.php_version = version
            result.detected_from.append("error_page")
    except Exception:
        pass

    if not result.php_version:
        # Probe common phpinfo locations
        for suffix in ("/phpinfo.php", "/info.php", "/phpinfo"):
            try:
                purl = f"{url.rstrip('/')}{suffix}"
                resp = await client.get(
                    purl, headers=headers, proxy=proxy, timeout=config.timeout
                )
                version = detect_from_phpinfo(resp.text)
                if not version:
                    version = detect_php_version(
                        body=resp.text, community_rules=community_rules
                    )
                if version:
                    result.php_version = version
                    result.detected_from.append("phpinfo")
                    break
            except Exception:
                continue

    if result.php_version:
        result.vulns = get_vulns_for_version(result.php_version)
        result.risk_score = _compute_risk_score(result)

    # Exposed SQL files
    try:
        for sql_url in locate_sql_urls(url)[:2]:
            try:
                resp = await client.get(
                    sql_url, headers=headers, proxy=proxy, timeout=config.timeout
                )
                if resp.status_code == 200 and any(
                    kw in resp.text.lower() for kw in ("create table", "insert into", "dump")
                ):
                    result.exposed_files.append(
                        ExposedFile(url=sql_url, snippet=resp.text[:300])
                    )
                    if result.db_schema is None:
                        result.db_schema = parse_sql_dump(resp.text)
            except Exception:
                continue
    except Exception:
        pass

    # Nuclei
    if config.use_nuclei:
        try:
            result.nuclei_findings = validate_with_nuclei([url])
            if result.nuclei_findings:
                result.risk_score = _compute_risk_score(result)
        except Exception:
            pass

    # Ollama
    if config.use_ollama:
        try:
            if is_ollama_available(timeout=2):
                result.llm_summary = generate_summary([result], config.ollama_model)
        except Exception:
            result.llm_summary = "Summary generation failed (Ollama not available)."

    if callback is not None:
        callback(result)

    return result


async def scan_targets(
    targets: List[str],
    config: Optional[Union[ConfigSettings, Dict[str, Any]]] = None,
    callback: Optional[Callable[[ScanResult], None]] = None,
) -> List[ScanResult]:
    """Main async scanning function.

    - Accepts dict or ConfigSettings (validated).
    - Rotates User-Agents and proxies per request.
    - Uses semaphore for concurrency control.
    - Calls live callback after each target for real-time UIs.
    - Gracefully handles errors per target.
    """
    if isinstance(config, dict) or config is None:
        config = ConfigSettings(**(config or {}))
    if not config.user_agents:
        config.user_agents = DEFAULT_USER_AGENTS[:]

    community_rules = None
    if config.use_community_fingerprints:
        try:
            community_rules = CommunityFingerprinter.load(config.community_repo_url)
        except Exception:
            pass  # fallback to built-in in detect_php_version

    results: List[ScanResult] = []

    limits = httpx.Limits(
        max_connections=config.max_concurrency,
        max_keepalive_connections=config.max_concurrency,
    )
    timeout = httpx.Timeout(config.timeout, connect=5.0)

    async with httpx.AsyncClient(
        limits=limits,
        timeout=timeout,
        follow_redirects=True,
    ) as client:
        semaphore = asyncio.Semaphore(config.max_concurrency)

        async def _scan_one(target: str):
            async with semaphore:
                try:
                    r = await _probe_target(
                        client, target, config, community_rules, callback
                    )
                    results.append(r)
                except Exception:
                    # graceful error handling as tested by test_scan_error_graceful
                    err_result = ScanResult(url=target, php_version=None)
                    results.append(err_result)
                    if callback:
                        callback(err_result)

        await asyncio.gather(*[_scan_one(t) for t in targets])

    return results


__all__ = [
    "scan_targets",
    "_compute_risk_score",  # exported for test compatibility
]
