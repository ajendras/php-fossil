"""Async scanner for PHP Fossil.

Handles concurrent scanning with rate limiting, proxy support, fingerprinting,
vuln lookup, schema extraction, optional Nuclei/Ollama/community steps,
and live callbacks. One focused, high-quality improvement per commit.
"""

import asyncio
from typing import Any, Callable, Dict, List, Optional

import httpx

from .fingerprinter import (
    CommunityFingerprinter,
    detect_cms_version,
    detect_php_version,
)
from .models import ExposedFile, ScanResult, SchemaResult
from .nuclei import validate_with_nuclei
from .ollama import generate_summary, is_ollama_available
from .schema import locate_sql_urls, parse_sql_dump
from .vulndb import get_vulns_for_version


async def _probe_target(
    client: httpx.AsyncClient,
    url: str,
    config: Dict[str, Any],
    callback: Optional[Callable[[ScanResult], None]] = None,
) -> ScanResult:
    """Probe a single target, run all detection steps and enrich a ScanResult.

    Order of operations reflects reliability and cost: headers/body first,
    then optional community rules, schema, nuclei and LLM steps.
    """
    result = ScanResult(url=url)
    try:
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"
        result.url = url

        resp = await client.get(url, follow_redirects=True)
        resp.raise_for_status()

        headers = dict(resp.headers)
        body = resp.text

        community_rules = None
        if config.get("use_community_fingerprints", False):
            try:
                community_rules = CommunityFingerprinter.load()
            except Exception:  # noqa: BLE001
                pass  # graceful fallback

        php_version = detect_php_version(
            headers=headers,
            body=body,
            community_rules=community_rules,
        )
        if php_version:
            result.php_version = php_version
            result.detected_from.append("headers/body/community")
            result.vulns.extend(get_vulns_for_version(php_version))

        cms_info = detect_cms_version(body)
        if cms_info:
            result.detected_from.append(f"cms:{cms_info[0]}")

        # Schema extraction
        sql_urls = locate_sql_urls(url, body)
        for sql_url in sql_urls[:3]:  # bounded
            try:
                sql_resp = await client.get(
                    sql_url, timeout=10.0, follow_redirects=True
                )
                if sql_resp.status_code == 200:
                    preview = sql_resp.text[:500]
                    result.exposed_files.append(
                        ExposedFile(
                            url=sql_url,
                            file_type="sql_dump",
                            content_preview=preview,
                        )
                    )
                    result.db_schema = parse_sql_dump(preview)
                    break
            except Exception:  # noqa: BLE001
                continue

        # Nuclei (subprocess, not httpx)
        if config.get("use_nuclei", False) and result.vulns:
            try:
                result.nuclei_findings = validate_with_nuclei(
                    result.url,
                    result.vulns,
                    timeout=config.get("timeout", 15),
                )
            except Exception as exc:  # noqa: BLE001
                result.errors.append(f"nuclei: {exc}")

        # Ollama summary
        if config.get("use_ollama", False):
            try:
                if is_ollama_available():
                    result.llm_summary = generate_summary(
                        [result],
                        model=config.get("ollama_model", "llama3"),
                        timeout=20,
                    )
            except Exception as exc:  # noqa: BLE001
                result.errors.append(f"ollama: {exc}")

        if callback:
            callback(result)

    except httpx.RequestError as exc:
        result.errors.append(f"request: {exc}")
    except Exception as exc:  # noqa: BLE001
        result.errors.append(str(exc))

    return result


async def scan_targets(
    targets: List[str],
    config: Optional[Dict[str, Any]] = None,
    callback: Optional[Callable[[ScanResult], None]] = None,
) -> List[ScanResult]:
    """Public async entrypoint. Rate-limited concurrent scan of targets.

    Proxies are only passed to AsyncClient when a non-empty value is supplied,
    ensuring compatibility with pytest-httpx's mock (which does not declare
    the 'proxies' parameter in its __init__ signature).
    """
    config = config or {}
    max_concurrency = min(int(config.get("max_concurrency", 20)), 50)
    timeout_sec = int(config.get("timeout", 12))

    semaphore = asyncio.Semaphore(max_concurrency)

    client_params: Dict[str, Any] = {
        "timeout": httpx.Timeout(timeout_sec),
        "limits": httpx.Limits(max_connections=max_concurrency),
        "follow_redirects": True,
    }

    proxies = config.get("proxies")
    if proxies and (
        isinstance(proxies, (str, dict))
        or (isinstance(proxies, list) and len(proxies) > 0)
    ):
        client_params["proxies"] = proxies

    async with httpx.AsyncClient(**client_params) as client:
        async def bounded_probe(tgt: str) -> ScanResult:
            async with semaphore:
                return await _probe_target(client, tgt, config, callback)

        tasks = [bounded_probe(t) for t in targets]
        raw_results = await asyncio.gather(*tasks, return_exceptions=True)

    results: List[ScanResult] = []
    for item in raw_results:
        if isinstance(item, Exception):
            results.append(
                ScanResult(
                    url="unknown",
                    errors=[f"Unhandled error: {item}"],
                )
            )
        else:
            results.append(item)

    return results


class AsyncScanner:
    """Thin wrapper for test compatibility and direct instantiation.

    Mirrors the legacy test surface while delegating to the public
    scan_targets coroutine.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self.config = config or {}

    async def scan(
        self,
        targets: List[str],
        callback: Optional[Callable[[ScanResult], None]] = None,
    ) -> List[ScanResult]:
        """Run scan with instance config."""
        return await scan_targets(targets, self.config, callback)


__all__ = ["scan_targets", "AsyncScanner"]
