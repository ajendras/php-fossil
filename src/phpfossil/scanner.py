"""Async scanner for PHP Fossil.

Orchestrates fingerprinting, vulnerability lookup, schema extraction,
Nuclei validation, Ollama summarization and live callbacks with
rate-limited concurrent HTTP requests and optional proxy rotation.
"""

import asyncio
import random
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

import httpx

from .fingerprinter import (
    CommunityFingerprinter,
    detect_from_phpinfo,
    detect_php_version,
    load_community_fingerprints,
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
    """Probe a single target for PHP version, vulns, exposed files, schema,
    nuclei confirmations and optional LLM summary.

    All feature flags from config are respected. Errors are captured
    in the ScanResult rather than failing the whole scan.
    """
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    result = ScanResult(url=url)
    detected_from: List[str] = []

    try:
        # Primary probe
        resp = await client.get(
            url, follow_redirects=True, timeout=config.get("timeout", 12)
        )
        headers = dict(resp.headers)
        body = resp.text

        # Version fingerprinting (headers, body, community rules)
        use_community = config.get("use_community_fingerprints", False)
        community_rules = None
        if use_community:
            try:
                community_rules = load_community_fingerprints()
            except Exception:  # noqa: BLE001
                community_rules = None

        php_version = detect_php_version(
            headers=headers,
            body=body,
            community_rules=community_rules,
        )
        if php_version:
            result.php_version = php_version
            source = "headers/body"
            if use_community:
                source += "/community"
            detected_from.append(source)
            result.vulns = get_vulns_for_version(php_version)

        # Exposed files & schema extraction (phpinfo, sql dumps, backups)
        common_paths = [
            "/phpinfo.php",
            "/info.php",
            "/backup.sql",
            "/dump.sql",
            "/db.sql",
            "/database.sql",
            "/.env",
        ]
        base = url.rstrip("/")
        for path in common_paths:
            probe_url = f"{base}{path}"
            try:
                r = await client.get(
                    probe_url,
                    timeout=5,
                    follow_redirects=True,
                )
                if r.status_code != 200:
                    continue

                text = r.text
                lower = text.lower()

                if any(
                    kw in lower
                    for kw in ("php version", "mysql", "create table", "insert into")
                ):
                    if "php version" in lower or "phpinfo" in lower:
                        ftype = "phpinfo"
                        if not result.php_version:
                            php_from_info = detect_from_phpinfo(text)
                            if php_from_info:
                                result.php_version = php_from_info
                                detected_from.append("phpinfo")
                    else:
                        ftype = "sql_dump"

                    result.exposed_files.append(
                        ExposedFile(
                            url=str(r.url),
                            file_type=ftype,
                            content_preview=text[:240].replace("\n", " "),
                        )
                    )
                    detected_from.append("exposed-files")

                    if ftype == "sql_dump":
                        try:
                            result.db_schema = parse_sql_dump(text)
                        except Exception:  # noqa: BLE001
                            result.db_schema = SchemaResult()
            except (httpx.RequestError, httpx.TimeoutException, httpx.HTTPStatusError):
                continue
            except Exception:  # noqa: BLE001
                continue

        # Nuclei validation when enabled and vulns present
        if config.get("use_nuclei", False) and result.vulns:
            try:
                findings = validate_with_nuclei(
                    url, result.vulns, timeout=config.get("timeout", 15)
                )
                result.nuclei_findings = findings
                if findings:
                    detected_from.append("nuclei")
            except Exception as exc:  # noqa: BLE001
                result.errors.append(f"Nuclei error: {exc}")

        # Ollama LLM summary when enabled
        if config.get("use_ollama", False):
            try:
                if is_ollama_available():
                    summary = generate_summary(
                        [result],
                        model=config.get("ollama_model", "llama3"),
                        timeout=30,
                    )
                    result.llm_summary = summary
                else:
                    result.llm_summary = (
                        "Ollama not available. Start the service and pull a model."
                    )
                detected_from.append("ollama")
            except Exception as exc:  # noqa: BLE001
                result.errors.append(f"Ollama error: {exc}")
                result.llm_summary = "LLM summarization failed."

        result.detected_from = detected_from
        result.scan_time = datetime.now(timezone.utc)

        if callback:
            callback(result)

        return result

    except Exception as exc:  # noqa: BLE001
        result.errors.append(str(exc))
        result.scan_time = datetime.now(timezone.utc)
        if callback:
            callback(result)
        return result


def _build_client(config: Dict[str, Any]) -> httpx.AsyncClient:
    """Create an AsyncClient with timeout, limits and optional proxy.

    If proxies is a list, a random one is selected (rotation support).
    Only valid httpx parameters are passed, preventing TypeError on
    extraneous config keys.
    """
    timeout = httpx.Timeout(config.get("timeout", 12.0))
    max_concurrency = min(config.get("max_concurrency", 20), 50)
    limits = httpx.Limits(
        max_connections=max_concurrency,
        max_keepalive_connections=max_concurrency // 2,
    )

    proxies = config.get("proxies")
    if isinstance(proxies, list) and proxies:
        proxies = random.choice(proxies)
    elif not proxies:
        proxies = None

    return httpx.AsyncClient(
        timeout=timeout,
        limits=limits,
        follow_redirects=True,
        proxies=proxies,
    )


async def scan_targets(
    targets: List[str],
    config: Optional[Dict[str, Any]] = None,
    callback: Optional[Callable[[ScanResult], None]] = None,
) -> List[ScanResult]:
    """Scan a list of targets concurrently.

    Wraps _probe_target with a semaphore for rate limiting.
    A single client is reused for connection efficiency.
    Results are returned in input order.
    """
    config = config or {}
    if not targets:
        targets = ["https://httpbin.org", "http://example.com"]

    # Lower concurrency for live TUI to keep UI responsive
    if callback:
        config["max_concurrency"] = min(config.get("max_concurrency", 20), 5)

    semaphore = asyncio.Semaphore(config.get("max_concurrency", 20))
    results: List[ScanResult] = []

    client = _build_client(config)
    try:
        async with client:
            tasks = []
            for target_url in targets:

                async def bounded_probe(t: str = target_url) -> ScanResult:
                    async with semaphore:
                        return await _probe_target(client, t, config, callback)

                tasks.append(bounded_probe())

            raw_results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in raw_results:
                if isinstance(r, ScanResult):
                    results.append(r)
                elif isinstance(r, Exception):
                    # Create minimal error result
                    err_result = ScanResult(url="unknown")
                    err_result.errors.append(str(r))
                    results.append(err_result)
    except Exception as exc:  # noqa: BLE001
        err_result = ScanResult(url="scan-error")
        err_result.errors.append(str(exc))
        results.append(err_result)

    return results


class AsyncScanner:
    """Wrapper for the scanner (mirrors NucleiValidator / OllamaSummarizer style)."""

    @staticmethod
    async def scan(
        targets: List[str],
        config: Optional[Dict[str, Any]] = None,
        callback: Optional[Callable[[ScanResult], None]] = None,
    ) -> List[ScanResult]:
        """Run a scan (static convenience method)."""
        return await scan_targets(targets, config, callback)


__all__ = ["scan_targets", "AsyncScanner"]
