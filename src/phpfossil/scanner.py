"""Async scanner for PHP Fossil.

The core scanning engine. Uses a rate-limited AsyncClient to probe targets,
delegates to fingerprinter, vulndb, schema, nuclei and ollama modules.
Supports live callback for TUI, persistent results, error handling.
"""

import asyncio
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urljoin

import httpx

from .fingerprinter import (
    CommunityFingerprinter,
    detect_cms_version,
    detect_php_version,
    load_community_fingerprints,
)
from .models import ExposedFile, NucleiFinding, ScanResult, SchemaResult
from .nuclei import validate_with_nuclei
from .ollama import generate_summary
from .schema import find_exposed_sql_dumps
from .store import store_results
from .vulndb import get_vulns_for_version


async def scan_targets(
    targets: List[str],
    config: Optional[Dict[str, Any]] = None,
    callback: Optional[Callable[[ScanResult], None]] = None,
) -> List[ScanResult]:
    """Scan a list of targets for legacy PHP issues.

    Main public API entrypoint. Automatically persists results to the
    SQLite store. Supports concurrency limits, proxies, Nuclei, Ollama
    and community fingerprints via the config dict.
    """
    if config is None:
        config = {}

    max_concurrency = min(int(config.get("max_concurrency", 20)), 50)
    timeout = int(config.get("timeout", 12))
    use_nuclei = bool(config.get("use_nuclei", False))
    use_ollama = bool(config.get("use_ollama", False))
    use_community = bool(config.get("use_community_fingerprints", False))
    proxies = config.get("proxies", [])

    community_rules = None
    if use_community:
        try:
            community_rules = load_community_fingerprints()
        except Exception:  # noqa: BLE001
            community_rules = CommunityFingerprinter.load()

    results: List[ScanResult] = []
    semaphore = asyncio.Semaphore(max_concurrency)

    limits = httpx.Limits(max_connections=max_concurrency, max_keepalive_connections=max_concurrency)
    async with httpx.AsyncClient(
        timeout=timeout,
        proxies=proxies if proxies else None,
        follow_redirects=True,
        headers={"User-Agent": "PHP-Fossil-Scanner/0.1.0"},
        limits=limits,
    ) as client:
        tasks = [
            _probe_target(
                url=url,
                client=client,
                semaphore=semaphore,
                use_nuclei=use_nuclei,
                use_ollama=use_ollama,
                community_rules=community_rules,
                callback=callback,
                timeout=timeout,
            )
            for url in targets
        ]
        for coro in asyncio.as_completed(tasks):
            result = await coro
            results.append(result)
            if callback:
                callback(result)

    store_results(results)
    return results


async def _probe_target(
    url: str,
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    use_nuclei: bool,
    use_ollama: bool,
    community_rules: Optional[List] = None,
    callback: Optional[Callable[[ScanResult], None]] = None,
    timeout: int = 12,
) -> ScanResult:
    """Probe a single target asynchronously under semaphore."""
    async with semaphore:
        result = ScanResult(url=url.strip())
        try:
            response = await client.get(url)
            response.raise_for_status()

            headers = dict(response.headers)
            body = response.text

            php_version = detect_php_version(
                headers=headers,
                body=body,
                community_rules=community_rules,
            )
            if php_version:
                result.php_version = php_version
                detected_source = "headers" if "php" in str(headers).lower() else "body"
                result.detected_from.append(detected_source)
                result.vulns = get_vulns_for_version(php_version)

            cms_info = detect_cms_version(body)
            if cms_info:
                result.detected_from.append(f"cms:{cms_info[0]}")

            # Check for obvious phpinfo exposure in main response
            if any(phrase in body.lower() for phrase in ("phpinfo", "php version", "configuration")):
                phpinfo_url = urljoin(url.rstrip("/") + "/", "phpinfo.php")
                result.exposed_files.append(
                    ExposedFile(
                        url=phpinfo_url,
                        file_type="phpinfo",
                        content_preview=body[:180] + ("..." if len(body) > 180 else ""),
                    )
                )

            # Schema / exposed SQL dumps
            sql_files, db_schema = find_exposed_sql_dumps(url, timeout=timeout)
            result.exposed_files.extend(sql_files)
            if db_schema and db_schema.tables:
                result.db_schema = db_schema

            # Nuclei validation
            if use_nuclei and result.vulns:
                try:
                    result.nuclei_findings = validate_with_nuclei(
                        url, result.vulns, timeout=timeout
                    )
                except Exception as exc:  # noqa: BLE001
                    result.errors.append(f"Nuclei error: {exc}")

            # Ollama summary (only if there is something meaningful to summarize)
            if use_ollama and (result.vulns or result.db_schema or result.nuclei_findings):
                try:
                    result.llm_summary = generate_summary([result])
                except Exception as exc:  # noqa: BLE001
                    result.llm_summary = f"# Summary unavailable\n\nOllama error: {exc}"

            result.scan_time = datetime.now(timezone.utc)

        except httpx.HTTPStatusError as exc:
            result.errors.append(f"HTTP error {exc.response.status_code}")
        except httpx.RequestError as exc:
            result.errors.append(f"Request error: {exc}")
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"Unexpected error: {exc}")

        return result


class AsyncScanner:
    """Object-oriented wrapper around scan_targets (for extensibility and TUI)."""

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self.config = config or {}

    async def scan(self, targets: List[str], callback: Optional[Callable[[ScanResult], None]] = None) -> List[ScanResult]:
        """Perform a scan with the configured options."""
        return await scan_targets(targets, self.config, callback=callback)


__all__ = ["scan_targets", "AsyncScanner"]
