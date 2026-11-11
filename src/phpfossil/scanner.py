"""Async scanner for PHP Fossil.

Handles concurrent scanning of targets with rate limiting via semaphore,
proxy support, version fingerprinting via multiple vectors, vuln lookup,
schema extraction, optional Nuclei and Ollama steps, and live callbacks
for the TUI. Consistent with the rest of the codebase.
"""

import asyncio
import random
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

from .fingerprinter import (
    detect_cms_version,
    detect_from_body,
    detect_from_error_page,
    detect_from_headers,
    detect_from_phpinfo,
    detect_php_version,
)
from .models import ExposedFile, ScanResult, SchemaResult
from .nuclei import validate_with_nuclei
from .ollama import generate_summary
from .schema import locate_sql_urls, parse_sql_dump
from .vulndb import get_vulns_for_version


class AsyncScanner:
    """Internal scanner with config-driven concurrency, proxies and feature flags."""

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self.config = config or {}
        self.max_concurrency = min(int(self.config.get("max_concurrency", 20)), 50)
        self.timeout = int(self.config.get("timeout", 12))
        self.proxies: List[str] = self.config.get("proxies") or []
        self.use_nuclei = bool(self.config.get("use_nuclei", False))
        self.use_ollama = bool(self.config.get("use_ollama", False))
        self.ollama_model = self.config.get("ollama_model", "llama3")

    async def scan(
        self,
        targets: List[str],
        callback: Optional[Callable[[ScanResult], None]] = None,
    ) -> List[ScanResult]:
        """Scan targets concurrently and return results.

        Uses a single AsyncClient (with optional proxy). Calls callback
        as each target completes for live UIs. Post-processes with Nuclei/Ollama
        when enabled.
        """
        if not targets:
            return []

        semaphore = asyncio.Semaphore(self.max_concurrency)
        proxy = random.choice(self.proxies) if self.proxies else None

        limits = httpx.Limits(
            max_connections=self.max_concurrency, max_keepalive_connections=self.max_concurrency
        )
        client_kwargs: Dict[str, Any] = {
            "timeout": httpx.Timeout(self.timeout, connect=10.0),
            "limits": limits,
            "follow_redirects": True,
            "headers": {"User-Agent": "PHP-Fossil/0.1.0 (Security Scanner)"},
        }
        if proxy:
            client_kwargs["proxies"] = proxy

        results: List[ScanResult] = []
        async with httpx.AsyncClient(**client_kwargs) as client:
            coros = [self._probe_target(client, semaphore, url) for url in targets]
            for coro in asyncio.as_completed(coros):
                result = await coro
                results.append(result)
                if callback:
                    callback(result)

        if self.use_ollama and results:
            try:
                summary = generate_summary(
                    [r for r in results if r.is_vulnerable() or r.exposed_files],
                    model=self.ollama_model,
                )
                results[0].llm_summary = summary
            except Exception:  # noqa: BLE001
                results[0].errors.append("ollama_summary_failed")

        return sorted(results, key=lambda r: r.url)

    async def _probe_target(
        self, client: httpx.AsyncClient, semaphore: asyncio.Semaphore, url: str
    ) -> ScanResult:
        """Probe one target using multiple vectors; populate ScanResult."""
        async with semaphore:
            result = ScanResult(
                url=url,
                scan_time=datetime.now(timezone.utc),
            )
            try:
                # Primary request
                response = await self._safe_request(client, url)
                if response:
                    self._process_response(response, result)

                # Additional probes for debug files and exposed content
                for path in ("phpinfo.php", "info.php", "test.php", ".env", "backup.sql"):
                    probe_url = f"{url.rstrip('/')}/{path.lstrip('/')}"
                    probe_resp = await self._safe_request(client, probe_url)
                    if not probe_resp or probe_resp.status_code >= 400:
                        continue

                    text = probe_resp.text.lower()
                    if any(k in text for k in ("phpinfo", "php version", "zend")):
                        result.exposed_files.append(
                            ExposedFile(
                                url=probe_url,
                                file_type="phpinfo",
                                content_preview=probe_resp.text[:300],
                            )
                        )
                        ver = (
                            detect_from_phpinfo(probe_resp.text)
                            or detect_from_body(probe_resp.text)
                        )
                        if ver and not result.php_version:
                            result.php_version = ver
                            result.detected_from.append("phpinfo")

                    if any(k in text for k in ("create table", "insert into", "mysqldump", ".sql")):
                        result.exposed_files.append(
                            ExposedFile(
                                url=probe_url,
                                file_type="sql_dump",
                                content_preview=probe_resp.text[:300],
                            )
                        )
                        try:
                            result.db_schema = parse_sql_dump(probe_resp.text)
                        except Exception:  # noqa: BLE001
                            pass

                # Error page probe for version leak
                if not result.php_version:
                    err_url = f"{url.rstrip('/')}/nonexistent-{random.randint(10000, 99999)}.php"
                    err_resp = await self._safe_request(client, err_url)
                    if err_resp and err_resp.status_code >= 400:
                        ver = detect_from_error_page(err_resp.text)
                        if ver:
                            result.php_version = ver
                            result.detected_from.append("error_page")

                # Final combined detection on primary response
                if not result.php_version and response:
                    headers_dict = dict(response.headers)
                    ver = detect_php_version(headers=headers_dict, body=response.text)
                    if ver:
                        result.php_version = ver
                        result.detected_from.append("headers_or_body")

                # CMS detection on primary body
                if response and response.text:
                    cms = detect_cms_version(response.text)
                    if cms:
                        result.detected_from.append(f"cms_{cms[0]}")

                if result.php_version:
                    result.vulns = get_vulns_for_version(result.php_version)

                # Nuclei (only if vulns found)
                if self.use_nuclei and result.vulns:
                    try:
                        result.nuclei_findings = validate_with_nuclei(
                            result.url, result.vulns, timeout=self.timeout
                        )
                    except Exception as exc:  # noqa: BLE001
                        result.errors.append(f"nuclei_failed: {exc}")

                # Additional SQL URLs discovered in body
                if response and response.text:
                    sql_urls = locate_sql_urls(response.text)
                    for s_url in sql_urls[:2]:
                        if not any(f.url == s_url for f in result.exposed_files):
                            s_resp = await self._safe_request(client, s_url)
                            if s_resp and s_resp.status_code == 200:
                                result.exposed_files.append(
                                    ExposedFile(
                                        url=s_url,
                                        file_type="sql_dump",
                                        content_preview=s_resp.text[:200],
                                    )
                                )
                                try:
                                    result.db_schema = parse_sql_dump(s_resp.text)
                                except Exception:  # noqa: BLE001
                                    pass

            except Exception as exc:  # noqa: BLE001
                result.errors.append(str(exc))

            return result

    async def _safe_request(
        self, client: httpx.AsyncClient, url: str, method: str = "GET"
    ) -> Optional[httpx.Response]:
        """Perform request; swallow network errors."""
        try:
            return await client.request(method, url)
        except httpx.RequestError:
            return None
        except Exception:  # noqa: BLE001
            return None

    def _process_response(self, response: httpx.Response, result: ScanResult) -> None:
        """Update result from primary response (headers + body)."""
        if response.status_code != 200:
            return

        headers_dict = dict(response.headers)
        ver = detect_from_headers(headers_dict)
        if ver:
            result.php_version = ver
            result.detected_from.append("headers")

        if not ver:
            ver = detect_from_body(response.text)
            if ver:
                result.php_version = ver
                result.detected_from.append("body")

        text_lower = response.text.lower()
        if "phpinfo" in text_lower or "php version" in text_lower:
            result.exposed_files.append(
                ExposedFile(
                    url=result.url,
                    file_type="phpinfo",
                    content_preview=response.text[:250],
                )
            )
        if any(k in text_lower for k in ("create table", "mysqldump", "dumped from")):
            result.exposed_files.append(
                ExposedFile(
                    url=result.url,
                    file_type="sql_dump",
                    content_preview=response.text[:250],
                )
            )
            try:
                result.db_schema = parse_sql_dump(response.text)
            except Exception:  # noqa: BLE001
                pass


async def scan_targets(
    targets: List[str],
    config: Optional[Dict[str, Any]] = None,
    callback: Optional[Callable[[ScanResult], None]] = None,
) -> List[ScanResult]:
    """Public async API for scanning targets.

    Instantiates AsyncScanner internally and runs the scan. Matches
    signature expected by CLI, TUI and tests.
    """
    scanner = AsyncScanner(config)
    return await scanner.scan(targets, callback)


__all__ = ["scan_targets", "AsyncScanner"]
