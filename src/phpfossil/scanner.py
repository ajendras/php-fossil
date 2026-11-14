"""Async scanner for PHP Fossil.

Handles concurrent scanning of targets with rate limiting via semaphore,
proxy support, version fingerprinting via multiple vectors, vuln lookup,
schema extraction, optional Nuclei and Ollama post-processing, and live callbacks
for the TUI. Consistent with the rest of the codebase.
"""

import asyncio
import random
import secrets
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

from .fingerprinter import (
    detect_from_body,
    detect_from_error_page,
    detect_from_headers,
    detect_from_phpinfo,
    detect_php_version,
)
from .models import ExposedFile, ScanResult
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

    def _get_proxy(self) -> Optional[str]:
        """Return a random proxy if configured."""
        if not self.proxies:
            return None
        return random.choice(self.proxies)

    async def _fetch(
        self, client: httpx.AsyncClient, url: str
    ) -> Optional[httpx.Response]:
        """Fetch a URL (with optional proxy) and return response or None on error."""
        try:
            proxy = self._get_proxy()
            return await client.get(
                url, proxy=proxy, follow_redirects=True, timeout=self.timeout
            )
        except httpx.RequestError:
            return None

    async def _probe_target(
        self,
        client: httpx.AsyncClient,
        url: str,
        semaphore: asyncio.Semaphore,
        callback: Optional[Callable[[ScanResult], None]] = None,
    ) -> ScanResult:
        """Probe a single target with multiple vectors for version detection."""
        async with semaphore:
            result = ScanResult(url=url.strip())
            responses: List[httpx.Response] = []
            try:
                base = url.rstrip("/")

                # 1. Main page
                resp = await self._fetch(client, url)
                if resp is not None:
                    responses.append(resp)

                # 2. Common PHP info / debug endpoints that often leak versions
                info_paths = ["/phpinfo.php", "/info.php", "/?phpinfo=1"]
                for path in info_paths:
                    probe_url = (
                        base + path if not path.startswith("?") else url + path
                    )
                    resp = await self._fetch(client, probe_url)
                    if resp is not None:
                        responses.append(resp)
                        if resp.status_code == 200:
                            preview = resp.text[:500] if resp.text else ""
                            ftype = "phpinfo" if "phpinfo" in path else "info"
                            result.exposed_files.append(
                                ExposedFile(
                                    url=probe_url,
                                    file_type=ftype,
                                    content_preview=preview,
                                )
                            )

                # 3. Non-existent .php to trigger error pages that often contain "PHP/X.Y.Z"
                rand = secrets.randbelow(999999)
                err_url = f"{base}/nonexistent-{rand}.php"
                resp = await self._fetch(client, err_url)
                if resp is not None:
                    responses.append(resp)

                # Detect version from any response (headers first, then body, phpinfo, error)
                for resp in responses:
                    if result.php_version:
                        break
                    headers = dict(resp.headers)
                    ver = detect_from_headers(headers)
                    if ver:
                        result.php_version = ver
                        result.detected_from.append("headers")
                        continue

                    ver = detect_from_body(resp.text or "")
                    if ver:
                        result.php_version = ver
                        result.detected_from.append("body")
                        continue

                    if any(p in str(resp.url) for p in ("phpinfo", "info")):
                        ver = detect_from_phpinfo(resp.text or "")
                        if ver:
                            result.php_version = ver
                            result.detected_from.append("phpinfo")
                            continue

                    if resp.status_code >= 400:
                        ver = detect_from_error_page(resp.text or "")
                        if ver:
                            result.php_version = ver
                            result.detected_from.append("error_page")
                            continue

                # Fallback combined detection
                if not result.php_version:
                    combined = " ".join(
                        r.text or "" for r in responses if r.text
                    )
                    ver = detect_php_version(body=combined)
                    if ver:
                        result.php_version = ver
                        result.detected_from.append("combined")

                # Vuln lookup
                if result.php_version:
                    result.vulns = get_vulns_for_version(result.php_version)

                # Schema extraction from exposed SQL dumps
                for resp in responses:
                    if not resp.text:
                        continue
                    sql_urls = locate_sql_urls(resp.text)
                    for s_url in sql_urls[:2]:  # limit probes
                        s_resp = await self._fetch(client, s_url)
                        if s_resp is not None and s_resp.status_code == 200:
                            preview = s_resp.text[:400] if s_resp.text else ""
                            result.exposed_files.append(
                                ExposedFile(
                                    url=s_url,
                                    file_type="sql_dump",
                                    content_preview=preview,
                                )
                            )
                            result.db_schema = parse_sql_dump(s_resp.text)
                            break
                    if result.db_schema:
                        break

                # Optional Nuclei validation
                if self.use_nuclei and result.vulns:
                    try:
                        result.nuclei_findings = validate_with_nuclei(
                            result.url, result.vulns, timeout=self.timeout
                        )
                    except Exception:  # noqa: BLE001
                        result.errors.append("Nuclei validation failed")

                # Optional Ollama summary
                if self.use_ollama:
                    try:
                        result.llm_summary = generate_summary(
                            [result], model=self.ollama_model
                        )
                    except Exception:  # noqa: BLE001
                        result.errors.append("Ollama summary unavailable")

                if callback is not None:
                    callback(result)

                return result

            except Exception as exc:  # noqa: BLE001
                result.errors.append(str(exc))
                if callback is not None:
                    callback(result)
                return result

    async def scan(
        self,
        targets: List[str],
        callback: Optional[Callable[[ScanResult], None]] = None,
    ) -> List[ScanResult]:
        """Scan multiple targets concurrently."""
        if not targets:
            return []

        semaphore = asyncio.Semaphore(self.max_concurrency)
        limits = httpx.Limits(max_keepalive_connections=5, max_connections=self.max_concurrency)

        async with httpx.AsyncClient(timeout=self.timeout, limits=limits) as client:
            tasks = [
                self._probe_target(client, target, semaphore, callback)
                for target in targets
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            final: List[ScanResult] = []
            for i, item in enumerate(results):
                if isinstance(item, Exception):
                    err_result = ScanResult(url=targets[i])
                    err_result.errors.append(str(item))
                    final.append(err_result)
                else:
                    final.append(item)
            return final


async def scan_targets(
    targets: List[str],
    config: Optional[Dict[str, Any]] = None,
    callback: Optional[Callable[[ScanResult], None]] = None,
) -> List[ScanResult]:
    """Public async entrypoint for scanning targets.

    Wrap with asyncio.run() when calling from synchronous code.
    """
    if not targets:
        targets = ["https://httpbin.org", "http://example.com"]
    scanner = AsyncScanner(config=config)
    return await scanner.scan(targets, callback=callback)


__all__ = ["scan_targets", "AsyncScanner"]
