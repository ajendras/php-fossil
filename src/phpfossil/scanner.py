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
        self.client: Optional[httpx.AsyncClient] = None

    async def _probe_target(
        self, url: str, semaphore: asyncio.Semaphore, callback: Optional[Callable[[ScanResult], None]] = None
    ) -> ScanResult:
        """Probe a single target with multiple fingerprint vectors and feature steps."""
        result = ScanResult(url=url.strip())
        async with semaphore:
            try:
                proxy = random.choice(self.proxies) if self.proxies else None

                # Primary request
                resp = await self.client.get(
                    url, timeout=self.timeout, proxy=proxy, follow_redirects=True
                )
                headers = dict(resp.headers)
                body = await resp.text()

                version = detect_from_headers(headers)
                detected_from: List[str] = []
                if version:
                    detected_from.append("headers")
                else:
                    version = detect_from_body(body)
                    if version:
                        detected_from.append("body")

                if version:
                    result.php_version = version
                    result.detected_from = detected_from

                # Probe common PHP info endpoints
                info_paths = ["/phpinfo.php", "/info.php", "/test.php", "/?phpinfo=1"]
                for path in info_paths:
                    if "phpinfo" in result.detected_from:
                        break
                    probe_url = url.rstrip("/") + path
                    try:
                        info_resp = await self.client.get(
                            probe_url, timeout=self.timeout, proxy=proxy
                        )
                        if info_resp.status_code == 200:
                            content = await info_resp.text()
                            v = detect_from_phpinfo(content)
                            if v:
                                result.php_version = v
                                result.detected_from.append("phpinfo")
                                result.exposed_files.append(
                                    ExposedFile(
                                        url=probe_url,
                                        file_type="phpinfo",
                                        content_preview=content[:200] + "...",
                                    )
                                )
                                break
                    except Exception as exc:  # noqa: BLE001
                        result.errors.append(f"Info probe failed: {exc}")

                # Probe for exposed SQL/schema files
                sql_paths = ["/backup.sql", "/dump.sql", "/database.sql", "/db_backup.sql"]
                for path in sql_paths:
                    probe_url = url.rstrip("/") + path
                    try:
                        sql_resp = await self.client.get(
                            probe_url, timeout=self.timeout, proxy=proxy
                        )
                        if sql_resp.status_code == 200:
                            content = await sql_resp.text()
                            if any(kw in content.lower() for kw in ("create table", "insert into", "dump", "schema")):
                                result.exposed_files.append(
                                    ExposedFile(
                                        url=probe_url,
                                        file_type="sql_dump",
                                        content_preview=content[:180] + "...",
                                    )
                                )
                                result.db_schema = parse_sql_dump(content)
                                break
                    except Exception:  # noqa: BLE001
                        continue

                # Error-page probe (version leak on 404s) - only if still unknown
                if not result.php_version:
                    for _ in range(3):
                        rand = random.randint(1000, 99999)
                        err_path = f"/nonexistent-{rand}.php"
                        err_url = url.rstrip("/") + err_path
                        try:
                            err_resp = await self.client.get(
                                err_url, timeout=self.timeout, proxy=proxy
                            )
                            content = await err_resp.text()
                            v = detect_from_error_page(content)
                            if v:
                                result.php_version = v
                                result.detected_from.append("error_page")
                                break
                        except Exception as exc:  # noqa: BLE001
                            result.errors.append(str(exc))

                # CMS detection as bonus signal
                if not result.php_version and body:
                    cms = detect_cms_version(body)
                    if cms:
                        result.detected_from.append(f"cms:{cms[0]}")

                # Vulnerability lookup
                if result.php_version:
                    result.vulns = get_vulns_for_version(result.php_version)

                # Nuclei post-validation
                if self.use_nuclei and result.vulns:
                    try:
                        result.nuclei_findings = validate_with_nuclei(
                            result.url, result.vulns, timeout=self.timeout
                        )
                    except Exception as exc:  # noqa: BLE001
                        result.errors.append(f"Nuclei error: {exc}")

                # Ollama LLM summary (only when relevant findings exist)
                if self.use_ollama and (result.vulns or result.exposed_files or result.db_schema):
                    try:
                        result.llm_summary = generate_summary(
                            [result], model=self.ollama_model
                        )
                    except Exception as exc:  # noqa: BLE001
                        result.errors.append(f"Ollama error: {exc}")

                if callback is not None:
                    callback(result)

            except Exception as exc:  # noqa: BLE001
                result.errors.append(str(exc))

            result.scan_time = datetime.now(timezone.utc)
            return result

    async def scan(
        self, targets: List[str], callback: Optional[Callable[[ScanResult], None]] = None
    ) -> List[ScanResult]:
        """Run concurrent scans with rate limiting."""
        if not targets:
            return []

        limits = httpx.Limits(max_connections=self.max_concurrency)
        timeout_cfg = httpx.Timeout(self.timeout, connect=10.0)
        async with httpx.AsyncClient(
            limits=limits, timeout=timeout_cfg, follow_redirects=True
        ) as client:
            self.client = client
            semaphore = asyncio.Semaphore(self.max_concurrency)
            tasks = [self._probe_target(t, semaphore, callback) for t in targets]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            final: List[ScanResult] = []
            for item in results:
                if isinstance(item, ScanResult):
                    final.append(item)
                elif isinstance(item, Exception):
                    final.append(
                        ScanResult(
                            url="unknown",
                            errors=[f"Task failure: {item}"],
                            scan_time=datetime.now(timezone.utc),
                        )
                    )
            return final


def scan_targets(
    targets: List[str],
    config: Optional[Dict[str, Any]] = None,
    callback: Optional[Callable[[ScanResult], None]] = None,
) -> List[ScanResult]:
    """Public API: scan list of targets asynchronously.

    Results are returned as validated ScanResult objects.
    """
    scanner = AsyncScanner(config)
    return asyncio.run(scanner.scan(targets, callback))


__all__ = ["scan_targets"]
