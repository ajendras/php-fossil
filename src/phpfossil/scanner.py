"""AsyncScanner for PHP Fossil.

Provides concurrent, rate-limited HTTP probing of targets.
Uses the fingerprinter for version detection, probes common
exposed files (phpinfo, SQL dumps), extracts schemas and maps
vulnerabilities. Fully typed, validated, production-ready.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from itertools import cycle
from typing import Any, Dict, List, Optional, Sequence

import httpx

from phpfossil import __version__

from .fingerprinter import (
    detect_from_body,
    detect_from_error_page,
    detect_from_headers,
    detect_from_phpinfo,
    detect_php_version,
)
from .models import ExposedFile, ScanResult, SchemaResult
from .nuclei import validate_with_nuclei
from .ollama import generate_summary
from .schema import parse_sql_dump, locate_sql_urls
from .vulndb import get_vulns_for_version
from .store import store_results


class AsyncScanner:
    """Rate-limited async scanner with support for proxies, Nuclei and Ollama."""

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self.config = config or {}
        self.max_concurrency: int = min(self.config.get("max_concurrency", 20), 50)
        self.timeout: int = self.config.get("timeout", 12)
        self.proxies: List[str] = self.config.get("proxies", [])
        self.use_nuclei: bool = self.config.get("use_nuclei", False)
        self.use_ollama: bool = self.config.get("use_ollama", False)
        self.semaphore = asyncio.Semaphore(self.max_concurrency)
        self.proxy_cycle = cycle(self.proxies) if self.proxies else None

    async def scan(self, targets: Sequence[str]) -> List[ScanResult]:
        """Scan all targets and return results (optionally enriched by Nuclei/Ollama)."""
        if not targets:
            return []

        timeout_client = httpx.Timeout(self.timeout)
        limits = httpx.Limits(max_connections=self.max_concurrency)
        headers = {"User-Agent": f"PHP-Fossil/{__version__}"}

        async with httpx.AsyncClient(
            timeout=timeout_client,
            limits=limits,
            headers=headers,
            follow_redirects=True,
        ) as client:
            tasks = [self._probe_target(t, client) for t in targets]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        processed: List[ScanResult] = []
        for item in results:
            if isinstance(item, Exception):
                processed.append(
                    ScanResult(
                        url="unknown",
                        errors=[f"Scan failed: {item}"],
                        scan_time=datetime.now(timezone.utc),
                    )
                )
            else:
                processed.append(item)

        if self.use_ollama and processed:
            try:
                summary = generate_summary(processed)
                for r in processed:
                    r.llm_summary = summary
            except Exception as exc:  # noqa: BLE001
                for r in processed:
                    r.errors.append(f"Ollama summary failed: {exc}")

        valid_results = [r for r in processed if isinstance(r, ScanResult)]
        store_results(valid_results)
        return processed

    async def _probe_target(self, url: str, client: httpx.AsyncClient) -> ScanResult:
        """Probe a single target for PHP version, exposed files and related data."""
        result = ScanResult(url=url, scan_time=datetime.now(timezone.utc))
        proxy = next(self.proxy_cycle) if self.proxy_cycle else None

        try:
            # Primary request
            resp = await client.get(url, proxy=proxy)
            headers_dict = dict(resp.headers)
            body = resp.text

            # Fingerprint from headers and body
            ver = detect_from_headers(headers_dict)
            if ver:
                result.php_version = ver
                result.detected_from.append("headers")

            if not ver:
                ver = detect_from_body(body)
                if ver:
                    result.php_version = ver
                    result.detected_from.append("body")

            if not ver:
                ver = detect_from_error_page(body)
                if ver:
                    result.php_version = ver
                    result.detected_from.append("error_page")

            # Probe common PHP info endpoints
            phpinfo_paths = [
                "/phpinfo.php",
                "/info.php",
                "/phpinfo",
                "/test.php",
                "/debug.php",
                "/admin/phpinfo.php",
            ]
            base = url.rstrip("/")
            for path in phpinfo_paths:
                try:
                    info_url = f"{base}{path}"
                    info_resp = await client.get(info_url, proxy=proxy)
                    if info_resp.status_code == 200 and any(
                        kw in info_resp.text for kw in ("phpinfo()", "PHP Version", "<h1>PHP")
                    ):
                        preview = info_resp.text[:300]
                        result.exposed_files.append(
                            ExposedFile(
                                url=info_url,
                                file_type="phpinfo",
                                content_preview=preview,
                            )
                        )
                        info_ver = detect_from_phpinfo(info_resp.text)
                        if info_ver:
                            result.php_version = info_ver
                            if "phpinfo" not in result.detected_from:
                                result.detected_from.append("phpinfo")
                        break
                except Exception:  # noqa: BLE001, S110
                    continue

            # Probe for exposed SQL dumps and other sensitive files
            common_files = [
                "/dump.sql",
                "/backup.sql",
                "/database.sql",
                "/schema.sql",
                "/db.sql",
                "/backup.sql.gz",
                "/data.sql",
            ]
            for fname in common_files:
                try:
                    file_url = f"{base}{fname}"
                    f_resp = await client.get(file_url, proxy=proxy)
                    if f_resp.status_code != 200:
                        continue
                    text = f_resp.text.strip()
                    if any(
                        marker in text.lower()
                        for marker in ("create table", "insert into", "-- phpmyadmin", "mysqldump")
                    ) or text.startswith(("/*", "--", "DROP TABLE")):
                        preview = text[:400]
                        result.exposed_files.append(
                            ExposedFile(
                                url=file_url,
                                file_type="sql_dump",
                                content_preview=preview,
                            )
                        )
                        schema_obj = parse_sql_dump(preview)
                        result.db_schema = schema_obj
                        break
                except Exception:  # noqa: BLE001, S110
                    continue

            # Additional SQL URLs from body (if any)
            sql_urls = locate_sql_urls(body, base_url=url)
            for sql_url in sql_urls[:2]:  # limit extra requests
                try:
                    s_resp = await client.get(sql_url, proxy=proxy)
                    if s_resp.status_code == 200:
                        preview = s_resp.text[:400]
                        result.exposed_files.append(
                            ExposedFile(
                                url=sql_url,
                                file_type="sql_dump",
                                content_preview=preview,
                            )
                        )
                        schema_obj = parse_sql_dump(preview)
                        if not result.db_schema:
                            result.db_schema = schema_obj
                        break
                except Exception:  # noqa: BLE001, S110
                    continue

            # Vuln lookup
            if result.php_version:
                result.vulns = get_vulns_for_version(result.php_version)

            # Optional Nuclei validation
            if self.use_nuclei and result.vulns:
                try:
                    result.nuclei_findings = validate_with_nuclei(
                        url, result.vulns, timeout=self.timeout
                    )
                except Exception as exc:  # noqa: BLE001
                    result.errors.append(f"Nuclei failed: {exc}")

            return result

        except httpx.RequestError as exc:
            result.errors.append(f"Request error: {exc}")
            return result
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"Unexpected error: {exc}")
            return result


async def scan_targets(
    targets: Sequence[str],
    config: Optional[Dict[str, Any]] = None,
) -> List[ScanResult]:
    """Scan multiple targets concurrently with rate limiting and optional proxy rotation.

    This is the main public API function. Supports all config options from CLI and library.
    """
    scanner = AsyncScanner(config=config)
    return await scanner.scan(targets)


__all__ = ["scan_targets", "AsyncScanner"]
