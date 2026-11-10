"""AsyncScanner for PHP Fossil.

Provides concurrent, rate-limited HTTP probing of targets.
Uses the fingerprinter for version detection, probes common
exposed files (phpinfo, SQL dumps), extracts schemas and maps
vulnerabilities. Fully typed, validated, production-ready.
Supports an optional live callback used by the Textual TUI.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from itertools import cycle
from typing import Any, Callable, Dict, List, Optional, Sequence

import httpx

from .fingerprinter import (
    detect_cms_version,
    detect_from_body,
    detect_from_headers,
    detect_from_phpinfo,
    detect_php_version,
)
from .models import ExposedFile, ScanResult, SchemaResult
from .nuclei import validate_with_nuclei
from .ollama import generate_summary
from .schema import locate_sql_urls, parse_sql_dump
from .vulndb import get_vulns_for_version
from .store import store_results


class AsyncScanner:
    """Rate-limited async scanner with support for proxies, Nuclei and Ollama."""

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self.config = config or {}
        self.max_concurrency: int = min(self.config.get("max_concurrency", 20), 50)
        self.timeout: int = self.config.get("timeout", 12)
        self.proxies: List[str] = self.config.get("proxies", [])
        self.proxy_cycle = cycle(self.proxies) if self.proxies else None
        self.use_nuclei = self.config.get("use_nuclei", False)
        self.use_ollama = self.config.get("use_ollama", False)

    async def _probe_target(
        self, client: httpx.AsyncClient, url: str, semaphore: asyncio.Semaphore
    ) -> ScanResult:
        """Probe a single target with version detection, exposed file checks, etc."""
        async with semaphore:
            result = ScanResult(
                url=url,
                scan_time=datetime.now(timezone.utc),
            )
            try:
                proxy = next(self.proxy_cycle) if self.proxy_cycle else None
                resp = await client.get(
                    url,
                    timeout=self.timeout,
                    proxy=proxy,
                    follow_redirects=True,
                )
                headers = dict(resp.headers)
                body = resp.text
                result.detected_from.append("headers")
                php_ver = detect_php_version(headers=headers, body=body)
                if php_ver:
                    result.php_version = php_ver
                    result.detected_from.append("body")

                cms = detect_cms_version(body)
                if cms:
                    result.detected_from.append(f"cms:{cms[0]}")

                base = url.rstrip("/")
                common_paths = [
                    "/phpinfo.php",
                    "/info.php",
                    "/.env",
                    "/phpmyadmin/",
                ]
                for path in common_paths:
                    try:
                        f_resp = await client.get(
                            f"{base}{path}", timeout=8, proxy=proxy
                        )
                        if f_resp.status_code == 200:
                            content = f_resp.text[:500]
                            if "PHP Version" in content or "phpinfo" in content.lower():
                                ftype = "phpinfo"
                                if result.php_version is None:
                                    pver = detect_from_phpinfo(content) or detect_from_body(content)
                                    if pver:
                                        result.php_version = pver
                                        result.detected_from.append("phpinfo-page")
                                preview = content
                            elif any(k in content.lower() for k in ["create table", "insert into", "dump"]):
                                ftype = "sql_dump"
                                try:
                                    schema = parse_sql_dump(content)
                                    result.db_schema = schema
                                except Exception:
                                    schema = None
                                preview = content[:250]
                            else:
                                ftype = "exposed"
                                preview = content[:150]
                            result.exposed_files.append(
                                ExposedFile(
                                    url=str(f_resp.url),
                                    file_type=ftype,
                                    content_preview=preview,
                                )
                            )
                    except Exception:
                        continue

                sql_urls = locate_sql_urls(body)
                for s_url in sql_urls[:2]:
                    try:
                        s_resp = await client.get(s_url, timeout=10, proxy=proxy)
                        if s_resp.status_code == 200 and ("sql" in s_url.lower() or "CREATE TABLE" in s_resp.text):
                            result.exposed_files.append(
                                ExposedFile(
                                    url=s_url,
                                    file_type="sql_dump",
                                    content_preview=s_resp.text[:200],
                                )
                            )
                            result.db_schema = parse_sql_dump(s_resp.text)
                    except Exception:
                        continue

                if result.php_version:
                    result.vulns = get_vulns_for_version(result.php_version)

                if self.use_nuclei and result.vulns:
                    result.nuclei_findings = validate_with_nuclei(
                        url, result.vulns, timeout=self.timeout
                    )

                if self.use_ollama and (result.vulns or result.exposed_files):
                    result.llm_summary = generate_summary([result], timeout=20)

                return result
            except httpx.TimeoutException:
                result.errors.append("Request timeout")
                return result
            except Exception as exc:
                result.errors.append(str(exc))
                return result

    async def scan(
        self,
        targets: Sequence[str],
        callback: Optional[Callable[[ScanResult], None]] = None,
    ) -> List[ScanResult]:
        """Scan multiple targets concurrently with optional live callback for TUI."""
        if not targets:
            return []

        semaphore = asyncio.Semaphore(self.max_concurrency)
        limits = httpx.Limits(max_connections=self.max_concurrency, max_keepalive_connections=5)
        async with httpx.AsyncClient(
            limits=limits, timeout=self.timeout, follow_redirects=True
        ) as client:
            tasks = [
                self._probe_target(client, target, semaphore) for target in targets
            ]
            results: List[ScanResult] = []
            for task in asyncio.as_completed(tasks):
                result = await task
                results.append(result)
                if callback is not None:
                    callback(result)

        if results:
            store_results(results)
        return results


async def scan_targets(
    targets: List[str],
    config: Optional[Dict[str, Any]] = None,
    callback: Optional[Callable[[ScanResult], None]] = None,
) -> List[ScanResult]:
    """Public async entrypoint for scanning. Supports optional live callback for TUI.

    The callback (if supplied) is invoked with each ScanResult as soon as it
    becomes available, enabling real-time UI updates in the Textual TUI.
    """
    if not isinstance(targets, list):
        targets = list(targets)

    scanner = AsyncScanner(config)
    return await scanner.scan(targets, callback=callback)


__all__ = ["scan_targets", "AsyncScanner"]
