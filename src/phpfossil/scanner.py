"""Async scanner for PHP Fossil.

Handles concurrent scanning of targets with rate limiting via semaphore,
proxy support, version fingerprinting via multiple vectors, vuln lookup,
schema extraction, optional Nuclei and Ollama post-processing, and live callbacks
for the TUI. Consistent with the rest of the codebase.
"""

import asyncio
import random
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

from .fingerprinter import (
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

    async def scan(
        self,
        targets: List[str],
        callback: Optional[Callable[[ScanResult], None]] = None,
    ) -> List[ScanResult]:
        """Perform concurrent scan of all targets and apply optional post-processing."""
        if not targets:
            return []

        semaphore = asyncio.Semaphore(self.max_concurrency)
        results: List[ScanResult] = []

        # Choose proxy once per scan (rotation can be extended per-request if needed)
        proxy = random.choice(self.proxies) if self.proxies else None

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            proxy=proxy,
        ) as client:
            tasks = [
                asyncio.create_task(
                    self._probe_target(client, target, semaphore, callback)
                )
                for target in targets
            ]
            for task in asyncio.as_completed(tasks):
                result: ScanResult = await task
                results.append(result)

        # Nuclei validation (runs synchronously but after all HTTP done)
        if self.use_nuclei:
            for result in results:
                if result.php_version or result.vulns:
                    result.nuclei_findings = validate_with_nuclei(
                        result.url, result.vulns, timeout=self.timeout
                    )

        # Ollama summarization (one summary for the whole batch)
        if self.use_ollama and results:
            try:
                summary = generate_summary(results, model=self.ollama_model)
                for result in results:
                    result.llm_summary = summary
            except Exception as exc:  # noqa: BLE001
                err_msg = f"LLM summary failed: {exc}"
                for result in results:
                    result.errors.append(err_msg)

        return results

    async def _probe_target(
        self,
        client: httpx.AsyncClient,
        url: str,
        semaphore: asyncio.Semaphore,
        callback: Optional[Callable[[ScanResult], None]] = None,
    ) -> ScanResult:
        """Single target probing with multiple detection methods and fallback probes."""
        async with semaphore:
            result = ScanResult(url=url)
            try:
                # Primary request
                probe_url = url if url.endswith(("/", ".php", ".html")) else f"{url}/"
                response = await client.get(probe_url)
                headers = dict(response.headers)
                body = response.text

                version = detect_php_version(headers=headers, body=body)
                detected_from: List[str] = []
                if version:
                    if detect_from_headers(headers):
                        detected_from.append("headers")
                    else:
                        detected_from.append("body")

                # phpinfo probe
                for path in ("/phpinfo.php", "/info.php", "/?phpinfo=1"):
                    try:
                        pi_url = url.rstrip("/") + path
                        pi_resp = await client.get(pi_url)
                        if pi_resp.status_code < 400:
                            pi_version = detect_from_phpinfo(
                                pi_resp.text
                            ) or detect_from_body(pi_resp.text)
                            if pi_version:
                                version = pi_version
                                detected_from.append("phpinfo")
                                result.exposed_files.append(
                                    ExposedFile(
                                        url=pi_url,
                                        file_type="phpinfo",
                                        content_preview=pi_resp.text[:400],
                                    )
                                )
                                break
                    except httpx.HTTPError:
                        continue

                # Schema / SQL dump probe
                sql_candidates = locate_sql_urls(body)
                if not sql_candidates:
                    sql_candidates = ["dump.sql", "backup.sql", "database.sql", "schema.sql"]
                for candidate in sql_candidates[:2]:
                    try:
                        sql_url = (
                            candidate
                            if candidate.startswith(("http://", "https://"))
                            else f"{url.rstrip('/')}/{candidate.lstrip('/')}"
                        )
                        sql_resp = await client.get(sql_url)
                        if sql_resp.status_code == 200:
                            preview = sql_resp.text[:500].lower()
                            if any(
                                k in preview
                                for k in ("table", "insert", "create", "--", "dump")
                            ):
                                parsed_schema = parse_sql_dump(sql_resp.text)
                                result.db_schema = parsed_schema
                                result.exposed_files.append(
                                    ExposedFile(
                                        url=sql_url,
                                        file_type="sql_dump",
                                        content_preview=sql_resp.text[:300],
                                    )
                                )
                                break
                    except httpx.HTTPError:
                        continue

                # Error-page version leak probe (only if still unknown)
                if not version:
                    for i in range(1, 4):
                        try:
                            nonce = i * 11111 + 123
                            err_url = f"{url.rstrip('/')}/nonexistent-{nonce}.php"
                            err_resp = await client.get(err_url)
                            err_version = detect_from_error_page(err_resp.text)
                            if err_version:
                                version = err_version
                                detected_from.append("error_page")
                                break
                        except httpx.HTTPError:
                            continue

                if version:
                    result.php_version = version
                    result.detected_from = detected_from
                    result.vulns = get_vulns_for_version(version)

                if callback is not None:
                    callback(result)

                return result
            except Exception as exc:  # noqa: BLE001
                result.errors.append(f"Probe failed: {str(exc)}")
                return result


async def scan_targets(
    targets: List[str],
    config: Optional[Dict[str, Any]] = None,
    callback: Optional[Callable[[ScanResult], None]] = None,
) -> List[ScanResult]:
    """Public async API to scan targets.

    Returns list of ScanResult. From synchronous code (CLI, scripts, tests)
    wrap with asyncio.run():

        import asyncio
        results = asyncio.run(scan_targets(targets, config=config))

    The optional live callback is invoked as soon as each target finishes.
    """
    scanner = AsyncScanner(config)
    return await scanner.scan(targets, callback=callback)


__all__ = ["scan_targets", "AsyncScanner"]
