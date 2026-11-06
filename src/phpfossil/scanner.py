"""AsyncScanner for PHP Fossil.

Provides concurrent, rate-limited HTTP probing of targets.
Uses the fingerprinter for version detection, probes common
exposed files (phpinfo, SQL dumps), extracts schemas and maps
vulnerabilities. Fully typed, validated, production-ready.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

import httpx

from phpfossil import __version__

from .fingerprinter import (
    detect_from_body,
    detect_from_error_page,
    detect_from_headers,
    detect_from_phpinfo,
)
from .models import ExposedFile, ScanResult, SchemaResult
from .schema import parse_sql_dump
from .vulndb import get_vulns_for_version


async def _probe_target(
    url: str, client: httpx.AsyncClient, config: Dict[str, Any]
) -> ScanResult:
    """Probe a single target asynchronously for PHP version, exposed files, and vulnerabilities."""
    result = ScanResult(url=url)
    headers = {"User-Agent": f"PHPFossil/{__version__} (https://github.com/ajendras/php-fossil)"}

    try:
        resp = await client.get(
            url,
            headers=headers,
            timeout=config.get("timeout", 12.0),
            follow_redirects=True,
        )
        result.detected_from.append("http-response")

        # Fingerprint from headers (most reliable)
        ver = detect_from_headers(dict(resp.headers))
        if ver:
            result.php_version = ver
            result.detected_from.append("headers")

        body = resp.text

        # Fingerprint from body if not already found
        if not result.php_version:
            ver = detect_from_body(body)
            if ver:
                result.php_version = ver
                result.detected_from.append("body")

        base = url.rstrip("/")

        # Probe common phpinfo locations
        for path in ("/phpinfo.php", "/info.php", "/php.php"):
            probe_url = base + path
            try:
                info_resp = await client.get(
                    probe_url, headers=headers, timeout=8.0, follow_redirects=True
                )
                if info_resp.status_code == 200 and (
                    "phpinfo()" in info_resp.text.lower()
                    or "PHP Version" in info_resp.text
                ):
                    preview = info_resp.text[:180].replace("\n", " ")
                    result.exposed_files.append(
                        ExposedFile(
                            url=probe_url,
                            file_type="phpinfo",
                            content_preview=preview,
                        )
                    )
                    if not result.php_version:
                        ver = detect_from_phpinfo(info_resp.text)
                        if ver:
                            result.php_version = ver
                            result.detected_from.append("phpinfo")
                    break
            except httpx.TransportError:
                continue

        # Probe common SQL dump locations
        for path in (
            "/dump.sql",
            "/backup.sql",
            "/db.sql",
            "/database.sql",
            "/schema.sql",
        ):
            probe_url = base + path
            try:
                sql_resp = await client.get(
                    probe_url, headers=headers, timeout=8.0, follow_redirects=True
                )
                if sql_resp.status_code == 200 and any(
                    kw in sql_resp.text.lower()
                    for kw in ("create table", "insert into", "phpmyadmin", "mysqldump")
                ):
                    preview = sql_resp.text[:180].replace("\n", " ")
                    result.exposed_files.append(
                        ExposedFile(
                            url=probe_url,
                            file_type="sql_dump",
                            content_preview=preview,
                        )
                    )
                    if not result.schema:
                        result.schema = parse_sql_dump(sql_resp.text)
                    break
            except httpx.TransportError:
                continue

        # Final fallback via error page
        if not result.php_version:
            try:
                err_url = base + "/nonexistent-404.php"
                err_resp = await client.get(
                    err_url, headers=headers, timeout=6.0, follow_redirects=True
                )
                ver = detect_from_error_page(err_resp.text)
                if ver:
                    result.php_version = ver
                    result.detected_from.append("error-page")
            except httpx.TransportError:
                pass

        if result.php_version:
            result.vulns = get_vulns_for_version(result.php_version)

    except Exception as exc:  # noqa: BLE001
        result.errors.append(str(exc))

    return result


def scan_targets(
    targets: List[str], config: Optional[Dict[str, Any]] = None
) -> List[ScanResult]:
    """Scan a list of targets concurrently and return ScanResult objects.

    Uses a rate-limited async HTTP client. Validates input and respects
    concurrency and timeout settings.
    """
    if not isinstance(targets, list) or not targets:
        raise ValueError("targets must be a non-empty list of URL strings")
    if any(not isinstance(t, str) or not t.startswith(("http://", "https://")) for t in targets):
        raise ValueError("All targets must be valid http/https URLs")

    config = config or {}
    max_concurrency = min(config.get("max_concurrency", 20), 50)
    timeout = config.get("timeout", 12)

    async def _run() -> List[ScanResult]:
        limits = httpx.Limits(max_connections=max_concurrency, max_keepalive_connections=5)
        timeout_cfg = httpx.Timeout(timeout, connect=10.0)

        async with httpx.AsyncClient(
            limits=limits,
            timeout=timeout_cfg,
            headers={"User-Agent": f"PHPFossil/{__version__}"},
        ) as client:
            semaphore = asyncio.Semaphore(max_concurrency)

            async def bounded_probe(t: str) -> ScanResult:
                async with semaphore:
                    return await _probe_target(t, client, config)

            tasks = [bounded_probe(t) for t in targets]
            return await asyncio.gather(*tasks)

    return asyncio.run(_run())
