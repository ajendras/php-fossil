"""AsyncScanner for PHP Fossil.

Provides concurrent, rate-limited HTTP probing of targets.
Uses the fingerprinter for version detection, probes common
exposed files (phpinfo, SQL dumps), extracts schemas and maps
vulnerabilities. Fully typed, validated, production-ready.
"""

import asyncio
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx

from .fingerprinter import (
    detect_from_body,
    detect_from_error_page,
    detect_from_headers,
    detect_from_phpinfo,
)
from .models import ExposedFile, ScanResult, SchemaResult, Vulnerability


def _get_embedded_vulndb() -> Dict[str, List[Vulnerability]]:
    """Return a small embedded database of PHP CVEs.

    In production this would load from a JSON file packaged with the module.
    """
    return {
        "5.": [
            Vulnerability(
                cve="CVE-2012-1823",
                title="PHP CGI Argument Injection",
                severity="critical",
                description="Unauthenticated remote code execution via query string.",
                fixed_in="5.4.3",
                reference="https://www.php.net/ChangeLog-5.php#5.4.3",
            ),
            Vulnerability(
                cve="CVE-2018-19518",
                title="PHP IMAP Open RCE",
                severity="high",
                description="Remote code execution when imap_open is used with attacker-controlled input.",
                fixed_in="5.6.39",
                reference="https://nvd.nist.gov/vuln/detail/CVE-2018-19518",
            ),
        ],
        "7.0": [
            Vulnerability(
                cve="CVE-2019-11043",
                title="PHP-FPM Remote Code Execution",
                severity="critical",
                description="RCE when Nginx and PHP-FPM are misconfigured.",
                fixed_in="7.3.12",
                reference="https://www.rapid7.com/db/vulnerabilities/php-cve-2019-11043/",
            ),
        ],
        "8.0": [
            Vulnerability(
                cve="CVE-2021-21702",
                title="Hash Collision Denial of Service",
                severity="medium",
                description="CPU exhaustion via specially crafted HTTP parameters.",
                fixed_in="8.0.12",
                reference="https://www.php.net/releases/8.0.12.php",
            ),
        ],
    }


def get_vulns_for_version(version: str) -> List[Vulnerability]:
    """Return known vulnerabilities for a given PHP version string."""
    if not version or not isinstance(version, str):
        return []
    db = _get_embedded_vulndb()
    for prefix, entries in db.items():
        if version.startswith(prefix):
            return entries
    # Fallback for legacy versions
    if version.startswith(("4.", "5.", "6.", "7.")):
        return db.get("5.", [])
    return []


def parse_sql_dump(content: str) -> SchemaResult:
    """Simple regex-based parser for SQL dumps. Extracts table names and columns.

    Handles typical mysqldump / phpMyAdmin output.
    """
    if not content or not isinstance(content, str):
        return SchemaResult()

    # Extract CREATE TABLE statements
    tables: List[str] = re.findall(
        r"(?i)CREATE TABLE\s+[`']?(\w+)[`']?", content
    )
    unique_tables = list(dict.fromkeys(tables))

    columns: Dict[str, List[str]] = {}
    for table in unique_tables:
        match = re.search(
            rf"(?i)CREATE TABLE[^`]*[`']?{re.escape(table)}[`']?\s*\((.+?)\)[^;]*;",
            content,
            re.DOTALL,
        )
        if match:
            col_defs = match.group(1)
            col_names = re.findall(r"[`']?(\w+)[`']?\s+\w+", col_defs)
            columns[table] = col_names

    # Rough row count estimation from INSERT statements
    row_counts = {}
    for table in unique_tables:
        inserts = re.findall(
            rf"(?i)INSERT INTO\s+[`']?{re.escape(table)}[`']?.*?;",
            content,
        )
        row_counts[table] = len(inserts)

    return SchemaResult(
        tables=unique_tables, columns=columns, row_counts=row_counts
    )


class AsyncScanner:
    """Rate-limited asynchronous scanner for legacy PHP detection.

    Features:
      * Configurable concurrency and timeouts
      * Automatic retry on transient errors
      * Comprehensive fingerprinting via Fingerprinter
      * Probing for phpinfo(), SQL dumps and error pages
      * Schema extraction and CVE mapping
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """Initialize scanner with rate-limit and timeout settings.

        Args:
            config: Optional dict with keys: timeout, max_concurrency, retries.
        """
        self.config = config or {}
        self.timeout = float(self.config.get("timeout", 12.0))
        self.max_concurrency = min(int(self.config.get("max_concurrency", 20)), 50)
        self.retries = int(self.config.get("retries", 2))
        self.user_agent = (
            "PHPFossil/0.1.0 (https://github.com/php-fossil/php-fossil)"
        )

    async def scan(
        self, targets: List[str], config: Optional[Dict[str, Any]] = None
    ) -> List[ScanResult]:
        """Scan a list of targets concurrently and return ScanResult objects.

        Args:
            targets: List of full HTTP/HTTPS URLs.
            config: Optional per-scan configuration override.

        Returns:
            List of ScanResult objects (one per target).

        Raises:
            ValueError: On invalid targets or configuration.
        """
        if config:
            self.config.update(config)
            self.timeout = float(self.config.get("timeout", self.timeout))
            self.max_concurrency = min(
                int(self.config.get("max_concurrency", self.max_concurrency)), 50
            )

        if not isinstance(targets, list) or not targets:
            raise ValueError("targets must be a non-empty list of URL strings")

        for t in targets:
            if not isinstance(t, str) or not t.startswith(("http://", "https://")):
                raise ValueError(
                    f"All targets must be valid http/https URLs, got: {t}"
                )

        limits = httpx.Limits(
            max_connections=self.max_concurrency,
            max_keepalive_connections=max(2, self.max_concurrency // 3),
        )
        timeout_cfg = httpx.Timeout(self.timeout, connect=8.0)

        async with httpx.AsyncClient(
            limits=limits,
            timeout=timeout_cfg,
            headers={"User-Agent": self.user_agent},
            follow_redirects=True,
        ) as client:
            semaphore = asyncio.Semaphore(self.max_concurrency)
            tasks = [
                self._probe_target(t, client, semaphore) for t in targets
            ]
            return await asyncio.gather(*tasks)

    async def _probe_target(
        self,
        url: str,
        client: httpx.AsyncClient,
        semaphore: asyncio.Semaphore,
    ) -> ScanResult:
        """Probe a single target with retries and comprehensive fingerprinting.

        Internal method - not part of public API.
        """
        async with semaphore:
            result = ScanResult(url=url)

            for attempt in range(self.retries + 1):
                try:
                    resp = await client.get(url)
                    result.detected_from.append("http-response")
                    break
                except (httpx.TransportError, httpx.TimeoutException) as exc:
                    if attempt == self.retries:
                        result.errors.append(f"Request failed: {exc}")
                        return result
                    await asyncio.sleep(0.3 * (attempt + 1))

            headers_dict = dict(resp.headers)
            body = resp.text

            # Version fingerprinting (priority order)
            version = detect_from_headers(headers_dict)
            if version:
                result.php_version = version
                result.detected_from.append("headers")

            if not result.php_version:
                version = detect_from_body(body)
                if version:
                    result.php_version = version
                    result.detected_from.append("body")

            base = url.rstrip("/")

            # Probe common phpinfo() locations
            phpinfo_paths = ("/phpinfo.php", "/info.php", "/php.php", "/i.php")
            for path in phpinfo_paths:
                probe_url = base + path
                try:
                    info_resp = await client.get(
                        probe_url, timeout=httpx.Timeout(8.0)
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
                            vmatch = detect_from_phpinfo(info_resp.text)
                            if vmatch:
                                result.php_version = vmatch
                                result.detected_from.append("phpinfo")
                except (httpx.TransportError, httpx.TimeoutException):
                    continue

            # Probe common SQL dump locations
            sql_paths = (
                "/dump.sql",
                "/backup.sql",
                "/db.sql",
                "/database.sql",
                "/schema.sql",
                "/backup/db.sql",
            )
            for path in sql_paths:
                probe_url = base + path
                try:
                    sql_resp = await client.get(
                        probe_url, timeout=httpx.Timeout(8.0)
                    )
                    if sql_resp.status_code == 200:
                        text_lower = sql_resp.text.lower()
                        if any(
                            kw in text_lower
                            for kw in ("create table", "insert into", "mysqldump")
                        ):
                            preview = sql_resp.text[:180].replace("\n", " ")
                            result.exposed_files.append(
                                ExposedFile(
                                    url=probe_url,
                                    file_type="sql_dump",
                                    content_preview=preview,
                                )
                            )
                            if not result.schema and len(sql_resp.text) > 200:
                                result.schema = parse_sql_dump(sql_resp.text)
                except (httpx.TransportError, httpx.TimeoutException):
                    continue

            # Final fallback via error page (often leaks version)
            if not result.php_version:
                try:
                    err_url = base + "/nonexistent-404.php"
                    err_resp = await client.get(
                        err_url, timeout=httpx.Timeout(6.0)
                    )
                    version = detect_from_error_page(err_resp.text)
                    if version:
                        result.php_version = version
                        result.detected_from.append("error-page")
                except (httpx.TransportError, httpx.TimeoutException):
                    pass

            if result.php_version:
                result.vulns = get_vulns_for_version(result.php_version)

            result.scan_time = datetime.utcnow()
            return result


def scan(targets: List[str], config: Optional[Dict[str, Any]] = None) -> List[ScanResult]:
    """Synchronous wrapper for AsyncScanner.scan.

    Matches the public API signature used by the CLI and __init__.
    """
    scanner = AsyncScanner(config=config)
    return asyncio.run(scanner.scan(targets))


__all__ = ["AsyncScanner", "scan", "get_vulns_for_version"]
