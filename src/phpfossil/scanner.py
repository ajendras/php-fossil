"""Async scanner core for PHP Fossil.

Handles concurrent HTTP probing with rotating User-Agent list (configurable
via ConfigSettings.user_agents) and proxy rotation, version fingerprinting,
vuln lookup, schema extraction, optional Nuclei/Ollama steps and live
callbacks for the TUI.
"""

import asyncio
from itertools import cycle
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urljoin

import httpx

from .fingerprinter import (
    CommunityFingerprinter,
    detect_php_version,
)
from .models import (
    ConfigSettings,
    DEFAULT_USER_AGENTS,
    ExposedFile,
    ScanResult,
    SchemaResult,
)
from .nuclei import validate_with_nuclei
from .ollama import generate_summary
from .schema import locate_sql_urls, parse_sql_dump
from .vulndb import get_vulns_for_version


DEFAULT_PROBE_PATHS = [
    "/",
    "/phpinfo.php",
    "/info.php",
    "/test.php",
    "/admin.php",
]


class AsyncScanner:
    """Main asynchronous scanner with built-in UA and proxy rotation."""

    def __init__(self, config: Optional[ConfigSettings] = None):
        if config is None:
            config = ConfigSettings()
        elif isinstance(config, dict):
            config = ConfigSettings.model_validate(config)
        self.config = config
        self.semaphore = asyncio.Semaphore(self.config.max_concurrency)

        # Rotating User-Agent pool (core of this implementation)
        ua_list = self.config.user_agents or DEFAULT_USER_AGENTS
        self.ua_cycle = cycle(ua_list)

        self.proxy_cycle = cycle(self.config.proxies) if self.config.proxies else None
        self.community_rules = None
        if self.config.use_community_fingerprints:
            self.community_rules = CommunityFingerprinter.load(
                self.config.community_repo_url
            )

    def _get_next_ua_headers(self) -> Dict[str, str]:
        """Return fresh headers using the next User-Agent from the rotating pool."""
        ua = next(self.ua_cycle)
        return {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }

    def _get_next_proxy(self) -> Optional[str]:
        """Return next proxy URL from cycle or None."""
        if self.proxy_cycle is None:
            return None
        return next(self.proxy_cycle)

    async def _fetch(
        self, client: httpx.AsyncClient, target_url: str
    ) -> Optional[httpx.Response]:
        """Execute GET with current UA (and proxy if configured)."""
        headers = self._get_next_ua_headers()
        proxy = self._get_next_proxy()
        try:
            resp = await client.get(
                target_url,
                headers=headers,
                proxy=proxy,
                timeout=self.config.timeout,
                follow_redirects=True,
            )
            return resp
        except httpx.HTTPError:
            # One retry with a different UA from the pool
            headers = self._get_next_ua_headers()
            try:
                resp = await client.get(
                    target_url,
                    headers=headers,
                    proxy=proxy,
                    timeout=self.config.timeout,
                    follow_redirects=True,
                )
                return resp
            except httpx.HTTPError:
                return None
        except Exception:  # noqa: BLE001
            return None

    async def _probe_target(
        self,
        url: str,
        client: httpx.AsyncClient,
        callback: Optional[Callable[[ScanResult], None]] = None,
    ) -> ScanResult:
        """Probe a target URL (and common PHP info paths), aggregate findings."""
        result = ScanResult(url=url)
        responses: List[tuple[str, httpx.Response]] = []

        for path in DEFAULT_PROBE_PATHS:
            target_url = urljoin(url.rstrip("/") + "/", path)
            resp = await self._fetch(client, target_url)
            if resp and resp.is_success:
                responses.append((target_url, resp))
                # Early PHP version extraction from phpinfo-like pages
                if any(p in path.lower() for p in ("phpinfo", "info", "test")):
                    from .fingerprinter import detect_from_phpinfo
                    ver = detect_from_phpinfo(resp.text)
                    if ver:
                        result.php_version = ver
                        result.detected_from.append("phpinfo-page")
                        break

        if not responses:
            result.errors.append("No successful responses")
            if callback:
                callback(result)
            return result

        # Use first successful response for broad fingerprinting
        main_url, main_resp = responses[0]
        headers_dict = dict(main_resp.headers)
        body = main_resp.text

        version = detect_php_version(
            headers=headers_dict,
            body=body,
            community_rules=self.community_rules,
        )
        if version and not result.php_version:
            result.php_version = version
            result.detected_from.append("headers+body")

        if result.php_version:
            result.vulns = get_vulns_for_version(result.php_version)

        # Exposed file & schema detection
        for turl, resp in responses:
            content = resp.text.strip()
            if any(kw in content.lower() for kw in ("create table", "insert into", "dump", ".sql")) or any(
                ext in turl.lower() for ext in (".sql", ".dump", ".bak")
            ):
                preview = content[:250].replace("\n", " ")
                result.exposed_files.append(
                    ExposedFile(
                        url=turl,
                        file_type="sql_dump" if "sql" in turl.lower() else "backup",
                        content_preview=preview,
                    )
                )
                try:
                    parsed = parse_sql_dump(content)
                    result.db_schema = SchemaResult(
                        tables=parsed.get("tables", []),
                        columns=parsed.get("columns", {}),
                        row_counts=parsed.get("row_counts", {}),
                    )
                except Exception:  # noqa: BLE001
                    pass

        # Nuclei integration (post-processing)
        if self.config.use_nuclei and result.php_version:
            try:
                nuclei_findings = validate_with_nuclei(result.url)
                if isinstance(nuclei_findings, list):
                    result.nuclei_findings = nuclei_findings
            except Exception as exc:  # noqa: BLE001
                result.errors.append(f"Nuclei failed: {exc}")

        # Ollama summarization
        if self.config.use_ollama and (result.vulns or result.nuclei_findings):
            try:
                result.llm_summary = generate_summary([result], model=self.config.ollama_model)
            except Exception as exc:  # noqa: BLE001
                result.errors.append(f"Ollama failed: {exc}")

        if callback:
            callback(result)

        return result

    async def scan(
        self,
        targets: List[str],
        callback: Optional[Callable[[ScanResult], Any]] = None,
    ) -> List[ScanResult]:
        """Run concurrent scans with UA/proxy rotation."""
        timeout = httpx.Timeout(self.config.timeout, connect=self.config.timeout * 2)
        limits = httpx.Limits(
            max_keepalive_connections=self.config.max_concurrency,
            max_connections=self.config.max_concurrency,
        )

        async with httpx.AsyncClient(
            timeout=timeout,
            limits=limits,
            follow_redirects=True,
        ) as client:
            tasks = [self._probe_target(t, client, callback) for t in targets]
            raw_results = await asyncio.gather(*tasks, return_exceptions=True)

        results: List[ScanResult] = []
        for item in raw_results:
            if isinstance(item, Exception):
                results.append(
                    ScanResult(
                        url="unknown-error",
                        errors=[f"Unhandled exception: {item}"],
                    )
                )
            else:
                results.append(item)

        return results


async def scan_targets(
    targets: List[str],
    config: Optional[ConfigSettings | dict] = None,
    callback: Optional[Callable[[ScanResult], Any]] = None,
) -> List[ScanResult]:
    """Public async entrypoint. Accepts ConfigSettings, dict or None (defaults)."""
    if config is None or isinstance(config, dict):
        config = ConfigSettings.model_validate(config or {})
    scanner = AsyncScanner(config)
    return await scanner.scan(targets, callback=callback)


__all__ = ["scan_targets", "AsyncScanner"]
