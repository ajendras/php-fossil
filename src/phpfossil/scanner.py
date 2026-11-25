"""Core async scanning engine for PHP Fossil.

Handles concurrent HTTP requests with proxy rotation, rotating User-Agents,
per-domain rate limiting via Semaphores, fingerprinting, vuln lookup,
schema extraction, optional Nuclei and Ollama post-processing.
Uses the validated ConfigSettings for all options including the new
nuclei_templates_dir.
"""

import asyncio
import random
from collections.abc import Callable
from typing import Any, Dict, List, Optional, Union

import httpx

from .fingerprinter import detect_php_version, detect_with_community_rules
from .models import ConfigSettings, ExposedFile, ScanResult
from .nuclei import validate_with_nuclei
from .ollama import generate_summary, is_ollama_available
from .schema import locate_sql_urls, parse_sql_dump
from .vulndb import get_vulns_for_version


class AsyncScanner:
    """Manages async scanning with rate limits and config."""

    def __init__(self, config: ConfigSettings):
        self.config = config
        self.global_semaphore = asyncio.Semaphore(config.max_concurrency)
        self.domain_semaphores: Dict[str, asyncio.Semaphore] = {}
        self.ua_pool = config.user_agents or []
        self.proxy_cycle = 0

    def _next_user_agent(self) -> str:
        if not self.ua_pool:
            return "Mozilla/5.0 (compatible; PHPFossil/0.1)"
        return random.choice(self.ua_pool)

    def _next_proxy(self) -> Optional[str]:
        if not self.config.proxies:
            return None
        proxy = self.config.proxies[self.proxy_cycle % len(self.config.proxies)]
        self.proxy_cycle = (self.proxy_cycle + 1) % len(self.config.proxies)
        return proxy

    async def _fetch_with_retry(
        self, client: httpx.AsyncClient, url: str, retries: int = 2
    ) -> Optional[httpx.Response]:
        for attempt in range(retries + 1):
            try:
                headers = {"User-Agent": self._next_user_agent()}
                proxy = self._next_proxy()
                resp = await client.get(
                    url,
                    headers=headers,
                    proxy=proxy,
                    timeout=self.config.timeout,
                    follow_redirects=True,
                )
                resp.raise_for_status()
                return resp
            except Exception:
                if attempt == retries:
                    return None
                await asyncio.sleep(0.5 * (attempt + 1))
        return None

    async def _probe_target(
        self,
        url: str,
        client: httpx.AsyncClient,
        callback: Optional[Callable[[ScanResult], None]] = None,
    ) -> ScanResult:
        """Probe single target with all detection vectors."""
        result = ScanResult(url=url)
        # get domain for per-domain limit
        try:
            domain = httpx.URL(url).host or "unknown"
        except Exception:
            domain = "unknown"
        if domain not in self.domain_semaphores:
            self.domain_semaphores[domain] = asyncio.Semaphore(
                self.config.per_domain_limit
            )
        async with self.global_semaphore, self.domain_semaphores[domain]:
            resp = await self._fetch_with_retry(client, url)
            if resp is None:
                if callback:
                    callback(result)
                return result

            result.detected_from = ["body", "headers"]
            version = detect_php_version(
                dict(resp.headers), resp.text, None, None
            )
            if not version and self.config.use_community_fingerprints:
                version = detect_with_community_rules(resp.text)
            result.php_version = version or "unknown"
            if version and version != "unknown":
                result.vulns = get_vulns_for_version(version)

            # Look for exposed SQL dumps
            sql_urls = locate_sql_urls(resp.text, base_url=url)
            for s_url in sql_urls[:3]:
                sql_resp = await self._fetch_with_retry(client, s_url)
                if sql_resp and sql_resp.status_code < 400:
                    snippet = sql_resp.text[:500] if sql_resp.text else ""
                    result.exposed_files.append(
                        ExposedFile(
                            url=s_url,
                            content_type=sql_resp.headers.get("content-type", "text/plain"),
                            snippet=snippet,
                        )
                    )
                    if not result.db_schema:
                        result.db_schema = parse_sql_dump(sql_resp.text)

            # Nuclei validation - now passes full config including nuclei_templates_dir
            if self.config.use_nuclei:
                result.nuclei_findings.extend(
                    validate_with_nuclei(url, self.config)
                )

            # Ollama summary
            if (
                self.config.use_ollama
                and is_ollama_available()
                and result.is_vulnerable()
            ):
                try:
                    result.llm_summary = generate_summary(
                        [result], model=self.config.ollama_model
                    )
                except Exception:
                    result.llm_summary = "Ollama summarization unavailable."

            if callback is not None:
                callback(result)
            return result

    async def scan(
        self,
        targets: List[str],
        callback: Optional[Callable[[ScanResult], None]] = None,
    ) -> List[ScanResult]:
        limits = httpx.Limits(max_keepalive_connections=5, max_connections=10)
        timeout = httpx.Timeout(self.config.timeout, connect=10.0)
        async with httpx.AsyncClient(
            limits=limits, timeout=timeout, follow_redirects=True
        ) as client:
            tasks = [
                asyncio.create_task(self._probe_target(t, client, callback))
                for t in targets
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        final_results: List[ScanResult] = []
        for res in results:
            if isinstance(res, ScanResult):
                final_results.append(res)
            # ignore exceptions for robustness
        return final_results


async def scan_targets(
    targets: List[str],
    config: Union[ConfigSettings, Dict[str, Any], None] = None,
    callback: Optional[Callable[[ScanResult], None]] = None,
) -> List[ScanResult]:
    """Public async scan entrypoint. Accepts ConfigSettings, dict or None."""
    if isinstance(config, dict) or config is None:
        config_obj = ConfigSettings.model_validate(config or {})
    else:
        config_obj = config
    scanner = AsyncScanner(config_obj)
    return await scanner.scan(targets, callback)
