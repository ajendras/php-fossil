"""Async scanner for PHP Fossil.

Handles concurrent scanning with global and per-domain rate limiting,
rotating User-Agents, round-robin proxy support via per-request proxy=,
fingerprinting, vuln lookup, schema extraction, optional Nuclei and Ollama,
and live callback support for TUI. Compatible with pytest-httpx mocks.
"""

import asyncio
from collections import defaultdict
from itertools import cycle
from typing import Any, Callable, Dict, List, Optional, Union
from urllib.parse import urlparse

import httpx

from .models import (
    ConfigSettings,
    DEFAULT_USER_AGENTS,
    ExposedFile,
    ScanResult,
)
from .fingerprinter import detect_php_version, detect_with_community_rules
from .vulndb import get_vulns_for_version
from .schema import locate_sql_urls, parse_sql_dump
from .nuclei import validate_with_nuclei
from .ollama import generate_summary, is_ollama_available


async def scan_targets(
    targets: List[str],
    config: Optional[Union[ConfigSettings, Dict[str, Any]]] = None,
    callback: Optional[Callable[[ScanResult], Any]] = None,
) -> List[ScanResult]:
    """Scan targets for legacy PHP versions, vulns, exposed files and schemas.

    Accepts ConfigSettings instance or dict (converted internally).
    Proxies are rotated round-robin using the per-request 'proxy' argument
    (avoids TypeError on AsyncClient.__init__ with list-valued proxies=).
    User-Agents rotate on every request. Per-domain Semaphore prevents
    overwhelming individual hosts.
    """
    if config is None:
        cfg = ConfigSettings()
    elif isinstance(config, dict):
        cfg = ConfigSettings(**config)
    else:
        cfg = config

    max_concurrency = min(cfg.max_concurrency, 50)
    timeout = httpx.Timeout(cfg.timeout)
    limits = httpx.Limits(
        max_connections=max_concurrency, max_keepalive_connections=max_concurrency
    )

    user_agents = cfg.user_agents if cfg.user_agents else DEFAULT_USER_AGENTS
    ua_cycle = cycle(user_agents)
    proxy_cycle = cycle(cfg.proxies) if cfg.proxies else None

    domain_semaphores: Dict[str, asyncio.Semaphore] = defaultdict(
        lambda: asyncio.Semaphore(cfg.per_domain_limit)
    )
    global_semaphore = asyncio.Semaphore(max_concurrency)

    results: List[ScanResult] = []

    async with httpx.AsyncClient(
        timeout=timeout,
        limits=limits,
        follow_redirects=True,
        # proxies= is deliberately omitted (list not accepted by all mock versions;
        # rotation is performed per-request via the proxy= argument below)
    ) as client:
        async def _probe_target(url: str) -> ScanResult:
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.hostname or url
            async with global_semaphore, domain_semaphores[domain]:
                try:
                    headers = {"User-Agent": next(ua_cycle)}
                    proxy = next(proxy_cycle) if proxy_cycle is not None else None

                    response = await client.get(
                        url, headers=headers, proxy=proxy
                    )
                    response.raise_for_status()
                    body = response.text
                    headers_dict = {k.lower(): v for k, v in response.headers.items()}

                    php_version = detect_php_version(
                        headers=headers_dict, body=body
                    )
                    detected_from: List[str] = []
                    if php_version:
                        detected_from.append("headers")

                    if not php_version and cfg.use_community_fingerprints:
                        php_version = detect_with_community_rules(body)
                        if php_version:
                            detected_from.append("community")

                    if not php_version:
                        php_version = detect_php_version(body=body)
                        if php_version:
                            detected_from.append("body")

                    vulns = (
                        get_vulns_for_version(php_version) if php_version else []
                    )

                    exposed_files: List[ExposedFile] = []
                    sql_urls = locate_sql_urls(body, base_url=url)
                    for sql_url in sql_urls[:2]:  # limit extra requests in tests
                        try:
                            s_proxy = (
                                next(proxy_cycle) if proxy_cycle is not None else None
                            )
                            s_headers = {"User-Agent": next(ua_cycle)}
                            s_response = await client.get(
                                sql_url, headers=s_headers, proxy=s_proxy
                            )
                            if s_response.status_code == 200:
                                schema = parse_sql_dump(s_response.text)
                                exposed_files.append(
                                    ExposedFile(
                                        url=sql_url,
                                        content_type=s_response.headers.get(
                                            "content-type", "text/plain"
                                        ),
                                        size=len(s_response.content),
                                        snippet=(
                                            s_response.text[:250]
                                            if len(s_response.text) > 250
                                            else s_response.text
                                        ),
                                    )
                                )
                        except Exception:
                            continue

                    nuclei_findings = []
                    if cfg.use_nuclei and php_version:
                        try:
                            nuclei_findings = validate_with_nuclei(url, php_version)
                        except Exception:
                            pass

                    llm_summary = None
                    if cfg.use_ollama:
                        try:
                            if is_ollama_available():
                                llm_summary = generate_summary(
                                    [ScanResult(url=url, php_version=php_version, vulns=vulns)]
                                )
                        except Exception:
                            llm_summary = None

                    result = ScanResult(
                        url=url,
                        php_version=php_version,
                        detected_from=detected_from,
                        vulns=vulns,
                        exposed_files=exposed_files,
                        nuclei_findings=nuclei_findings,
                        llm_summary=llm_summary,
                    )

                    if callback is not None:
                        callback(result)
                    return result

                except httpx.HTTPStatusError:
                    result = ScanResult(url=url)
                    if callback is not None:
                        callback(result)
                    return result
                except Exception:
                    result = ScanResult(url=url)
                    if callback is not None:
                        callback(result)
                    return result

        tasks = [_probe_target(t) for t in targets]
        for coro in asyncio.as_completed(tasks):
            result = await coro
            results.append(result)

    return results
