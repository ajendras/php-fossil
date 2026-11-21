"""Async scanner for PHP Fossil.

Uses httpx.AsyncClient with rate limiting, rotating User-Agents and optional proxies.
Delegates to fingerprinter, vulndb, schema, nuclei and ollama modules.
Supports live callback for TUI and CLI progress.
Gracefully handles errors per target.
"""

import asyncio
import itertools
import logging
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Union

import httpx

from .fingerprinter import detect_php_version, load_community_fingerprints
from .models import ConfigSettings, ExposedFile, ScanResult
from .vulndb import get_vulns_for_version
from .schema import locate_sql_urls, parse_sql_dump
from .nuclei import validate_with_nuclei
from .ollama import generate_summary

logger = logging.getLogger(__name__)


async def scan_targets(
    targets: List[str],
    config: Optional[Union[ConfigSettings, Dict[str, Any]]] = None,
    callback: Optional[Callable[[ScanResult], None]] = None,
) -> List[ScanResult]:
    """Scan multiple targets concurrently for legacy PHP fingerprints, vulns, exposed files and schemas.

    config can be a dict or ConfigSettings instance (validated with defaults).
    callback is called synchronously with each ScanResult as soon as it is ready (for live UIs).
    """
    if config is None:
        config = ConfigSettings()
    elif isinstance(config, dict):
        try:
            config = ConfigSettings.model_validate(config)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Config validation failed, using defaults: %s", exc)
            config = ConfigSettings()

    community_rules: Optional[List] = None
    if config.use_community_fingerprints:
        try:
            community_rules = load_community_fingerprints(config.community_repo_url)
            logger.debug("Loaded %d community fingerprint rules", len(community_rules))
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Community fingerprints load failed: %s. Using built-in detection only.",
                exc,
            )

    ua_cycle = itertools.cycle(config.user_agents)
    proxy_cycle = itertools.cycle(config.proxies) if config.proxies else itertools.cycle([None])

    semaphore = asyncio.Semaphore(config.max_concurrency)
    results: List[ScanResult] = []

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(config.timeout),
        limits=httpx.Limits(
            max_connections=config.max_concurrency, max_keepalive_connections=10
        ),
        follow_redirects=True,
    ) as client:
        tasks = []
        for target in targets:
            normalized_url = (
                target if "://" in target else f"https://{target}"
            )
            task = asyncio.create_task(
                _probe_target(
                    client,
                    normalized_url,
                    semaphore,
                    config,
                    next(ua_cycle),
                    next(proxy_cycle),
                    community_rules,
                    callback,
                )
            )
            tasks.append(task)

        for task in asyncio.as_completed(tasks):
            try:
                result = await task
                results.append(result)
            except Exception as exc:  # noqa: BLE001
                logger.error("Task failed: %s", exc)
                results.append(ScanResult(url="unknown", php_version=None))

    # Global post-processing for summaries if enabled (cheaper to do once)
    if config.use_ollama and results:
        try:
            summary = generate_summary(results, model=config.ollama_model)
            for r in results:
                if r.is_vulnerable():
                    r.llm_summary = summary
                    break
        except Exception as exc:  # noqa: BLE001
            logger.debug("Ollama summarization failed: %s", exc)

    return results


async def _probe_target(
    client: httpx.AsyncClient,
    url: str,
    semaphore: asyncio.Semaphore,
    config: ConfigSettings,
    user_agent: str,
    proxy: Optional[str],
    community_rules: Optional[List],
    callback: Optional[Callable[[ScanResult], None]],
) -> ScanResult:
    """Single target probe with error isolation."""
    async with semaphore:
        result = ScanResult(url=url, scan_time=datetime.now(timezone.utc))
        try:
            headers = {"User-Agent": user_agent}
            response = await client.get(url, headers=headers, proxy=proxy)

            # Fingerprint version from headers and body
            version = detect_php_version(
                headers=dict(response.headers),
                body=response.text,
                community_rules=community_rules,
            )
            if version:
                result.php_version = version
                detected_source = "headers"
                if "php" not in str(response.headers).lower():
                    detected_source = "body"
                result.detected_from = [detected_source]

            if result.php_version:
                result.vulns = get_vulns_for_version(result.php_version)
                result.risk_score = min(100, len(result.vulns) * 15)

            # Exposed files and schema extraction
            for sql_url in locate_sql_urls(url)[:3]:
                try:
                    sql_resp = await client.get(
                        sql_url,
                        headers=headers,
                        proxy=proxy,
                        timeout=5.0,
                    )
                    if sql_resp.status_code == 200 and len(sql_resp.text) > 100:
                        result.exposed_files.append(
                            ExposedFile(
                                url=sql_url,
                                content_type=str(sql_resp.headers.get("content-type")),
                                size=len(sql_resp.text),
                                snippet=sql_resp.text[:150].replace("\n", " "),
                            )
                        )
                        if not result.db_schema:
                            result.db_schema = parse_sql_dump(sql_resp.text)
                except Exception:  # noqa: BLE001
                    continue

            # Nuclei integration (only on legacy versions)
            if (
                config.use_nuclei
                and result.php_version
                and result.php_version.startswith(("5.", "7."))
            ):
                try:
                    result.nuclei_findings = validate_with_nuclei(url)
                except Exception as exc:  # noqa: BLE001
                    logger.debug("Nuclei scan failed for %s: %s", url, exc)

            if callback:
                callback(result)

            return result

        except httpx.HTTPStatusError as exc:
            logger.debug("HTTP error for %s: %s", url, exc)
            if callback:
                callback(result)
            return result
        except httpx.RequestError as exc:
            logger.debug("Request error for %s: %s", url, exc)
            if callback:
                callback(result)
            return result
        except Exception as exc:  # noqa: BLE001
            logger.error("Unexpected error for %s: %s", url, exc)
            if callback:
                callback(result)
            return result
