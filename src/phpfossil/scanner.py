"""PHP Fossil Async Scanner.

Handles concurrent scanning of targets with rate limiting, proxy rotation,
fingerprinting, vuln mapping, schema extraction, optional Nuclei and Ollama
integration, community fingerprints and live callbacks.
"""

import asyncio
from collections.abc import Callable
from itertools import cycle
from typing import Any, Dict, List, Optional, Union

import httpx

from .fingerprinter import (
    CommunityFingerprinter,
    detect_from_phpinfo,
    detect_php_version,
)
from .models import ConfigSettings, ExposedFile, ScanResult
from .nuclei import validate_with_nuclei
from .ollama import generate_summary
from .schema import locate_sql_urls, parse_sql_dump
from .vulndb import get_vulns_for_version


class AsyncScanner:
    """Main scanner class supporting all PHP Fossil detection features."""

    def __init__(self, config: Optional[Union[ConfigSettings, dict]] = None) -> None:
        if isinstance(config, dict):
            self.config = ConfigSettings.model_validate(config)
        else:
            self.config = config or ConfigSettings()

    async def scan(
        self,
        targets: List[str],
        callback: Optional[Callable[[ScanResult], None]] = None,
    ) -> List[ScanResult]:
        """Scan multiple targets asynchronously with concurrency control."""
        if not targets:
            return []

        semaphore = asyncio.Semaphore(self.config.max_concurrency)
        proxies = self.config.proxies or [None]
        proxy_cycle = cycle(proxies)

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(self.config.timeout),
            follow_redirects=True,
            limits=httpx.Limits(max_keepalive_connections=5, max_connections=10),
        ) as client:
            tasks = [
                self._probe_target(
                    client, target, next(proxy_cycle), semaphore, callback
                )
                for target in targets
            ]
            return await asyncio.gather(*tasks)


    async def _probe_target(
        self,
        client: httpx.AsyncClient,
        target: str,
        proxy: Optional[str],
        semaphore: asyncio.Semaphore,
        callback: Optional[Callable[[ScanResult], None]],
    ) -> ScanResult:
        """Probe a single target URL."""
        async with semaphore:
            if not target.startswith(("http://", "https://")):
                target = "https://" + target.lstrip("/")

            result = ScanResult(url=target)
            try:
                kwargs = {"proxy": proxy} if proxy else {}
                response = await client.get(target, **kwargs)
                response.raise_for_status()

                headers = dict(response.headers)
                body = response.text
                result.detected_from.extend(["headers", "body"])

                community_rules = None
                if self.config.use_community_fingerprints:
                    community_rules = CommunityFingerprinter.load(
                        self.config.community_repo_url
                    )

                php_version = detect_php_version(
                    headers=headers,
                    body=body,
                    community_rules=community_rules,
                )
                if php_version:
                    result.php_version = php_version
                    result.vulns = get_vulns_for_version(php_version)

                # Check for phpinfo-style pages
                for path in ("phpinfo.php", "info.php", "phpinfo"):
                    try:
                        info_url = f"{target.rstrip('/')}/{path}"
                        info_resp = await client.get(info_url, **kwargs)
                        if any(
                            keyword in info_resp.text
                            for keyword in ("PHP Version", "phpinfo()", "Zend")
                        ):
                            result.exposed_files.append(
                                ExposedFile(
                                    url=str(info_resp.url),
                                    file_type="phpinfo",
                                    content_preview=info_resp.text[:500],
                                )
                            )
                            if not result.php_version:
                                pv = detect_from_phpinfo(info_resp.text)
                                if pv:
                                    result.php_version = pv
                                    result.vulns = get_vulns_for_version(pv)
                    except Exception:  # noqa: BLE001
                        continue

                # Schema extraction
                for sql_url in locate_sql_urls(body):
                    try:
                        sql_resp = await client.get(sql_url, **kwargs)
                        if sql_resp.is_success and "CREATE TABLE" in sql_resp.text.upper():
                            schema = parse_sql_dump(sql_resp.text)
                            result.db_schema = schema
                            result.exposed_files.append(
                                ExposedFile(
                                    url=sql_url,
                                    file_type="sql_dump",
                                    content_preview=sql_resp.text[:300],
                                )
                            )
                            break
                    except Exception:  # noqa: BLE001
                        continue

                # Nuclei integration
                if (
                    self.config.use_nuclei
                    and result.php_version
                    and result.php_version.startswith(("5.", "7.0", "7.1", "7.2", "7.3", "7.4"))
                ):
                    findings = validate_with_nuclei(target, result.php_version)
                    if findings:
                        result.nuclei_findings = findings

                # Ollama summarization
                if self.config.use_ollama and (result.vulns or result.exposed_files or result.nuclei_findings):
                    try:
                        result.llm_summary = generate_summary(
                            [result], model=self.config.ollama_model
                        )
                    except Exception as exc:  # noqa: BLE001
                        result.errors.append(f"LLM summary failed: {exc}")

                if callback is not None:
                    callback(result)

                return result

            except httpx.HTTPError as exc:
                result.errors.append(f"HTTP error: {exc}")
                return result
            except Exception as exc:  # noqa: BLE001
                result.errors.append(str(exc))
                return result


async def scan_targets(
    targets: List[str],
    config: Optional[Union[ConfigSettings, Dict[str, Any]]] = None,
    callback: Optional[Callable[[ScanResult], None]] = None,
) -> List[ScanResult]:
    """Public async entrypoint for scanning targets.

    Accepts config as dict (legacy), ConfigSettings instance or None (uses defaults).
    Results are automatically stored in the history DB.
    """
    scanner = AsyncScanner(config)
    results = await scanner.scan(targets, callback)

    # auto-persist (import here avoids potential circular imports)
    from .store import store_results
    store_results(results)
    return results


def scan_targets_direct(
    targets: List[str], config: Optional[Union[ConfigSettings, dict]] = None
) -> List[ScanResult]:
    """Synchronous wrapper used by some tests."""
    return asyncio.run(scan_targets(targets, config))


__all__ = ["scan_targets", "AsyncScanner", "scan_targets_direct"]
