"""Async scanner for PHP Fossil with rate limiting, proxy support, fingerprinting,
schema extraction, optional Nuclei and Ollama integration, and live callbacks.
"""

import asyncio
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

import httpx

from .fingerprinter import detect_php_version, load_community_fingerprints
from .models import ExposedFile, ScanResult
from .nuclei import validate_with_nuclei
from .ollama import generate_summary, is_ollama_available
from .schema import locate_sql_urls, parse_sql_dump
from .vulndb import get_vulns_for_version


class AsyncScanner:
    """Main scanner class supporting async concurrent scanning with configurable features."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.max_concurrency: int = min(self.config.get("max_concurrency", 20), 50)
        self.timeout: int = self.config.get("timeout", 12)
        self.proxies = self.config.get("proxies")
        self.use_nuclei: bool = self.config.get("use_nuclei", False)
        self.use_ollama: bool = self.config.get("use_ollama", False)
        self.use_community_fingerprints: bool = self.config.get(
            "use_community_fingerprints", False
        )
        self.ollama_model: str = self.config.get("ollama_model", "llama3")
        self.community_rules = None
        if self.use_community_fingerprints:
            try:
                self.community_rules = load_community_fingerprints(
                    self.config.get("community_repo_url")
                )
            except Exception:  # noqa: BLE001
                self.community_rules = None

    async def scan(
        self, targets: List[str], callback: Optional[Callable[[ScanResult], None]] = None
    ) -> List[ScanResult]:
        """Scan multiple targets concurrently."""
        if not targets:
            return []

        results: List[ScanResult] = []
        semaphore = asyncio.Semaphore(self.max_concurrency)

        async with httpx.AsyncClient(
            timeout=self.timeout,
            proxies=self.proxies,
            follow_redirects=True,
            headers={"User-Agent": "PHP-Fossil-Scanner/0.1.0"},
        ) as client:
            tasks = [
                self._probe_target(t, client, semaphore, callback) for t in targets
            ]
            task_results = await asyncio.gather(*tasks, return_exceptions=True)
            for res in task_results:
                if isinstance(res, Exception):
                    results.append(
                        ScanResult(
                            url="error-target",
                            errors=[f"Scan failed: {str(res)}"],
                        )
                    )
                else:
                    results.append(res)
        return results

    async def _probe_target(
        self,
        url: str,
        client: httpx.AsyncClient,
        semaphore: asyncio.Semaphore,
        callback: Optional[Callable[[ScanResult], None]] = None,
    ) -> ScanResult:
        """Probe a single target with all enabled detection vectors."""
        async with semaphore:
            result = ScanResult(url=url)
            try:
                response = await client.get(url)
                headers = dict(response.headers)
                body = response.text
                if not response.is_success:
                    result.errors.append(f"HTTP status: {response.status_code}")

                # Version detection (headers, body, community rules)
                php_version = detect_php_version(
                    headers=headers,
                    body=body,
                    community_rules=self.community_rules
                    if self.use_community_fingerprints
                    else None,
                )
                if php_version:
                    result.php_version = php_version
                    result.detected_from.append(
                        "community"
                        if self.use_community_fingerprints
                        else "headers/body"
                    )
                    result.vulns = get_vulns_for_version(php_version)

                # Schema / exposed SQL files
                sql_urls = locate_sql_urls(body, url)
                for sql_url in sql_urls:
                    try:
                        sql_response = await client.get(sql_url)
                        if sql_response.is_success:
                            content = sql_response.text
                            preview = (
                                content[:400] + "..."
                                if len(content) > 400
                                else content
                            )
                            result.exposed_files.append(
                                ExposedFile(
                                    url=sql_url,
                                    file_type="sql_dump",
                                    content_preview=preview,
                                )
                            )
                            schema = parse_sql_dump(content)
                            if schema:
                                result.db_schema = schema
                            break
                    except httpx.HTTPError:
                        continue
                    except Exception as e:  # noqa: BLE001
                        result.errors.append(f"SQL fetch error for {sql_url}: {e}")

                # Nuclei validation
                if self.use_nuclei and result.vulns:
                    try:
                        result.nuclei_findings = validate_with_nuclei(
                            url, result.vulns
                        )
                    except Exception as e:  # noqa: BLE001
                        result.errors.append(f"Nuclei failed: {e}")

                # Ollama summarization
                if (
                    self.use_ollama
                    and result.php_version
                    and (result.vulns or result.db_schema)
                ):
                    try:
                        if is_ollama_available():
                            summary = generate_summary([result], self.ollama_model)
                            result.llm_summary = summary
                    except Exception as e:  # noqa: BLE001
                        result.errors.append(f"Ollama summary failed: {e}")

                if callback is not None:
                    callback(result)

            except httpx.TimeoutException:
                result.errors.append("Request timeout")
            except httpx.RequestError as e:
                result.errors.append(f"Request error: {str(e)}")
            except Exception as e:  # noqa: BLE001
                result.errors.append(f"Unexpected error: {str(e)}")

            result.scan_time = datetime.now()
            return result


async def scan_targets(
    targets: List[str],
    config: Optional[Dict[str, Any]] = None,
    callback: Optional[Callable[[ScanResult], None]] = None,
) -> List[ScanResult]:
    """Public async entrypoint for scanning targets."""
    scanner = AsyncScanner(config)
    return await scanner.scan(targets, callback)


__all__ = ["scan_targets", "AsyncScanner"]
