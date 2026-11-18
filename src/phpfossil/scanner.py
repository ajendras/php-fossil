"""Async target scanner with rate limiting and modular detection.

The main entrypoint is the `scan_targets()` function. It accepts a list of URLs
and an optional ConfigSettings instance (or legacy dict). All configuration is
validated by the pydantic ConfigSettings model, providing defaults, constraints
and improved DX. Delegates to fingerprinter, vulndb, schema, nuclei and ollama
modules.
"""

import asyncio
from typing import Any, Callable, Dict, List, Optional, Union

import httpx

from .fingerprinter import (
    detect_php_version,
    load_community_fingerprints,
    detect_cms_version,
)
from .models import (
    ConfigSettings,
    ScanResult,
    Vulnerability,
    ExposedFile,
    SchemaResult,
)
from .vulndb import get_vulns_for_version
from .schema import parse_sql_dump
from .nuclei import validate_with_nuclei
from .ollama import generate_summary, is_ollama_available


class AsyncScanner:
    """Main scanner class. Accepts ConfigSettings for validated config with defaults."""

    def __init__(self, config: Optional[Union[ConfigSettings, Dict[str, Any]]] = None):
        if isinstance(config, ConfigSettings):
            self.config = config
        elif isinstance(config, dict) or config is None:
            self.config = ConfigSettings(**(config or {}))
        else:
            self.config = ConfigSettings()

    async def scan(
        self, targets: List[str], callback: Optional[Callable[[ScanResult], None]] = None
    ) -> List[ScanResult]:
        """Scan multiple targets concurrently with rate limiting."""
        semaphore = asyncio.Semaphore(self.config.max_concurrency)
        results: List[ScanResult] = []

        limits = httpx.Limits(max_connections=self.config.max_concurrency)
        async with httpx.AsyncClient(
            timeout=self.config.timeout,
            follow_redirects=True,
            limits=limits,
            proxies=self.config.proxies if self.config.proxies else None,
        ) as client:
            tasks = [
                asyncio.create_task(
                    self._scan_single(target, client, semaphore, callback)
                )
                for target in targets
            ]
            for completed in asyncio.as_completed(tasks):
                result = await completed
                results.append(result)
                if callback:
                    callback(result)
        return results

    async def _scan_single(
        self,
        url: str,
        client: httpx.AsyncClient,
        semaphore: asyncio.Semaphore,
        callback: Optional[Callable[[ScanResult], None]] = None,
    ) -> ScanResult:
        """Probe a single target and enrich with fingerprint, vulns, schema, nuclei, ollama."""
        async with semaphore:
            if not url.startswith(("http://", "https://")):
                url = f"https://{url}"
            result = ScanResult(url=url)

            try:
                resp = await client.get(url)
                resp.raise_for_status()
                headers = dict(resp.headers)
                body = resp.text

                result.detected_from = []

                # Community fingerprints if enabled
                community_rules = None
                if self.config.use_community_fingerprints:
                    community_rules = load_community_fingerprints(
                        self.config.community_repo_url
                    )

                # Version fingerprinting
                version = detect_php_version(
                    headers=headers,
                    body=body,
                    community_rules=community_rules,
                )
                if version:
                    result.php_version = version
                    result.detected_from.append("headers/body/fingerprint")
                    result.vulns = get_vulns_for_version(version)

                # CMS detection as extra signal
                cms_info = detect_cms_version(body)
                if cms_info:
                    result.detected_from.append(f"cms:{cms_info[0]}")

                # Exposed file and schema detection
                for path in [
                    "phpinfo.php",
                    "info.php",
                    "test.php",
                    ".env",
                    "dump.sql",
                    "backup.sql",
                    "schema.sql",
                ]:
                    try:
                        file_url = f"{url.rstrip('/')}/{path}"
                        fresp = await client.get(file_url, timeout=5.0)
                        if fresp.status_code == 200 and len(fresp.text.strip()) > 30:
                            ftype = (
                                "phpinfo"
                                if "phpinfo" in path or "info" in path
                                else "sql_dump"
                                if any(x in path for x in ("sql", "dump", "schema"))
                                else "exposed"
                            )
                            preview = fresp.text[:180].replace("\n", " ").strip()
                            result.exposed_files.append(
                                ExposedFile(
                                    url=file_url,
                                    file_type=ftype,
                                    content_preview=preview,
                                )
                            )
                            if ftype == "sql_dump":
                                try:
                                    parsed = parse_sql_dump(fresp.text)
                                    if isinstance(parsed, dict):
                                        result.db_schema = SchemaResult(
                                            tables=parsed.get("tables", []),
                                            columns=parsed.get("columns", {}),
                                            row_counts=parsed.get("row_counts", {}),
                                        )
                                    else:
                                        result.db_schema = parsed
                                except Exception:  # noqa: BLE001
                                    result.db_schema = SchemaResult()
                    except Exception:  # noqa: BLE001
                        continue

                # Nuclei validation if enabled and vulns present
                if self.config.use_nuclei and result.vulns:
                    result.nuclei_findings = validate_with_nuclei(
                        result.url, result.vulns, timeout=self.config.timeout
                    )

                # Ollama summary if enabled and issues found
                if self.config.use_ollama and (result.is_vulnerable() or result.exposed_files):
                    if is_ollama_available():
                        result.llm_summary = generate_summary(
                            [result], model=self.config.ollama_model
                        )
                    else:
                        result.llm_summary = (
                            "Ollama not available. Start with `ollama serve`."
                        )

                # Demo fallback for legacy PHP when no vulns detected by DB
                if (
                    not result.vulns
                    and result.php_version
                    and result.php_version.startswith(("5.", "7."))
                ):
                    result.vulns = get_vulns_for_version(result.php_version) or [
                        Vulnerability(
                            cve="CVE-2019-11043",
                            title="PHP-FPM RCE example",
                            severity="high",
                            description="Example vulnerability for legacy PHP versions.",
                            fixed_in="7.4.33",
                            reference="https://github.com/php/php-src/pull/4760",
                        )
                    ]

            except httpx.RequestError as exc:
                result.errors.append(f"Request error: {exc}")
            except Exception as exc:  # noqa: BLE001
                result.errors.append(str(exc))

            return result


async def scan_targets(
    targets: List[str],
    config: Optional[Union[Dict[str, Any], ConfigSettings]] = None,
    callback: Optional[Callable[[ScanResult], None]] = None,
) -> List[ScanResult]:
    """Public async entrypoint for scanning targets.

    Accepts either a ConfigSettings instance (preferred, validated with defaults)
    or a legacy dict. Returns list of ScanResult objects. All scans are
    automatically persisted by the caller via store_results().
    """
    scanner = AsyncScanner(config=config)
    return await scanner.scan(targets, callback=callback)


__all__ = ["scan_targets", "AsyncScanner"]
