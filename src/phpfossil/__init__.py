"""PHP Fossil — discovers legacy PHP sites via search dorks, fingerprints old versions,
maps vulns, extracts schemas and builds prioritized security lists.

Public API:
    scan_targets, generate_dorks, generate_report, ScanResult, Vulnerability
"""

from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
from bs4 import BeautifulSoup
from jinja2 import Template
from pydantic import BaseModel, Field
from rich.console import Console
from rich.table import Table

__version__ = "0.1.0"

console = Console()


class Vulnerability(BaseModel):
    """Represents a known vulnerability tied to a PHP version."""

    cve: str
    title: str
    severity: str
    description: str
    fixed_in: Optional[str] = None
    reference: Optional[str] = None


class ExposedFile(BaseModel):
    """Represents a sensitive file discovered on a target (phpinfo, SQL dump, etc)."""

    url: str
    file_type: str
    content_preview: Optional[str] = None


class SchemaResult(BaseModel):
    """Parsed information from an exposed SQL dump."""

    tables: List[str] = Field(default_factory=list)
    columns: Dict[str, List[str]] = Field(default_factory=dict)
    row_counts: Dict[str, int] = Field(default_factory=dict)


class ScanResult(BaseModel):
    """Result of scanning one target."""

    url: str
    php_version: Optional[str] = Field(None, description="Detected PHP version string")
    detected_from: List[str] = Field(default_factory=list)
    vulns: List[Vulnerability] = Field(default_factory=list)
    exposed_files: List[ExposedFile] = Field(default_factory=list)
    schema: Optional[SchemaResult] = None
    errors: List[str] = Field(default_factory=list)
    scan_time: datetime = Field(default_factory=datetime.utcnow)

    def is_vulnerable(self) -> bool:
        """Return True if any vulnerabilities were found."""
        return len(self.vulns) > 0


def _get_embedded_vulndb() -> Dict[str, List[Vulnerability]]:
    """Return a small embedded database of PHP CVEs."""
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
    if not version:
        return []
    db = _get_embedded_vulndb()
    for prefix, entries in db.items():
        if version.startswith(prefix):
            return entries
    # Fallback for any legacy version
    if version.startswith(("4.", "5.", "6.", "7.0", "7.1", "7.2")):
        return db.get("5.", [])
    return []


def parse_sql_dump(content: str) -> SchemaResult:
    """Simple regex-based parser for SQL dumps. Extracts table names and columns."""
    tables: List[str] = re.findall(r"(?i)CREATE TABLE\s+[`']?(\w+)[`']?", content)
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

    return SchemaResult(tables=unique_tables, columns=columns)


async def _probe_target(
    url: str, client: httpx.AsyncClient, config: Dict[str, Any]
) -> ScanResult:
    """Probe a single target for PHP version, exposed files, and vulnerabilities."""
    result = ScanResult(url=url)
    headers = {"User-Agent": f"PHPFossil/{__version__} (https://github.com/php-fossil)"}

    try:
        resp = await client.get(
            url,
            headers=headers,
            timeout=config.get("timeout", 12.0),
            follow_redirects=True,
        )
        result.detected_from.append("http-response")

        # Fingerprint from headers
        powered_by = resp.headers.get("X-Powered-By") or resp.headers.get("Server", "")
        if "PHP" in powered_by.upper():
            match = re.search(r"PHP[/\s]?([0-9.]+)", powered_by, re.IGNORECASE)
            if match:
                result.php_version = match.group(1)
                result.detected_from.append("x-powered-by")

        body = resp.text

        # Fingerprint from body
        if not result.php_version:
            patterns = [
                r"PHP Version</td>\s*<td[^>]*>([0-9.]+)",
                r"php-?version[\"']?\s*[:=]\s*[\"']?([0-9.]+)",
                r"Powered by PHP ([0-9.]+)",
            ]
            for pattern in patterns:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    result.php_version = match.group(1)
                    result.detected_from.append("body")
                    break

        base = url.rstrip("/")

        # Probe common phpinfo locations
        for path in ("/phpinfo.php", "/info.php", "/php.php"):
            probe_url = base + path
            try:
                info_resp = await client.get(
                    probe_url, headers=headers, timeout=8.0
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
                        vmatch = re.search(
                            r"PHP Version.*?([0-9]+\.[0-9]+\.[0-9]+)",
                            info_resp.text,
                            re.IGNORECASE | re.DOTALL,
                        )
                        if vmatch:
                            result.php_version = vmatch.group(1)
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
                    probe_url, headers=headers, timeout=8.0
                )
                if sql_resp.status_code == 200 and any(
                    kw in sql_resp.text.lower()
                    for kw in ("create table", "insert into", "phpmyadmin")
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
            except httpx.TransportError:
                continue

        # Final fallback via error page
        if not result.php_version:
            try:
                err_url = base + "/nonexistent-404.php"
                err_resp = await client.get(err_url, headers=headers, timeout=6.0)
                match = re.search(r"PHP ([0-9.]+)", err_resp.text)
                if match:
                    result.php_version = match.group(1)
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


def generate_dorks(version: str, count: int = 12) -> List[str]:
    """Generate ready-to-use Google/Bing/Shodan dorks for a PHP version.

    Uses 18 distinct template patterns with variations.
    """
    if not version or not isinstance(version, str):
        raise ValueError("version must be a non-empty string (e.g. '7.4.33')")

    version = version.strip()
    templates = [
        f'PHP/{version} "X-Powered-By"',
        f'"PHP Version {version}"',
        f'inurl:phpinfo "Version {version}"',
        'intitle:phpinfo "PHP Version"',
        f'"{version}" filetype:php inurl:info',
        f'inurl:"?PHPSESSID=" "{version}"',
        'inurl:admin "powered by php"',
        f'ext:sql "MySQL dump" "{version}"',
        'inurl:backup "php" intitle:"index of"',
        '"mysql_connect" "php" -inurl:(github.com|gitlab.com)',
        f'"Server: Apache" "PHP/{version}"',
        'inurl:.php "Deprecated:"',
        '"PHP Parse error"',
        'intext:"PHP Warning" inurl:.php',
        f'site:.edu "PHP {version}"',
        f'site:.gov inurl:php {version}',
        'inurl:wp-content "PHP 5"',
        '"X-Powered-By" "PHP"',
    ]

    dorks: List[str] = []
    extras = ["inurl:admin", "intitle:index.of", "inurl:login", ""]
    i = 0
    while len(dorks) < count and i < 200:
        base = templates[i % len(templates)]
        prefix = extras[i % len(extras)]
        dork = f"{prefix} {base}".strip()
        if dork not in dorks:
            dorks.append(dork)
        i += 1

    return dorks[:count]


def generate_report(
    results: List[ScanResult],
    output_format: str = "terminal",
    output_path: Optional[Path] = None,
) -> Optional[str]:
    """Generate a terminal table report or a standalone HTML report.

    Returns HTML string when output_format is html, otherwise prints to console.
    """
    if not results:
        console.print("[yellow]No scan results to report.[/]")
        return None

    if output_format.lower() == "terminal":
        _render_terminal_report(results)
        return None

    if output_format.lower() in ("html", "html_report"):
        html = _render_html_report(results)
        if output_path:
            output_path.write_text(html, encoding="utf-8")
            console.print(f"[green]HTML report written to {output_path}[/]")
        return html

    raise ValueError(f"Unsupported output_format: {output_format}")


def _render_terminal_report(results: List[ScanResult]) -> None:
    """Render a rich table summary of scan results."""
    table = Table(title="PHP Fossil Scan Report", show_lines=True)
    table.add_column("URL", style="bright_blue", no_wrap=True)
    table.add_column("PHP Version", style="magenta")
    table.add_column("Vulns", style="red")
    table.add_column("Exposed", style="yellow")
    table.add_column("Schema", style="green")

    high_risk = 0
    for r in results:
        vcount = len(r.vulns)
        if vcount > 0:
            high_risk += 1
        ecount = len(r.exposed_files)
        schema_flag = "Yes" if r.schema and r.schema.tables else "No"
        version_str = r.php_version or "[dim]unknown[/dim]"
        vuln_str = f"[bold red]{vcount}[/]" if vcount else str(vcount)

        table.add_row(r.url, version_str, vuln_str, str(ecount), schema_flag)

    console.print(table)
    console.print(
        f"\n[bold]Summary:[/] [cyan]{len(results)}[/] targets • "
        f"[red]{high_risk}[/] high-risk findings"
    )
    if high_risk:
        console.print(
            "[bold red]Recommendation:[/] Upgrade all pre-8.1 PHP instances "
            "and remove exposed phpinfo / SQL files immediately."
        )


def _render_html_report(results: List[ScanResult]) -> str:
    """Render a modern, self-contained HTML report using an inline Jinja template."""
    template = Template(
        """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PHP Fossil Report — {{ now }}</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=Space+Grotesk:wght@500;600&display=swap');
        :root {
            --bg: #0f172a;
            --card: #1e2937;
            --text: #e2e8f0;
            --accent: #22d3ee;
            --red: #f87171;
        }
        body {
            font-family: 'Inter', system-ui, sans-serif;
            background: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 2rem;
            line-height: 1.6;
        }
        h1 {
            font-family: 'Space Grotesk', sans-serif;
            color: var(--accent);
            border-bottom: 4px solid var(--accent);
            padding-bottom: 0.75rem;
        }
        .card {
            background: var(--card);
            border-radius: 16px;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: 0 25px 50px -12px rgb(0 0 0 / 0.4);
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 14px 18px;
            text-align: left;
            border-bottom: 1px solid #334155;
        }
        th {
            background: #334155;
            font-weight: 500;
            color: #a5b4fc;
        }
        tr:hover {
            background: #334155;
        }
        .critical { color: var(--red); font-weight: 600; }
        .tag {
            display: inline-block;
            padding: 3px 12px;
            border-radius: 9999px;
            font-size: 0.8rem;
            background: #334155;
        }
        a { color: var(--accent); text-decoration: none; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <h1>PHP Fossil Security Report</h1>
    <div class="card">
        <h2>Overview</h2>
        <p><strong>Generated:</strong> {{ now }}</p>
        <p><strong>Targets scanned:</strong> {{ results|length }}</p>
    </div>

    <div class="card">
        <h2>Findings</h2>
        <table>
            <thead>
                <tr>
                    <th>Target</th>
                    <th>PHP Version</th>
                    <th>Vulnerabilities</th>
                    <th>Exposed Files</th>
                </tr>
            </thead>
            <tbody>
            {% for res in results %}
                <tr>
                    <td><a href="{{ res.url }}" target="_blank">{{ res.url }}</a></td>
                    <td>{{ res.php_version or 'Unknown' }}</td>
                    <td>
                        {% if res.vulns %}
                            <span class="tag critical">{{ res.vulns|length }} CVE(s)</span>
                            <ul style="margin-top:8px;padding-left:20px">
                            {% for v in res.vulns %}
                                <li class="critical">{{ v.cve }} — {{ v.title }}</li>
                            {% endfor %}
                            </ul>
                        {% else %}
                            <span class="tag">None</span>
                        {% endif %}
                    </td>
                    <td>{{ res.exposed_files|length }}</td>
                </tr>
            {% endfor %}
            </tbody>
        </table>
    </div>

    <div class="card">
        <h2>Recommendations</h2>
        <ul>
            <li>Immediately upgrade any PHP &lt; 8.1 to a supported release.</li>
            <li>Disable or remove all phpinfo() endpoints from production servers.</li>
            <li>Never expose database schema or backup SQL files publicly.</li>
            <li>Configure web servers to omit version strings from HTTP headers.</li>
            <li>Review and remediate the vulnerabilities listed above.</li>
        </ul>
    </div>
</body>
</html>
"""
    )
    return template.render(
        results=results,
        now=datetime.now().strftime("%Y-%m-%d %H:%M UTC"),
    )


__all__ = [
    "__version__",
    "scan_targets",
    "generate_dorks",
    "generate_report",
    "ScanResult",
    "Vulnerability",
    "ExposedFile",
    "SchemaResult",
]
