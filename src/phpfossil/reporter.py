"""Report generation utilities for PHP Fossil.

Provides a clean ReportGenerator class with rich terminal tables
and modern, self-contained HTML reports using Jinja2. Supports
custom templates, severity-based coloring, and responsive design
with dark/light mode readiness via CSS variables.
"""

from datetime import datetime
from pathlib import Path
from typing import List, Optional

from jinja2 import Template
from rich.console import Console
from rich.table import Table

from .models import NucleiFinding, ScanResult


class ReportGenerator:
    """Generates terminal and HTML reports from lists of ScanResult objects.

    Production-ready with input validation, rich terminal output,
    and a polished, accessible HTML report with embedded CSS.
    """

    def __init__(self) -> None:
        self.console = Console()

    def to_terminal(self, results: List[ScanResult]) -> None:
        """Render rich terminal table summarizing scan results.

        Includes color-coded vulnerability counts, exposed file
        indicators, Nuclei confirmations and high-risk recommendations.

        Args:
            results: List of ScanResult objects from a scan.

        Raises:
            ValueError: If results is not a list of ScanResult.
        """
        if not isinstance(results, list):
            raise ValueError("results must be a list of ScanResult objects")

        if not results:
            self.console.print("[yellow]No scan results to report.[/]")
            return

        table = Table(
            title="PHP Fossil Scan Report",
            show_lines=True,
            title_style="bold cyan",
        )
        table.add_column("URL", style="bright_blue", no_wrap=True)
        table.add_column("PHP Version", style="magenta")
        table.add_column("Vulns", style="red", justify="right")
        table.add_column("Exposed Files", style="yellow", justify="right")
        table.add_column("Schema", style="green", justify="center")
        table.add_column("Nuclei", style="cyan", justify="right")

        high_risk = sum(1 for r in results if r.is_vulnerable())
        total_exposed = sum(len(r.exposed_files) for r in results)
        total_nuclei = sum(len(r.nuclei_findings) for r in results if not any(f.template == "error" for f in r.nuclei_findings))

        for r in results:
            version_str = r.php_version or "[dim]unknown[/dim]"
            vuln_count = len(r.vulns)
            vuln_str = (
                f"[bold red]{vuln_count}[/]" if vuln_count > 0 else str(vuln_count)
            )
            exposed_str = str(len(r.exposed_files))
            schema_str = (
                f"[bold green]Yes[/] ({len(r.schema.tables)})"
                if r.schema and r.schema.tables
                else "[dim]No[/]"
            )
            nuclei_count = len([f for f in r.nuclei_findings if f.template != "error"])
            nuclei_str = (
                f"[bold cyan]{nuclei_count}[/]" if nuclei_count > 0 else str(nuclei_count)
            )

            table.add_row(
                r.url,
                version_str,
                vuln_str,
                exposed_str,
                schema_str,
                nuclei_str,
            )

        self.console.print(table)
        self.console.print(
            f"\n[bold]Summary:[/] [cyan]{len(results)}[/] targets • "
            f"[red]{high_risk}[/] high-risk • [yellow]{total_exposed}[/] exposed files • "
            f"[cyan]{total_nuclei}[/] Nuclei confirmations"
        )

        if high_risk > 0:
            self.console.print(
                "[bold red]Recommendation:[/] Upgrade all pre-8.1 PHP instances "
                "and remove exposed phpinfo() and SQL dump files immediately."
            )
        if total_nuclei > 0:
            self.console.print(
                "[bold cyan]Nuclei:[/] Confirmed exploits found. Review matched templates above."
            )

    def to_html(
        self, results: List[ScanResult], template_path: Optional[str] = None
    ) -> str:
        """Render a modern standalone HTML report.

        Uses an inline polished template with dark theme, responsive layout,
        subtle transitions, accessible labels, and severity coloring.
        If template_path is supplied, that Jinja2 template is used instead.

        Args:
            results: List of ScanResult objects.
            template_path: Optional path to a custom Jinja2 HTML template.

        Returns:
            Complete HTML document as a string.

        Raises:
            ValueError: If results is not a list.
            FileNotFoundError: If a custom template_path does not exist.
        """
        if not isinstance(results, list):
            raise ValueError("results must be a list of ScanResult objects")

        if not results:
            return "<h1>No scan results available.</h1>"

        if template_path:
            path = Path(template_path)
            if not path.exists():
                raise FileNotFoundError(f"Template not found at {template_path}")
            template_str = path.read_text(encoding="utf-8")
            template = Template(template_str)
        else:
            template = Template(self._default_html_template())

        total_vulns = sum(len(r.vulns) for r in results)
        total_nuclei = sum(
            len([f for f in r.nuclei_findings if f.template != "error"])
            for r in results
        )
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M UTC")

        return template.render(
            results=results,
            now=now_str,
            version="0.1.0",
            total_targets=len(results),
            total_vulns=total_vulns,
            high_risk=sum(1 for r in results if r.is_vulnerable()),
            total_nuclei=total_nuclei,
        )

    def _default_html_template(self) -> str:
        """Return a modern, self-contained HTML template with CSS variables.

        Features dark theme by default, responsive grid, hover states,
        focus indicators, severity-based coloring and a Nuclei column.
        """
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PHP Fossil Report — {{ now }}</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&amp;family=Space+Grotesk:wght@500;600&amp;display=swap');
        :root {
            --bg: #0f172a;
            --card: #1e2937;
            --text: #e2e8f0;
            --accent: #22d3ee;
            --red: #f87171;
            --orange: #fb923c;
            --green: #4ade80;
            --cyan: #67e8f9;
        }
        @media (prefers-color-scheme: light) {
            :root {
                --bg: #f8fafc;
                --card: #ffffff;
                --text: #0f172a;
                --accent: #0891b2;
            }
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
            margin-top: 0;
        }
        .card {
            background: var(--card);
            border-radius: 16px;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: 0 10px 15px -3px rgb(0 0 0 / 0.1);
            transition: transform 0.2s cubic-bezier(0.4, 0, 0.2, 1);
        }
        .card:hover {
            transform: translateY(-2px);
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
        }
        th, td {
            padding: 14px 18px;
            text-align: left;
            border-bottom: 1px solid #334155;
        }
        th {
            background: #334155;
            font-weight: 600;
            color: #c7d2fe;
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.5px;
        }
        tr:hover {
            background: #334155;
        }
        .critical { color: var(--red); font-weight: 600; }
        .high { color: var(--orange); font-weight: 500; }
        .tag {
            display: inline-block;
            padding: 3px 12px;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 500;
            background: #334155;
            color: var(--text);
        }
        .vuln-tag {
            background: #7f1d1d;
            color: #fda4af;
        }
        .nuclei-tag {
            background: #164e63;
            color: var(--cyan);
        }
        a {
            color: var(--accent);
            text-decoration: none;
        }
        a:hover, a:focus {
            text-decoration: underline;
            outline: 2px solid var(--accent);
            outline-offset: 2px;
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 1rem;
            margin-top: 1.5rem;
        }
        .stat {
            background: #334155;
            padding: 1rem;
            border-radius: 12px;
            text-align: center;
            transition: all 0.2s ease;
        }
        footer {
            text-align: center;
            margin-top: 3rem;
            color: #64748b;
            font-size: 0.8rem;
        }
    </style>
</head>
<body>
    <h1>PHP Fossil Security Report</h1>

    <div class="card">
        <h2>Overview</h2>
        <div class="summary">
            <div class="stat">
                <div style="font-size:2rem;font-weight:600;color:var(--accent)">{{ total_targets }}</div>
                <div style="font-size:0.8rem;opacity:0.7">Targets Scanned</div>
            </div>
            <div class="stat">
                <div style="font-size:2rem;font-weight:600;color:var(--red)">{{ total_vulns }}</div>
                <div style="font-size:0.8rem;opacity:0.7">Total CVEs</div>
            </div>
            <div class="stat">
                <div style="font-size:2rem;font-weight:600;color:#f59e0b">{{ high_risk }}</div>
                <div style="font-size:0.8rem;opacity:0.7">High-Risk Targets</div>
            </div>
            <div class="stat">
                <div style="font-size:2rem;font-weight:600;color:var(--cyan)">{{ total_nuclei }}</div>
                <div style="font-size:0.8rem;opacity:0.7">Nuclei Confirmations</div>
            </div>
        </div>
        <p><strong>Generated:</strong> {{ now }}</p>
    </div>

    <div class="card">
        <h2>Scan Findings</h2>
        <table>
            <thead>
                <tr>
                    <th>Target</th>
                    <th>PHP Version</th>
                    <th>Vulnerabilities</th>
                    <th>Exposed Files</th>
                    <th>Schema</th>
                    <th>Nuclei</th>
                </tr>
            </thead>
            <tbody>
            {% for res in results %}
                <tr>
                    <td><a href="{{ res.url }}" target="_blank" rel="noopener">{{ res.url }}</a></td>
                    <td>
                        {% if res.php_version %}
                            <span class="tag">{{ res.php_version }}</span>
                        {% else %}
                            <span style="opacity:0.6">unknown</span>
                        {% endif %}
                    </td>
                    <td>
                        {% if res.vulns %}
                            <span class="tag vuln-tag">{{ res.vulns|length }} CVE(s)</span>
                            <ul style="margin-top:8px;padding-left:1.2rem;font-size:0.9rem">
                            {% for v in res.vulns %}
                                <li class="critical">{{ v.cve }} — {{ v.title }} ({{ v.severity }})</li>
                            {% endfor %}
                            </ul>
                        {% else %}
                            <span class="tag">None</span>
                        {% endif %}
                    </td>
                    <td>
                        {% if res.exposed_files %}
                            {% for file in res.exposed_files %}
                                <div class="tag" style="margin:2px 4px 2px 0">{{ file.file_type }}</div>
                            {% endfor %}
                        {% else %}
                            <span style="opacity:0.5">—</span>
                        {% endif %}
                    </td>
                    <td>
                        {% if res.schema and res.schema.tables %}
                            <span class="tag" style="background:#166534;color:#86efac">
                                {{ res.schema.tables|length }} tables
                            </span>
                        {% else %}
                            <span style="opacity:0.5">No</span>
                        {% endif %}
                    </td>
                    <td>
                        {% if res.nuclei_findings %}
                            {% set confirmed = [] %}
                            {% for f in res.nuclei_findings %}
                                {% if f.template != 'error' %}
                                    {% if confirmed.append(f) %}{% endif %}
                                {% endif %}
                            {% endfor %}
                            {% if confirmed %}
                                <span class="tag nuclei-tag">{{ confirmed|length }} confirmed</span>
                                <ul style="margin-top:8px;padding-left:1.2rem;font-size:0.85rem">
                                {% for f in confirmed[:3] %}
                                    <li>{{ f.name }} <span style="opacity:0.6">({{ f.severity }})</span></li>
                                {% endfor %}
                                </ul>
                            {% else %}
                                <span style="opacity:0.5">—</span>
                            {% endif %}
                        {% else %}
                            <span style="opacity:0.5">—</span>
                        {% endif %}
                    </td>
                </tr>
            {% endfor %}
            </tbody>
        </table>
    </div>

    <div class="card">
        <h2>Recommendations</h2>
        <ul style="line-height:1.8">
            <li>Upgrade any PHP &lt; 8.1 to a currently supported version (8.2+).</li>
            <li>Immediately disable or remove all phpinfo(), info.php and similar debug endpoints.</li>
            <li>Ensure no database schema or backup .sql files are publicly accessible.</li>
            <li>Configure web servers to suppress version strings in HTTP headers.</li>
            <li>Review and remediate every CVE listed above using the supplied references.</li>
            <li>For any Nuclei confirmations, treat them as high-priority actionable issues.</li>
        </ul>
    </div>

    <footer>
        Generated by PHP Fossil v{{ version }} •
        <a href="https://github.com/php-fossil/php-fossil" target="_blank">Open-source legacy PHP scanner</a>
    </footer>
</body>
</html>
"""


def generate_report(
    results: List[ScanResult],
    output_format: str = "terminal",
    output_path: Optional[Path] = None,
    template_path: Optional[str] = None,
) -> Optional[str]:
    """Public convenience function matching the API in __init__.py."""
    generator = ReportGenerator()
    if output_format.lower() == "terminal":
        generator.to_terminal(results)
        return None

    if output_format.lower() in ("html", "html_report"):
        html = generator.to_html(results, template_path)
        if output_path:
            output_path.write_text(html, encoding="utf-8")
        return html

    raise ValueError(f"Unsupported output_format: {output_format}")


__all__ = ["ReportGenerator", "generate_report"]
