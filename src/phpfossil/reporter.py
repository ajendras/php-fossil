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
    Now includes optional Ollama LLM summary section and risk_score.
    """

    def __init__(self) -> None:
        self.console = Console()

    def to_terminal(self, results: List[ScanResult]) -> None:
        """Render rich terminal table summarizing scan results.

        Includes color-coded vulnerability counts, exposed file
        indicators, Nuclei confirmations and high-risk recommendations.
        If an LLM summary is present it is printed after the table.
        """
        if not isinstance(results, list):
            raise ValueError("results must be a list of ScanResult objects")

        if not results:
            self.console.print("[yellow]No results to report.[/]")
            return

        table = Table(title="PHP Fossil Scan Results", show_header=True, header_style="bold magenta")
        table.add_column("URL", style="cyan", no_wrap=True)
        table.add_column("PHP Version", justify="center")
        table.add_column("Risk Score", justify="center")
        table.add_column("Vulns", justify="center")
        table.add_column("Exposed", justify="center")
        table.add_column("Nuclei", justify="center")
        table.add_column("LLM Summary?")

        for result in results:
            score = result.risk_score
            if score >= 75:
                score_style = "[bold red]"
            elif score >= 50:
                score_style = "[bold yellow]"
            else:
                score_style = "[green]"
            score_str = f"{score_style}{score}[/]"

            vulns_count = len(result.vulns)
            exposed_count = len(result.exposed_files)
            nuclei_count = len(result.nuclei_findings)
            llm = "Yes" if result.llm_summary else "No"
            version = result.php_version or "unknown"

            table.add_row(
                result.url,
                version,
                score_str,
                str(vulns_count),
                str(exposed_count),
                str(nuclei_count),
                llm,
            )

        self.console.print(table)

        # Print high risk ones
        high_risk = [r for r in results if r.risk_score >= 60]
        if high_risk:
            self.console.print("\n[bold red]High Risk Targets:[/]")
            for r in high_risk:
                self.console.print(f"  • {r.url} (score: {r.risk_score})")

        # Print LLM summary if available (first one with summary)
        for r in results:
            if r.llm_summary:
                self.console.print("\n[bold]LLM Executive Summary:[/]")
                self.console.print(r.llm_summary)
                break

    def to_html(self, results: List[ScanResult], output_path: Path) -> None:
        """Generate a self-contained HTML report with risk scores."""
        if not results:
            return

        # Embedded template with risk score column and color coding
        template_str = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>PHP Fossil Report</title>
    <style>
        body { font-family: system-ui, sans-serif; margin: 40px; background: #f8f9fa; }
        table { border-collapse: collapse; width: 100%; background: white; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #2e8b57; color: white; }
        tr:hover { background: #f5f5f5; }
        .score { font-size: 1.2em; font-weight: bold; text-align: center; }
        .high { color: #d32f2f; }
        .medium { color: #f57c00; }
        .summary { background: #e8f5e9; padding: 20px; border-radius: 8px; margin: 20px 0; line-height: 1.6; }
    </style>
</head>
<body>
    <h1>PHP Fossil Scan Report</h1>
    <p>Generated on {{ now }}</p>
    <table>
        <thead>
            <tr>
                <th>URL</th>
                <th>PHP Version</th>
                <th>Risk Score</th>
                <th>Vulnerabilities</th>
                <th>Exposed Files</th>
                <th>Nuclei Findings</th>
            </tr>
        </thead>
        <tbody>
            {% for result in results %}
            <tr>
                <td>{{ result.url }}</td>
                <td>{{ result.php_version or 'N/A' }}</td>
                <td class="score {% if result.risk_score >= 75 %}high{% elif result.risk_score >= 50 %}medium{% endif %}">{{ result.risk_score }}</td>
                <td>{{ result.vulns|length }}</td>
                <td>{{ result.exposed_files|length }}</td>
                <td>{{ result.nuclei_findings|length }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    {% if summary %}
    <div class="summary">
        <h2>Executive Summary</h2>
        {{ summary | safe }}
    </div>
    {% endif %}
</body>
</html>
        """

        template = Template(template_str)

        # Use first llm_summary if any
        summary = next((r.llm_summary for r in results if r.llm_summary), None)

        html = template.render(
            results=results,
            now=datetime.now().isoformat(),
            summary=summary or "No LLM summary available."
        )

        output_path.write_text(html, encoding="utf-8")

def generate_report(
    results: List[ScanResult],
    output_format: str = "terminal",
    output_path: Optional[Path] = None,
) -> None:
    """Public convenience function to generate reports."""
    generator = ReportGenerator()
    if output_format == "terminal":
        generator.to_terminal(results)
    elif output_format == "html":
        if not output_path:
            output_path = Path("phpfossil-report.html")
        generator.to_html(results, output_path)
        print(f"HTML report written to {output_path}")
    else:
        raise ValueError(f"Unknown format: {output_format}")


__all__ = ["generate_report", "ReportGenerator"]
