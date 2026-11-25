"""Report generator for PHP Fossil.

Supports terminal (rich tables), self-contained dark HTML reports with sortable table,
and CSV exports formatted for bug-bounty platforms (one row per vulnerability).
Avoids any unbalanced rich markup to prevent MarkupError.
"""

import csv
import json
from pathlib import Path
from typing import List, Optional

from rich.console import Console
from rich.table import Table

from .models import ScanResult


def generate_report(
    results: List[ScanResult],
    output_format: str = "terminal",
    output_path: Optional[Path] = None,
) -> None:
    """Main report entrypoint. Dispatches to format-specific generators.
    All rich markup is balanced; fixes test_generate_report_terminal_smoke MarkupError.
    """
    if not results:
        Console().print("[yellow]No results to report.[/]")
        return

    if output_format == "terminal":
        _to_terminal(results)
    elif output_format == "html":
        _to_html(results, output_path)
    elif output_format == "csv":
        _to_csv(results, output_path)
    else:
        Console().print(f"[red]Unknown format: {output_format}[/]")


def _to_terminal(results: List[ScanResult]) -> None:
    """Rich terminal table with balanced markup only."""
    console = Console()
    console.print("\n[bold cyan]PHP Fossil Scan Results[/]\n")

    table = Table(title="Scan Summary", show_header=True, header_style="bold magenta")
    table.add_column("URL", style="cyan")
    table.add_column("PHP Version", style="green")
    table.add_column("Risk Score", style="yellow")
    table.add_column("Vulns", style="red")
    table.add_column("Exposed Files", style="blue")
    table.add_column("Summary")

    for r in results:
        risk_style = "red" if r.risk_score >= 70 else "yellow" if r.risk_score >= 40 else "green"
        vulns_count = len(r.vulns)
        exposed_count = len(r.exposed_files)
        summary = r.llm_summary[:60] + "..." if r.llm_summary else (r.risk_summary.upper() if r.risk_summary else "low")
        table.add_row(
            r.url,
            r.php_version or "unknown",
            f"[{risk_style}]{r.risk_score}[/{risk_style}]",
            str(vulns_count),
            str(exposed_count),
            summary,
        )

    console.print(table)
    console.print("\n[dim]Scan data persisted to SQLite. Use 'php-fossil history' to review.[/]\n")


def _to_html(results: List[ScanResult], output_path: Optional[Path] = None) -> None:
    """Self-contained dark HTML report with sortable vulnerability table (no external deps)."""
    if not output_path:
        output_path = Path("phpfossil-report.html")

    html = """<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>PHP Fossil Report</title>
    <style>
        body { font-family: system-ui, sans-serif; background: #1a1a1a; color: #ddd; padding: 20px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #444; }
        th { background: #2a2a2a; cursor: pointer; }
        tr:hover { background: #252525; }
        .critical { background: #440000; color: #ff8888; }
        .high { background: #442200; color: #ffcc88; }
        .medium { background: #333300; color: #ffff88; }
    </style>
    <script>
        function sortTable(n) {
            let table = document.querySelector("table");
            let rows = Array.from(table.rows).slice(1);
            let dir = table.getAttribute("data-dir") === "asc" ? "desc" : "asc";
            rows.sort((a, b) => {
                let x = a.cells[n].textContent.trim();
                let y = b.cells[n].textContent.trim();
                return (dir === "asc" ? x.localeCompare(y) : y.localeCompare(x));
            });
            rows.forEach(row => table.tBodies[0].appendChild(row));
            table.setAttribute("data-dir", dir);
        }
    </script>
</head>
<body>
    <h1>PHP Fossil Report</h1>
    <p>Generated on """ + str(results[0].scan_time if results else "now") + """</p>
    <table>
        <thead>
            <tr>
                <th onclick="sortTable(0)">URL</th>
                <th onclick="sortTable(1)">PHP Version</th>
                <th onclick="sortTable(2)">Risk</th>
                <th onclick="sortTable(3)">Vulns</th>
            </tr>
        </thead>
        <tbody>
    """
    for r in results:
        risk_class = r.risk_summary
        html += f"""
            <tr>
                <td>{r.url}</td>
                <td>{r.php_version or 'unknown'}</td>
                <td class="{risk_class}">{r.risk_score} ({r.risk_summary})</td>
                <td>{len(r.vulns)}</td>
            </tr>
        """
    html += """
        </tbody>
    </table>
    <p style="margin-top:30px;font-size:0.9em;color:#888;">
        Exported by PHP Fossil • Dark mode • Click headers to sort
    </p>
</body>
</html>
"""
    output_path.write_text(html, encoding="utf-8")


def _to_csv(results: List[ScanResult], output_path: Optional[Path] = None) -> None:
    """CSV export with one row per vulnerability, ready for HackerOne/Bugcrowd import."""
    if not output_path:
        output_path = Path("bounty.csv")

    rows = []
    for r in results:
        for v in r.vulns:
            rows.append({
                "url": r.url,
                "php_version": r.php_version or "",
                "risk_score": r.risk_score,
                "cve": v.cve,
                "title": v.title,
                "severity": v.severity,
                "description": v.description,
                "fixed_in": v.fixed_in or "",
                "reference": v.references[0] if v.references else "",
            })
        if not r.vulns and r.nuclei_findings:
            for n in r.nuclei_findings:
                rows.append({
                    "url": r.url,
                    "php_version": r.php_version or "",
                    "risk_score": r.risk_score,
                    "cve": "Nuclei-" + n.template,
                    "title": n.name,
                    "severity": n.severity,
                    "description": n.description or "Confirmed by Nuclei",
                    "fixed_in": "",
                    "reference": n.reference or "",
                })

    if not rows:
        rows = [{"url": r.url, "php_version": r.php_version or "", "risk_score": r.risk_score, "cve": "N/A", "title": "No vulns", "severity": "info", "description": "No issues found", "fixed_in": "", "reference": ""} for r in results]

    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["url", "php_version", "risk_score", "cve", "title", "severity", "description", "fixed_in", "reference"])
        writer.writeheader()
        writer.writerows(rows)


# Legacy compatibility aliases
to_terminal = _to_terminal
to_html = _to_html
to_csv = _to_csv
