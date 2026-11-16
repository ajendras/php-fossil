"""Report generation for PHP Fossil.

Supports terminal (rich tables), HTML (dark mode with sortable vulnerability table using Tailwind CDN + vanilla JS), and CSV (one row per vulnerability for bug-bounty platforms).

The HTML report is completely self-contained, includes a metrics dashboard, live filter input, clickable sortable column headers, severity-colored badges, reference links and a CSV export button. All consistent with existing models, style and public API.
"""

import csv
import io
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from jinja2 import Template
from rich.console import Console
from rich.table import Table

from .models import ScanResult

console = Console()


def generate_report(
    results: List[ScanResult],
    output_format: str = "terminal",
    output_path: Optional[Path] = None,
) -> Optional[str]:
    """Main entrypoint for generating reports.

    Dispatches based on output_format. Returns generated content for
    html/csv; terminal report is printed directly. Consistent with
    existing public API and CLI usage.
    """
    if not results:
        console.print("[yellow]No results to report.[/]")
        return None

    if output_format == "terminal":
        _generate_terminal_report(results)
        return None
    elif output_format == "html":
        html_content = _generate_html_report(results)
        if output_path:
            output_path.write_text(html_content, encoding="utf-8")
            console.print(f"[green]Dark-mode HTML report written to {output_path}[/]")
        return html_content
    elif output_format == "csv":
        return _generate_csv_report(results, output_path)
    else:
        console.print(f"[red]Unknown format '{output_format}'. Use terminal, html or csv.[/]")
        return None


def _generate_terminal_report(results: List[ScanResult]) -> None:
    """Print rich terminal summary table (unchanged core behaviour)."""
    table = Table(title="PHP Fossil Scan Results")
    table.add_column("URL")
    table.add_column("PHP Version")
    table.add_column("Risk")
    table.add_column("Vulns")
    table.add_column("Nuclei")
    table.add_column("Schema")

    for r in results:
        vcount = len(r.vulns)
        ncount = len(r.nuclei_findings)
        schema_flag = "Yes" if r.db_schema and r.db_schema.tables else "No"
        risk_style = "[bold red]" if r.risk_score >= 70 else "[bold yellow]" if r.risk_score >= 40 else ""
        table.add_row(
            r.url,
            r.php_version or "unknown",
            f"{risk_style}{r.risk_score}[/]",
            str(vcount),
            str(ncount),
            schema_flag,
        )

    console.print(table)

    if any(r.vulns for r in results):
        console.print("\n[bold]Key Vulnerabilities[/]")
        for r in results:
            if r.vulns:
                console.print(f"  [cyan]{r.url}[/] ([magenta]{r.php_version or 'N/A'}[/]) — Risk {r.risk_score}")
                for v in r.vulns[:3]:
                    console.print(f"    • [red]{v.cve}[/] {v.title} ([yellow]{v.severity}[/])")


def _prepare_vulnerability_rows(results: List[ScanResult]) -> List[Dict[str, Any]]:
    """Flatten ScanResult objects into rows suitable for the HTML table and CSV.

    One row per vulnerability (or a placeholder row when no vulns were found).
    """
    rows: List[Dict[str, Any]] = []
    for result in results:
        base = {
            "url": result.url,
            "php_version": result.php_version or "N/A",
            "risk_score": result.risk_score,
            "nuclei_count": len(result.nuclei_findings),
            "has_schema": bool(result.db_schema and result.db_schema.tables),
        }
        if result.vulns:
            for vuln in result.vulns:
                row = base.copy()
                row.update(
                    {
                        "cve": vuln.cve,
                        "title": vuln.title,
                        "severity": vuln.severity,
                        "fixed_in": vuln.fixed_in or "N/A",
                        "reference": vuln.reference or "",
                    }
                )
                rows.append(row)
        else:
            row = base.copy()
            row.update(
                {
                    "cve": "—",
                    "title": "No known vulnerabilities detected",
                    "severity": "low",
                    "fixed_in": "—",
                    "reference": "",
                }
            )
            rows.append(row)
    return rows


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PHP Fossil — Security Report</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&amp;family=Space+Grotesk:wght@500;600&amp;display=swap');
        :root { --accent: 134 76 61; }
        .tail-container { font-family: 'Inter', system_ui, sans-serif; }
        .logo-font { font-family: 'Space Grotesk', sans-serif; }
        table { border-collapse: collapse; }
        th, td { transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1); }
        th.sortable { cursor: pointer; user-select: none; }
        th.sortable:hover { background-color: #27272a; }
        .severity-critical { background-color: #7f1d1d; color: #fda4af; }
        .severity-high { background-color: #7c3aed; color: #c4b5fd; }
        .severity-medium { background-color: #854d0e; color: #fde047; }
        .severity-low { background-color: #14532d; color: #86efac; }
        tr:hover { background-color: #18181b !important; }
        .card { transition: transform 0.2s cubic-bezier(0.4, 0.0, 0.2, 1); }
        .card:hover { transform: translateY(-4px); }
        .tail-text { color: #a1a1aa; }
    </style>
</head>
<body class="bg-zinc-950 text-zinc-200 tail-container">
    <div class="max-w-screen-2xl mx-auto">
        <div class="bg-black border-b border-zinc-800 px-8 py-6 flex items-center justify-between">
            <div class="flex items-center gap-x-3">
                <div class="w-9 h-9 bg-emerald-600 rounded-2xl flex items-center justify-center text-white text-2xl font-bold logo-font">PF</div>
                <div>
                    <h1 class="text-3xl font-semibold tracking-tighter logo-font text-white">PHP Fossil</h1>
                    <p class="text-emerald-400 text-sm -mt-1">LEGACY PHP SECURITY REPORT</p>
                </div>
            </div>
            <div class="text-right">
                <div class="text-xs text-zinc-500">GENERATED ON</div>
                <div class="text-sm font-mono text-zinc-400">{{ generated_at }}</div>
            </div>
        </div>

        <div class="px-8 py-8">
            <div class="grid grid-cols-2 lg:grid-cols-4 gap-6">
                <div class="card bg-zinc-900 border border-zinc-700 rounded-3xl p-6">
                    <div class="flex justify-between items-start">
                        <div>
                            <p class="text-emerald-400 text-xs font-medium tracking-widest">TARGETS SCANNED</p>
                            <p class="text-6xl font-semibold text-white mt-3">{{ total_targets }}</p>
                        </div>
                        <i class="fa-solid fa-globe text-5xl text-emerald-900/70"></i>
                    </div>
                </div>
                <div class="card bg-zinc-900 border border-zinc-700 rounded-3xl p-6">
                    <div class="flex justify-between items-start">
                        <div>
                            <p class="text-rose-400 text-xs font-medium tracking-widest">VULNERABLE SITES</p>
                            <p class="text-6xl font-semibold text-white mt-3">{{ vulnerable_count }}</p>
                        </div>
                        <i class="fa-solid fa-bug text-5xl text-rose-900/70"></i>
                    </div>
                </div>
                <div class="card bg-zinc-900 border border-zinc-700 rounded-3xl p-6">
                    <div class="flex justify-between items-start">
                        <div>
                            <p class="text-amber-400 text-xs font-medium tracking-widest">TOTAL VULNERABILITIES</p>
                            <p class="text-6xl font-semibold text-white mt-3">{{ total_vulns }}</p>
                        </div>
                        <i class="fa-solid fa-shield-halved text-5xl text-amber-900/70"></i>
                    </div>
                </div>
                <div class="card bg-zinc-900 border border-zinc-700 rounded-3xl p-6">
                    <div class="flex justify-between items-start">
                        <div>
                            <p class="text-sky-400 text-xs font-medium tracking-widest">AVERAGE RISK</p>
                            <p class="text-6xl font-semibold text-white mt-3">{{ avg_risk }}</p>
                        </div>
                        <i class="fa-solid fa-chart-line text-5xl text-sky-900/70"></i>
                    </div>
                </div>
            </div>

            <div class="mt-12">
                <div class="flex items-center justify-between">
                    <div>
                        <h2 class="text-2xl font-semibold flex items-center gap-x-3">
                            <span class="text-emerald-500">Vulnerability Inventory</span>
                        </h2>
                        <p class="text-zinc-400">Click any column header to sort • Live filtering supported</p>
                    </div>
                    <div class="flex items-center gap-x-4">
                        <div class="relative w-80">
                            <input id="filter-input"
                                   onkeyup="filterTable()"
                                   type="text"
                                   placeholder="Filter URL, CVE or title..."
                                   class="w-full bg-zinc-900 border border-zinc-700 focus:border-emerald-500 rounded-2xl px-5 py-3 outline-none text-sm">
                        </div>
                        <button onclick="exportCSV()"
                                class="flex items-center gap-x-2 px-6 py-3 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 rounded-2xl text-sm font-medium transition-colors">
                            <i class="fa-solid fa-download"></i>
                            <span>Export CSV</span>
                        </button>
                    </div>
                </div>

                <div class="mt-6 bg-zinc-900 border border-zinc-700 rounded-3xl overflow-hidden shadow-2xl">
                    <table id="vuln-table" class="w-full text-sm">
                        <thead class="bg-zinc-950 border-b border-zinc-700">
                            <tr>
                                <th onclick="sortTable(0)" class="sortable px-7 py-5 text-left font-medium text-zinc-400 hover:text-emerald-300">TARGET</th>
                                <th onclick="sortTable(1)" class="sortable px-7 py-5 text-left font-medium text-zinc-400 hover:text-emerald-300">PHP VERSION</th>
                                <th onclick="sortTable(2)" class="sortable px-7 py-5 text-left font-medium text-zinc-400 hover:text-emerald-300">CVE</th>
                                <th onclick="sortTable(3)" class="sortable px-7 py-5 text-left font-medium text-zinc-400 hover:text-emerald-300">SEVERITY</th>
                                <th onclick="sortTable(4)" class="sortable px-7 py-5 text-left font-medium text-zinc-400 hover:text-emerald-300">TITLE</th>
                                <th onclick="sortTable(5)" class="sortable px-7 py-5 text-right font-medium text-zinc-400 hover:text-emerald-300">RISK</th>
                                <th onclick="sortTable(6)" class="sortable px-7 py-5 text-left font-medium text-zinc-400 hover:text-emerald-300">FIXED IN</th>
                                <th class="px-7 py-5 text-left font-medium text-zinc-400">REFERENCE</th>
                            </tr>
                        </thead>
                        <tbody id="table-body" class="divide-y divide-zinc-800 text-zinc-300">
                        </tbody>
                    </table>
                </div>
            </div>

            <div class="mt-16 border-t border-zinc-800 pt-8 text-center text-xs text-zinc-500 flex flex-col md:flex-row items-center justify-center gap-y-2 gap-x-8">
                <div>Generated by <span class="font-mono text-emerald-400">PHP Fossil v0.1.0</span></div>
                <div class="hidden md:block">•</div>
                <div>Dark theme • Client-side sortable table • Zero external dependencies after generation</div>
                <div class="hidden md:block">•</div>
                <a href="https://github.com/ajendras/php-fossil" target="_blank" class="hover:text-zinc-300 flex items-center gap-x-1">
                    <i class="fa-brands fa-github"></i> GitHub
                </a>
            </div>
        </div>
    </div>

    <script>
        const vulnerabilities = {{ vulnerabilities_json }};
        let currentSort = {col: -1, dir: 1};

        function getSeverityBadge(severity) {
            const s = (severity || 'low').toLowerCase();
            if (s === 'critical') return 'severity-critical px-3 py-1 rounded-xl text-[10px] font-bold';
            if (s === 'high') return 'severity-high px-3 py-1 rounded-xl text-[10px] font-bold';
            if (s === 'medium') return 'severity-medium px-3 py-1 rounded-xl text-[10px] font-bold';
            return 'severity-low px-3 py-1 rounded-xl text-[10px] font-bold';
        }

        function renderTable(data) {
            const tbody = document.getElementById('table-body');
            tbody.innerHTML = '';
            if (!data.length) {
                tbody.innerHTML = `<tr><td colspan="8" class="px-8 py-16 text-center text-zinc-500 italic">No matching records</td></tr>`;
                return;
            }
            data.forEach(row => {
                const tr = document.createElement('tr');
                tr.className = 'group hover:bg-zinc-800 transition-colors';
                tr.innerHTML = `
                    <td class="px-7 py-4 font-medium text-emerald-300 group-hover:text-white">${row.url}</td>
                    <td class="px-7 py-4 font-mono text-zinc-400">${row.php_version}</td>
                    <td class="px-7 py-4 font-mono text-amber-300">${row.cve}</td>
                    <td class="px-7 py-4"><span class="${getSeverityBadge(row.severity)}">${row.severity.toUpperCase()}</span></td>
                    <td class="px-7 py-4 max-w-xs truncate">${row.title}</td>
                    <td class="px-7 py-4 text-right font-semibold tabular-nums ${row.risk_score > 65 ? 'text-rose-400' : row.risk_score > 35 ? 'text-amber-300' : 'text-emerald-400'}">${row.risk_score}</td>
                    <td class="px-7 py-4 font-mono text-zinc-400">${row.fixed_in}</td>
                    <td class="px-7 py-4">
                        ${row.reference ? `<a href="${row.reference}" target="_blank" class="inline-flex items-center text-sky-400 hover:text-sky-300 text-xs gap-x-1"><i class="fa-solid fa-arrow-up-right-from-square text-[10px]"></i>REF</a>` : '<span class="text-zinc-600">—</span>'}
                    </td>
                `;
                tbody.append(tr);
            });
        }

        function sortTable(colIndex) {
            const keys = ['url','php_version','cve','severity','title','risk_score','fixed_in','reference'];
            const key = keys[colIndex];

            if (currentSort.col === colIndex) {
                currentSort.dir = -currentSort.dir;
            } else {
                currentSort.col = colIndex;
                currentSort.dir = 1;
            }

            const sortedData = [...vulnerabilities].sort((a, b) => {
                let va = a[key], vb = b[key];
                if (key === 'risk_score') return (parseFloat(va) - parseFloat(vb)) * currentSort.dir;
                if (typeof va === 'string') va = va.toLowerCase();
                if (typeof vb === 'string') vb = vb.toLowerCase();
                if (va < vb) return -1 * currentSort.dir;
                if (va > vb) return 1 * currentSort.dir;
                return 0;
            });

            renderTable(sortedData);

            document.querySelectorAll('th').forEach((th, idx) => {
                th.style.color = (idx === colIndex) ? '#34d399' : '';
                const arrow = currentSort.dir > 0 ? ' ▲' : ' ▼';
                th.textContent = th.textContent.replace(/[▲▼]/, '');
                if (idx === colIndex) th.textContent += arrow;
            });
        }

        function filterTable() {
            const term = document.getElementById('filter-input').value.toLowerCase().trim();
            if (!term) {
                renderTable(vulnerabilities);
                return;
            }
            const filtered = vulnerabilities.filter(r =>
                (r.url && r.url.toLowerCase().includes(term)) ||
                (r.cve && r.cve.toLowerCase().includes(term)) ||
                (r.title && r.title.toLowerCase().includes(term)) ||
                (r.php_version && r.php_version.toLowerCase().includes(term))
            );
            renderTable(filtered);
        }

        function exportCSV() {
            const header = ['Target','PHP Version','CVE','Severity','Title','Risk Score','Fixed In','Reference'];
            let csv = header.join(',') + '\\n';
            vulnerabilities.forEach(row => {
                const escapedTitle = (row.title || '').replace(/"/g, '""');
                const line = [
                    `"${row.url}"`,
                    row.php_version,
                    row.cve,
                    row.severity,
                    `"${escapedTitle}"`,
                    row.risk_score,
                    row.fixed_in,
                    row.reference
                ].join(',');
                csv += line + '\\n';
            });
            const blob = new Blob([csv], {type: 'text/csv'});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'phpfossil-vulnerabilities.csv';
            a.click();
            URL.revokeObjectURL(url);
        }

        window.onload = () => {
            renderTable(vulnerabilities);
            const ths = document.querySelectorAll('th');
            ths.forEach((th, i) => th.classList.add('sortable'));
        };
    </script>
</body>
</html>
"""


def _generate_html_report(results: List[ScanResult]) -> str:
    """Build the dark-mode interactive HTML report using the embedded Jinja template."""
    rows = _prepare_vulnerability_rows(results)
    total_targets = len(results)
    vulnerable_count = sum(1 for r in results if r.is_vulnerable())
    total_vulns = len(rows)
    avg_risk = round(sum(r.risk_score for r in results) / total_targets, 1) if total_targets else 0.0
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    template = Template(HTML_TEMPLATE)
    return template.render(
        total_targets=total_targets,
        vulnerable_count=vulnerable_count,
        total_vulns=total_vulns,
        avg_risk=avg_risk,
        generated_at=generated_at,
        vulnerabilities_json=json.dumps(rows),
    )


def _generate_csv_report(results: List[ScanResult], output_path: Optional[Path] = None) -> str:
    """Return CSV string (and write file if path given). One row per vulnerability."""
    rows = _prepare_vulnerability_rows(results)
    if not rows:
        return ""

    fieldnames = [
        "url",
        "php_version",
        "cve",
        "severity",
        "title",
        "risk_score",
        "fixed_in",
        "reference",
        "nuclei_count",
        "has_schema",
    ]

    if output_path:
        with output_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        console.print(f"[green]CSV written to {output_path}[/]")

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)
    return buf.getvalue()


__all__ = ["generate_report"]
