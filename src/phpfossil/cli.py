"""Typer-based CLI for PHP Fossil with rich terminal output."""

from datetime import datetime, UTC
from pathlib import Path
from typing import Annotated, Optional

import asyncio
import json
import typer
from rich.console import Console
from rich.table import Table

from phpfossil import (
    __version__,
    generate_dorks,
    generate_report,
    get_historical_results,
    scan_targets,
    ScanResult,
    store_results,
    run_tui,
)

app = typer.Typer(
    name="php-fossil",
    help=f"PHP Fossil v{__version__} — Legacy PHP discovery & vulnerability assessment",
    rich_markup_mode="rich",
    pretty_exceptions_show_locals=False,
)
console = Console()


def version_callback(value: bool) -> None:
    if value:
        console.print(f"[bold]php-fossil[/bold] [cyan]v{__version__}[/]")
        console.print("Targeted legacy PHP fingerprinting and CVE mapping toolkit.")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option("--version", callback=version_callback, is_eager=True),
    ] = False,
) -> None:
    """PHP Fossil CLI entrypoint."""


@app.command("dorks")
def cmd_dorks(
    version: Annotated[str, typer.Option("--version", "-v", prompt="Target PHP version (e.g. 7.4)")],
    count: Annotated[int, typer.Option("--count", "-c", min=1, max=50)] = 15,
    save: Annotated[Optional[Path], typer.Option("--save", "-s", help="Write dorks to file")] = None,
) -> None:
    """Generate Google, Bing and Shodan dorks for a specific PHP version."""
    try:
        dorks = generate_dorks(version, count)
        console.print(
            f"\n[bold green]Generated {len(dorks)} search dorks for PHP {version}:[/]\n"
        )
        for i, dork in enumerate(dorks, 1):
            console.print(f"  {i:2d}. [cyan]{dork}[/]")

        if save:
            save.write_text("\n".join(dorks), encoding="utf-8")
            console.print(f"\n[green]Saved dorks to [bold]{save}[/][/]")
    except ValueError as exc:
        console.print(f"[red]Error:[/] {exc}")
        raise typer.Exit(1) from exc


@app.command()
def scan(
    targets: Annotated[list[str], typer.Option("-t", "--target", help="Target URL")] = [],
    file: Annotated[
        Optional[Path],
        typer.Option("-f", "--file", exists=True, dir_okay=False, help="File with one URL per line"),
    ] = None,
    concurrency: Annotated[int, typer.Option("--concurrency", "-c", min=5, max=100)] = 20,
    timeout: Annotated[int, typer.Option("--timeout", min=5, max=60)] = 12,
    nuclei: Annotated[bool, typer.Option("--nuclei", help="Enable Nuclei for deeper exploit validation")] = False,
    ollama: Annotated[bool, typer.Option("--ollama", help="Enable Local LLM (Ollama) summaries of discovered issues")] = False,
    community: Annotated[bool, typer.Option("--community", help="Enable community fingerprint repository loader")] = False,
    output: Annotated[Path, typer.Option("--output", "-o")] = Path("phpfossil-results.json"),
    html: Annotated[Optional[Path], typer.Option("--html", help="Path for HTML report")] = None,
    csv: Annotated[
        Optional[Path],
        typer.Option("--csv", help="Path for CSV export compatible with bug-bounty platforms"),
    ] = None,
) -> None:
    """Scan targets for legacy PHP versions, exposed files and known CVEs."""
    if file and file.exists():
        lines = file.read_text(encoding="utf-8").splitlines()
        targets.extend([line.strip() for line in lines if line.strip() and not line.strip().startswith("#")])

    if not targets:
        console.print("[yellow]No targets supplied, using demonstration targets...[/]")
        targets = ["https://httpbin.org", "http://example.com"]

    config = {
        "max_concurrency": concurrency,
        "timeout": timeout,
        "use_nuclei": nuclei,
        "use_ollama": ollama,
        "use_community_fingerprints": community,
    }

    console.print(f"[bold blue]Scanning {len(targets)} target(s) (concurrency={concurrency}, nuclei={nuclei}, ollama={ollama}, community={community})...[/]")
    # Run the async scanner within the CLI's synchronous context
    results = asyncio.run(scan_targets(targets, config=config))

    # Persist raw results
    json_data = [r.model_dump(mode="json") for r in results]
    output.write_text(json.dumps(json_data, indent=2, default=str), encoding="utf-8")
    console.print(f"[green]JSON results saved to {output}[/]")

    # Persist to SQLite history store (automatic)
    store_results(results)
    console.print("[green]Scan history persisted to SQLite (~/.phpfossil/history.db)[/]")

    # Terminal summary
    generate_report(results, output_format="terminal")

    if html:
        generate_report(results, output_format="html", output_path=html)
    if csv:
        generate_report(results, output_format="csv", output_path=csv)

    console.print("\n[bold green]Scan completed.[/]")


@app.command()
def report(
    input_file: Annotated[Path, typer.Argument(help="JSON file produced by scan")],
    html: Annotated[Optional[Path], typer.Option("--html", "-h")] = None,
    csv: Annotated[
        Optional[Path],
        typer.Option("--csv", help="Path for CSV export compatible with bug-bounty platforms"),
    ] = None,
) -> None:
    """Re-generate reports from a previous JSON result file."""
    if not input_file.exists():
        console.print(f"[red]File {input_file} does not exist.[/]")
        raise typer.Exit(1)

    data = json.loads(input_file.read_text(encoding="utf-8"))
    results = [ScanResult.model_validate(item) for item in data]

    generate_report(results, output_format="terminal")
    if html:
        generate_report(results, output_format="html", output_path=html)
    if csv:
        generate_report(results, output_format="csv", output_path=csv)


@app.command("history")
def cmd_history(
    limit: Annotated[int, typer.Option("--limit", "-l", min=1, max=500)] = 30,
    url: Annotated[
        Optional[str],
        typer.Option("--url", "-u", help="Filter by URL substring"),
    ] = None,
    db_file: Annotated[
        Optional[Path],
        typer.Option("--db", help="Custom path to history database"),
    ] = None,
) -> None:
    """Display historical scan results from the persistent SQLite store."""
    try:
        results = get_historical_results(
            limit=limit, db_path=db_file, url_filter=url
        )
        if not results:
            console.print("[yellow]No historical scan results found.[/]")
            console.print("Run a scan first with: [bold]php-fossil scan ...[/]")
            return

        console.print(f"[bold green]Showing {len(results)} historical scan(s):[/]\n")
        generate_report(results, output_format="terminal")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Error accessing history: {exc}[/]")
        raise typer.Exit(1) from exc


@app.command("list")
def cmd_list(
    action: Annotated[str, typer.Argument(help="show | add | clear")],
    url: Annotated[Optional[str], typer.Option("--url")] = None,
    php_version: Annotated[Optional[str], typer.Option("--version", "-v")] = None,
    list_file: Annotated[Path, typer.Option("--file", "-f")] = Path("phpfossil-list.json"),
) -> None:
    """Manage a local prioritized list of at-risk domains."""
    if not list_file.parent.exists():
        list_file.mkdir(parents=True, exist_ok=True)

    if list_file.exists():
        try:
            tracked = json.loads(list_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            tracked = []
    else:
        tracked = []

    if action == "show":
        if not tracked:
            console.print("[dim]No entries in the at-risk list yet.[/]")
            return

        table = Table(title="PHP Fossil — At-Risk List")
        table.add_column("URL")
        table.add_column("PHP Version")
        table.add_column("Vulns")
        table.add_column("Added")

        for entry in tracked:
            table.add_row(
                entry.get("url", ""),
                entry.get("php_version", "unknown"),
                str(entry.get("vuln_count", 0)),
                entry.get("added", "")[:10],
            )
        console.print(table)

    elif action == "add":
        if not url:
            url = typer.prompt("URL to add")
        if not php_version:
            php_version = typer.prompt("PHP version", default="7.4")

        tracked.append(
            {
                "url": url,
                "php_version": php_version,
                "vuln_count": 3,
                "added": datetime.now(UTC).isoformat(),
            }
        )
        list_file.write_text(json.dumps(tracked, indent=2, default=str), encoding="utf-8")
        console.print(f"[green]Added [bold]{url}[/] to the at-risk list.[/]")

    elif action == "clear":
        if typer.confirm("Clear the entire at-risk list?"):
            list_file.write_text("[]", encoding="utf-8")
            console.print("[yellow]List cleared.[/]")
    else:
        console.print("[red]Unknown action. Use: show, add, or clear.[/]")


@app.command("tui")
def cmd_tui() -> None:
    """Launch interactive Textual TUI for live scanning with real-time updates."""
    console.print("[bold cyan]Starting PHP Fossil Interactive TUI...[/]")
    console.print("[dim]Use s to start scan, r to reset, d for report, q to quit.[/]")
    run_tui()


if __name__ == "__main__":
    app()
