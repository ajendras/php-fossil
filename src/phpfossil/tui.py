"""Interactive Textual TUI for PHP Fossil live scanning.

Provides a rich terminal interface with real-time result updates,
configurable options, live log and data table. Uses the callback
mechanism in scan_targets to update UI as each target completes.
"""

from typing import Any

from textual import on
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal
from textual.message import Message
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    Log,
    Switch,
)

from .models import ScanResult
from .scanner import scan_targets
from .store import store_results


class ScanResultMessage(Message):
    """Message carrying a completed ScanResult for live UI update."""

    def __init__(self, result: ScanResult) -> None:
        self.result = result
        super().__init__()


class ScanComplete(Message):
    """Message sent when full scan completes."""

    pass


class PHPFossilTUI(App[None]):
    """Interactive TUI application for PHP Fossil."""

    TITLE = "PHP Fossil • Live Scanner"
    SUB_TITLE = "Legacy PHP discovery with real-time updates"

    CSS = """
    Screen {
        background: #0f172a;
    }
    Header {
        background: #1e2937;
        color: #67e8f9;
    }
    #controls {
        padding: 1 2;
        background: #1e2937;
        border: tall #334155;
        margin: 1 0;
    }
    DataTable {
        margin: 1 0;
        height: 1fr;
    }
    Log {
        height: 8;
        background: #020617;
        border: tall #334155;
    }
    .label {
        color: #a5f3fc;
        text-style: bold;
    }
    Button {
        background: #22d3ee;
        color: #0f172a;
    }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("s", "start_scan", "Start Scan"),
        ("r", "reset_table", "Reset"),
        ("d", "dump_report", "Dump Report"),
    ]

    def compose(self) -> ComposeResult:
        """Create the TUI layout."""
        yield Header()
        with Container(id="controls"):
            yield Label("Target URLs (comma-separated):", classes="label")
            yield Input(
                id="targets",
                value="https://httpbin.org, http://example.com",
                placeholder="https://target1.com, https://target2.com",
            )
            with Horizontal():
                yield Label("Nuclei:", classes="label")
                yield Switch(id="nuclei-switch", value=False)
                yield Label("Ollama:", classes="label")
                yield Switch(id="ollama-switch", value=False)
        yield Button("🚀 Start Live Scan", variant="primary", id="scan-button")
        yield DataTable(id="results-table")
        yield Log(id="live-log")
        yield Footer()

    def on_mount(self) -> None:
        """Setup the table and initial log."""
        table = self.query_one("#results-table", DataTable)
        table.add_columns(
            ("URL", 40),
            ("PHP Version", 12),
            ("Vulns", 8),
            ("Exposed", 8),
            ("Nuclei", 8),
            ("Status", 15),
        )
        log = self.query_one(Log)
        log.write("[bold green]PHP Fossil TUI initialized.[/]")
        log.write("Press [bold]S[/] to start a live scan or click the button.")
        log.write("Results will appear in the table as targets complete.")

    @on(Button.Pressed, "#scan-button")
    def start_button_pressed(self) -> None:
        self.action_start_scan()

    def action_start_scan(self) -> None:
        """Start the scanning process in background worker."""
        targets_str = self.query_one(Input).value.strip()
        if not targets_str:
            self.query_one(Log).write("[red]No targets provided.[/]")
            return

        targets = [t.strip() for t in targets_str.split(",") if t.strip()]
        nuclei = self.query_one("#nuclei-switch", Switch).value
        ollama = self.query_one("#ollama-switch", Switch).value

        config: dict[str, Any] = {
            "max_concurrency": 5,
            "timeout": 15,
            "use_nuclei": nuclei,
            "use_ollama": ollama,
        }

        log = self.query_one(Log)
        log.write(f"[blue]Starting live scan of {len(targets)} target(s)...[/]")
        log.write(f"Config: nuclei={nuclei}, ollama={ollama}")

        self.run_worker(
            self._run_live_scan(targets, config), name="live-scan", exclusive=True
        )

    async def _run_live_scan(self, targets: list[str], config: dict[str, Any]) -> None:
        """Worker task that runs the scan with live callback."""
        log = self.query_one(Log)

        def live_callback(result: ScanResult) -> None:
            self.post_message(ScanResultMessage(result))

        try:
            results = await scan_targets(
                targets=targets,
                config=config,
                callback=live_callback,
            )
            store_results(results)
            log.write("[bold green]Scan completed successfully![/]")
            self.post_message(ScanComplete())
        except Exception as exc:
            log.write(f"[red]Scan error: {exc}[/]")

    def on_scan_result_message(self, message: ScanResultMessage) -> None:
        """Handle live result and add to table."""
        self._add_to_table(message.result)

    def on_scan_complete(self, message: ScanComplete) -> None:
        """Optional final actions after scan."""
        self.query_one(Log).write(
            "[bold cyan]All scans finished. Use 'd' to generate full report.[/]"
        )

    def _add_to_table(self, result: ScanResult) -> None:
        """Add row in the results table."""
        table = self.query_one("#results-table", DataTable)
        vcount = len(result.vulns)
        ecount = len(result.exposed_files)
        ncount = len([f for f in result.nuclei_findings if f.template != "error"])

        if result.errors:
            status = "[red]Error[/]"
        elif vcount > 0:
            status = "[red]VULNERABLE[/]"
        else:
            status = "[green]OK[/]"

        version = result.php_version or "unknown"
        table.add_row(
            result.url,
            version,
            str(vcount),
            str(ecount),
            str(ncount),
            status,
            key=result.url,
        )
        self.query_one(Log).write(
            f"→ {result.url} | v{version} | {vcount} vulns | {ncount} nuclei"
        )

    def action_reset_table(self) -> None:
        """Clear the results table."""
        table = self.query_one(DataTable)
        table.clear()
        self.query_one(Log).write("[yellow]Table reset.[/]")

    def action_dump_report(self) -> None:
        """Generate a terminal report from current table data (simplified)."""
        log = self.query_one(Log)
        log.write("[bold]Generating summary report...[/]")
        log.write(
            "Full HTML report can be generated via CLI: php-fossil report <file.json> --html report.html"
        )
        log.write("[dim]Report features available in CLI.[/]")


def run_tui() -> None:
    """Entry point to launch the TUI."""
    app = PHPFossilTUI()
    app.run()


if __name__ == "__main__":
    run_tui()
