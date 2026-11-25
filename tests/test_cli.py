"""Tests for the PHP Fossil CLI using typer.CliRunner.

Covers all commands (dorks, passive, scan, report, history, list, tui, version)
and ConfigSettings validation from CLI arguments.

Uses extensive mocking to avoid real network, subprocess or TUI launches.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from phpfossil.cli import app
from phpfossil.models import DEFAULT_USER_AGENTS, ConfigSettings, ScanResult


runner = CliRunner()


def test_version():
    """Test --version flag."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "php-fossil" in result.stdout
    assert "0.1.0" in result.stdout


def test_dorks():
    """Test dorks command."""
    with patch("phpfossil.cli.generate_dorks") as mock_generate:
        mock_generate.return_value = ["intitle:phpinfo() PHP 7.4", "inurl:php=7.4"]
        result = runner.invoke(
            app, ["dorks", "--version", "7.4", "--count", "10"]
        )
        assert result.exit_code == 0
        assert "Generated 2 search dorks for PHP 7.4" in result.stdout
        mock_generate.assert_called_once_with("7.4", 10)


def test_dorks_save(tmp_path):
    """Test dorks command with --save option."""
    save_file = tmp_path / "dorks.txt"
    with patch("phpfossil.cli.generate_dorks") as mock_generate:
        mock_generate.return_value = ["dork1", "dork2"]
        result = runner.invoke(
            app,
            ["dorks", "--version", "8.0", "--count", "2", "--save", str(save_file)],
        )
        assert result.exit_code == 0
        assert "Saved dorks to" in result.stdout
        assert save_file.read_text().strip() == "dork1\ndork2"
        mock_generate.assert_called_once_with("8.0", 2)


def test_dorks_error():
    """Test error handling in dorks."""
    with patch("phpfossil.cli.generate_dorks") as mock_generate:
        mock_generate.side_effect = ValueError("Invalid version")
        result = runner.invoke(app, ["dorks", "--version", "99.99"])
        assert result.exit_code == 1
        assert "Error:" in result.stdout


@patch("phpfossil.cli.passive_discover")
def test_passive(mock_passive):
    """Test passive command without auto-scan."""
    mock_passive.return_value = ["https://example.com", "http://legacy.test"]
    result = runner.invoke(
        app, ["passive", "--query", 'php "7.4"', "--limit", "5"]
    )
    assert result.exit_code == 0
    assert "Discovered 2 unique target(s)" in result.stdout
    mock_passive.assert_called_once()


@patch("phpfossil.cli.passive_discover")
@patch("phpfossil.cli.scan_targets")
@patch("phpfossil.cli.store_results")
@patch("phpfossil.cli.generate_report")
def test_passive_with_scan(mock_report, mock_store, mock_scan, mock_passive):
    """Test passive with --scan."""
    mock_passive.return_value = ["https://test.com"]
    mock_scan.return_value = [MagicMock(spec=ScanResult)]
    result = runner.invoke(
        app, ["passive", "--query", 'php version', "--scan", "--shodan"]
    )
    assert result.exit_code == 0
    assert "Scanning discovered targets" in result.stdout
    assert "Scan history persisted to SQLite" in result.stdout
    mock_scan.assert_called_once()
    mock_store.assert_called_once()
    mock_report.assert_called()


@patch("phpfossil.cli.ConfigSettings")
@patch("phpfossil.cli.scan_targets")
@patch("phpfossil.cli.store_results")
@patch("phpfossil.cli.generate_report")
def test_scan_basic(mock_report, mock_store, mock_scan, mock_config):
    """Test scan command and config parsing."""
    mock_config.return_value = MagicMock(spec=ConfigSettings)
    mock_scan.return_value = []
    result = runner.invoke(
        app,
        [
            "scan",
            "--target",
            "https://example.com",
            "--concurrency",
            "10",
            "--timeout",
            "5",
            "--nuclei",
            "--community",
        ],
    )
    assert result.exit_code == 0
    assert "Scanning 1 target(s)" in result.stdout
    assert "JSON results saved to" in result.stdout
    mock_config.assert_called_once()
    call_kwargs = mock_config.call_args.kwargs
    assert call_kwargs["max_concurrency"] == 10
    assert call_kwargs["timeout"] == 5
    assert call_kwargs["use_nuclei"] is True
    assert call_kwargs["use_community_fingerprints"] is True
    mock_scan.assert_called_once()
    mock_store.assert_called_once()
    mock_report.assert_called()


def test_scan_with_file(tmp_path):
    """Test scan using input file."""
    targets_file = tmp_path / "targets.txt"
    targets_file.write_text("https://test1.com\nhttps://test2.com\n")
    with (
        patch("phpfossil.cli.scan_targets") as mock_scan,
        patch("phpfossil.cli.store_results"),
        patch("phpfossil.cli.generate_report"),
        patch("phpfossil.cli.ConfigSettings") as mock_config,
    ):
        mock_config.return_value = MagicMock(spec=ConfigSettings)
        mock_scan.return_value = []
        result = runner.invoke(
            app, ["scan", "-f", str(targets_file), "--html", "report.html"]
        )
        assert result.exit_code == 0
        assert "Scanning 2 target(s)" in result.stdout


def test_scan_config_validation_error():
    """Test that invalid config raises proper error."""
    # timeout=0 is invalid per Field(ge=1)
    result = runner.invoke(app, ["scan", "--timeout", "0"])
    assert result.exit_code == 1
    assert "Config validation error" in result.stdout


@patch("phpfossil.cli.get_historical_results")
@patch("phpfossil.cli.generate_report")
def test_history(mock_report, mock_history):
    """Test history command."""
    mock_result = MagicMock(spec=ScanResult)
    mock_result.url = "https://example.com"
    mock_history.return_value = [mock_result]
    result = runner.invoke(app, ["history", "--limit", "5"])
    assert result.exit_code == 0
    assert "Showing 1 historical scan(s)" in result.stdout
    mock_history.assert_called_with(limit=5, db_path=None, url_filter=None)
    mock_report.assert_called_once()


def test_history_empty():
    """Test history command with no results."""
    with patch("phpfossil.cli.get_historical_results") as mock_get:
        mock_get.return_value = []
        result = runner.invoke(app, ["history", "--limit", "10"])
        assert result.exit_code == 0
        assert "No historical scan results found" in result.stdout


def test_report():
    """Test report command from JSON."""
    sample_data = [
        {
            "url": "https://legacy.example.com",
            "php_version": "5.6.40",
            "risk_score": 85,
            "vulns": [],
            "nuclei_findings": [],
            "exposed_files": [],
            "detected_from": [],
            "scan_time": "2024-01-01T00:00:00",
        }
    ]
    with runner.isolated_filesystem():
        Path("results.json").write_text(json.dumps(sample_data), encoding="utf-8")
        with patch("phpfossil.cli.generate_report") as mock_report:
            result = runner.invoke(app, ["report", "results.json"])
            assert result.exit_code == 0
            mock_report.assert_called()
            result2 = runner.invoke(
                app, ["report", "results.json", "--html", "out.html"]
            )
            assert result2.exit_code == 0


def test_list_show():
    """Test list show command."""
    with runner.isolated_filesystem():
        data = [
            {
                "url": "https://old.site",
                "php_version": "7.2.34",
                "vuln_count": 5,
                "added": "2024-01-01",
            }
        ]
        Path("phpfossil-list.json").write_text(json.dumps(data))
        result = runner.invoke(app, ["list", "show"])
        assert result.exit_code == 0
        assert "At-Risk List" in result.stdout
        assert "old.site" in result.stdout


def test_list_add():
    """Test list add command."""
    with runner.isolated_filesystem():
        result = runner.invoke(
            app,
            ["list", "add", "--url", "https://new-legacy.com", "--version", "8.0"],
        )
        assert result.exit_code == 0
        assert "Added https://new-legacy.com to the at-risk list" in result.stdout
        assert Path("phpfossil-list.json").exists()


def test_list_clear():
    """Test list clear."""
    with runner.isolated_filesystem():
        Path("phpfossil-list.json").write_text("[]")
        result = runner.invoke(
            app, ["list", "clear"], input="y\n"
        )
        assert result.exit_code == 0
        assert "List cleared" in result.stdout


@patch("phpfossil.cli.run_tui")
def test_tui(mock_run_tui):
    """Test tui command."""
    mock_run_tui.return_value = None
    result = runner.invoke(app, ["tui"])
    assert result.exit_code == 0
    assert "Starting PHP Fossil Interactive TUI" in result.stdout
    mock_run_tui.assert_called_once()


def test_config_settings_defaults():
    """Direct test of ConfigSettings from CLI-like values."""
    config = ConfigSettings(
        max_concurrency=25,
        timeout=30,
        use_nuclei=True,
        use_ollama=False,
        verbose=2,
    )
    assert config.max_concurrency == 25
    assert config.timeout == 30
    assert config.use_nuclei is True
    assert len(config.user_agents) == len(DEFAULT_USER_AGENTS)
    assert config.verbose == 2
