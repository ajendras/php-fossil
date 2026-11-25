"""Tests for CLI using Typer CliRunner."""

from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from phpfossil.cli import app
from phpfossil.models import ConfigSettings


runner = CliRunner(mix_stderr=False)


def test_scan_command_with_nuclei_templates():
    with patch("phpfossil.cli.scan_targets") as mock_scan, patch(
        "phpfossil.cli.store_results"
    ), patch("phpfossil.cli.generate_report"):
        mock_scan.return_value = []
        result = runner.invoke(
            app,
            [
                "scan",
                "--target",
                "https://example.com",
                "--nuclei",
                "--nuclei-templates",
                "/path/to/templates",
                "--community",
                "-v",
            ],
        )
        assert result.exit_code == 0
        assert "Scanning" in result.stdout
        # Verify config passed to scan_targets contains the new option
        call_kwargs = mock_scan.call_args.kwargs
        config = call_kwargs.get("config")
        assert isinstance(config, ConfigSettings)
        assert config.use_nuclei is True
        assert config.nuclei_templates_dir == Path("/path/to/templates")
        assert config.use_community_fingerprints is True


def test_config_settings_nuclei_templates():
    config = ConfigSettings(
        use_nuclei=True,
        nuclei_templates_dir=Path("/tmp/nuclei-custom"),
        verbose=1,
    )
    assert config.nuclei_templates_dir == Path("/tmp/nuclei-custom")
    assert config.use_nuclei is True


def test_scan_command_defaults():
    with patch("phpfossil.cli.scan_targets") as mock_scan, patch(
        "phpfossil.cli.store_results"
    ), patch("phpfossil.cli.generate_report"):
        mock_scan.return_value = []
        result = runner.invoke(app, ["scan", "--target", "https://httpbin.org"])
        assert result.exit_code == 0
        call_kwargs = mock_scan.call_args.kwargs
        config = call_kwargs.get("config")
        assert config.nuclei_templates_dir is None
