"""Tests for Nuclei integration."""

import json
from unittest.mock import patch, MagicMock

import pytest

from phpfossil.nuclei import validate_with_nuclei, NucleiValidator
from phpfossil.models import ConfigSettings, NucleiFinding


def test_validate_with_nuclei_disabled():
    config = ConfigSettings(use_nuclei=False)
    findings = validate_with_nuclei("https://example.com", config)
    assert findings == []


@patch("phpfossil.nuclei.subprocess.run")
def test_validate_with_nuclei_custom_templates(mock_run):
    mock_result = MagicMock()
    mock_result.stdout = (
        json.dumps(
            {
                "template-id": "php/version-detect",
                "info": {
                    "name": "PHP Version Disclosure",
                    "severity": "info",
                    "description": "Detects PHP version",
                },
            }
        )
        + "\n"
    )
    mock_run.return_value = mock_result

    config = ConfigSettings(
        use_nuclei=True,
        nuclei_templates_dir="/custom/nuclei/templates",
        timeout=5,
    )
    findings = validate_with_nuclei("http://test.com", config)
    assert len(findings) == 1
    assert findings[0].name == "PHP Version Disclosure"
    assert findings[0].severity == "info"
    # Verify command included custom template directory
    args, _ = mock_run.call_args
    cmd = args[0]
    assert any(part == "-t" for part in cmd)
    assert any("custom/nuclei/templates" in str(part) for part in cmd)


@patch("phpfossil.nuclei.subprocess.run")
def test_validate_with_nuclei_default_templates(mock_run):
    mock_result = MagicMock()
    mock_result.stdout = ""
    mock_run.return_value = mock_result

    config = ConfigSettings(use_nuclei=True, nuclei_templates_dir=None)
    findings = validate_with_nuclei("http://test.com", config)
    assert findings == []
    # No -t flag when no custom dir
    args, _ = mock_run.call_args
    cmd = args[0]
    assert "-t" not in cmd


def test_nuclei_finding_model():
    data = {
        "template-id": "test-template",
        "info": {"name": "Test Template", "severity": "high", "description": "Test"},
    }
    finding = NucleiFinding.model_validate(data)
    assert finding.template == "test-template"
    assert finding.name == "Test Template"
    assert finding.severity == "high"


def test_validate_with_nuclei_no_binary():
    config = ConfigSettings(use_nuclei=True, nuclei_templates_dir=None)
    with patch("phpfossil.nuclei.subprocess.run", side_effect=FileNotFoundError):
        findings = validate_with_nuclei("http://example.com", config)
        assert findings == []


def test_nuclei_validator_class():
    config = ConfigSettings(use_nuclei=True)
    validator = NucleiValidator(config)
    with patch("phpfossil.nuclei.validate_with_nuclei") as mock_validate:
        mock_validate.return_value = []
        assert validator.scan("http://test.com") == []
        mock_validate.assert_called_once_with("http://test.com", config)
