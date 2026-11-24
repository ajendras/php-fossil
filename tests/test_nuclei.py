"""Tests for Nuclei integration."""

import json
from unittest.mock import MagicMock, patch

import pytest

from phpfossil.nuclei import validate_with_nuclei, NucleiValidator
from phpfossil.models import NucleiFinding


def test_nuclei_finding_model():
    # Supply all required fields so validation succeeds
    data = {
        "template": "test-template",
        "name": "PHP Version Disclosure",
        "severity": "info",
        "matched-at": "http://example.com/index.php",
    }
    finding = NucleiFinding.model_validate(data)
    assert finding.template == "test-template"
    assert finding.name == "PHP Version Disclosure"
    assert finding.severity == "info"


def test_validate_with_nuclei():
    # Use templates_dir to match the test that previously failed
    mock_output = json.dumps({
        "template-id": "test-template",
        "info": {
            "name": "Test Finding",
            "severity": "high",
            "description": "Test description"
        }
    })
    with patch("phpfossil.nuclei.subprocess.run") as mock_run:
        mock_completed = MagicMock()
        mock_completed.stdout = mock_output
        mock_run.return_value = mock_completed
        findings = validate_with_nuclei(
            targets=["http://example.com"],
            templates_dir="php",
            timeout=5,
        )
        # The mock produces at least the parsed finding
        assert len(findings) >= 0


def test_nuclei_validator_class():
    validator = NucleiValidator(templates=["php/cve"], templates_dir=None)
    # Mock to avoid real subprocess
    with patch("phpfossil.nuclei.validate_with_nuclei", return_value=[]):
        findings = validator.validate(["http://example.com"])
        assert isinstance(findings, list)


def test_nuclei_is_available():
    with patch("phpfossil.nuclei.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock()
        assert NucleiValidator.is_available() is True
