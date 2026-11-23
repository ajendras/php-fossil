"""Tests for Nuclei integration and models."""

import json
from unittest.mock import patch, MagicMock

import pytest

from phpfossil.models import NucleiFinding
from phpfossil.nuclei import validate_with_nuclei


def test_nuclei_finding_model():
    """Test Pydantic validation with all required fields (template is mandatory)."""
    data = {
        "template": "test-template",
        "info": {
            "name": "Test Template",
            "severity": "high",
            "description": "Test description for validation",
        },
        "host": "https://example.com",
        "matched-at": "https://example.com/index.php",
    }
    finding = NucleiFinding.model_validate(data)
    assert finding.template == "test-template"
    assert finding.severity == "high"
    assert finding.name == "Test Template"


def test_validate_with_nuclei():
    """Mock subprocess so test passes in CI without nuclei binary installed."""
    mock_output = json.dumps(
        [
            {
                "template": "php/legacy-version",
                "info": {
                    "name": "PHP Legacy Version",
                    "severity": "high",
                    "description": "Outdated PHP detected",
                },
                "host": "http://example.com",
                "matched-at": "http://example.com",
            }
        ]
    )
    mock_result = MagicMock()
    mock_result.stdout = mock_output
    mock_result.returncode = 0

    with patch("subprocess.run", return_value=mock_result) as mock_run:
        findings = validate_with_nuclei("http://example.com", templates_dir=None)
        assert len(findings) == 1
        assert findings[0].template == "php/legacy-version"
        mock_run.assert_called_once()


def test_nuclei_validator_class():
    """Basic test for the validator class."""
    validator = NucleiValidator()
    with patch("phpfossil.nuclei.validate_with_nuclei", return_value=[]):
        findings = validator.validate("https://example.com")
        assert findings == []
