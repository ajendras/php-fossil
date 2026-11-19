"""Tests for nuclei.py with mocked subprocess calls."""

import json
import subprocess
from unittest.mock import MagicMock

import pytest

from phpfossil.nuclei import validate_with_nuclei, NucleiValidator
from phpfossil.models import NucleiFinding


def test_validate_with_nuclei(monkeypatch):
    """Test successful nuclei execution and parsing."""
    mock_output = json.dumps(
        {
            "template": "php/CVE-2021-1234",
            "name": "PHP RCE",
            "severity": "critical",
            "matched-at": "http://legacy.example.com/phpinfo.php",
        }
    )

    def mock_run(*args, **kwargs):
        return MagicMock(stdout=mock_output, stderr="", returncode=0)

    monkeypatch.setattr("subprocess.run", mock_run)

    findings = validate_with_nuclei(
        targets=["http://example.com"],
        templates=["php-cve.yaml"],
        timeout=10,
    )
    assert len(findings) == 1
    assert findings[0].name == "PHP RCE"
    assert findings[0].severity == "critical"


def test_validate_with_nuclei_no_binary(monkeypatch):
    """Test graceful handling when nuclei command is not found."""

    def mock_run(*args, **kwargs):
        raise FileNotFoundError("Command 'nuclei' not found")

    monkeypatch.setattr("subprocess.run", mock_run)

    findings = validate_with_nuclei(["http://test.com"])
    assert findings == []


def test_nuclei_validator_is_available(monkeypatch):
    def mock_run(*args, **kwargs):
        return MagicMock()

    monkeypatch.setattr("subprocess.run", mock_run)
    assert NucleiValidator.is_available() is True


def test_nuclei_validator_not_available(monkeypatch):
    def mock_run(*args, **kwargs):
        raise FileNotFoundError()

    monkeypatch.setattr("subprocess.run", mock_run)
    assert NucleiValidator.is_available() is False


def test_nuclei_finding_model():
    """Test Pydantic model for nuclei findings."""
    finding = NucleiFinding(
        template="test-template",
        name="Test Template",
        severity="high",
        matched_at="https://test.com",
        description="Test description",
    )
    assert finding.severity == "high"
    assert finding.template == "test-template"
    # test validator fallback
    finding2 = NucleiFinding(
        template="t2", name="n2", severity="invalid"
    )
    assert finding2.severity == "medium"


def test_validate_with_nuclei_timeout(monkeypatch):
    def mock_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="nuclei", timeout=10)

    monkeypatch.setattr("subprocess.run", mock_run)
    findings = validate_with_nuclei(["http://slow.com"])
    assert findings == []
