"""Tests for nuclei integration."""

import pytest
from unittest.mock import patch, MagicMock
from phpfossil import NucleiFinding, validate_with_nuclei, NucleiValidator


def test_nuclei_finding_model():
    finding = NucleiFinding(
        template="test-template",
        name="Test Finding",
        severity="invalid",
        description="test desc",
    )
    assert finding.severity == "medium"
    finding2 = NucleiFinding(
        template="test2",
        name="Test2",
        severity="high",
    )
    assert finding2.severity == "high"


def test_validate_with_nuclei():
    with patch("phpfossil.nuclei.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            stdout='{"template":"t1","name":"n1","severity":"medium"}',
            stderr="",
        )
        findings = validate_with_nuclei(["https://example.com"])
        assert isinstance(findings, list)


def test_nuclei_validator_class():
    validator = NucleiValidator(templates=["cves/php"])
    assert validator.templates == ["cves/php"]
    with patch("phpfossil.nuclei.validate_with_nuclei") as mock_v:
        mock_v.return_value = []
        assert validator.validate(["http://test.com"]) == []
    assert NucleiValidator.is_available() is False
