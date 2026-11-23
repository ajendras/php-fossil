"""Tests for nuclei integration."""

from unittest.mock import MagicMock, patch

from phpfossil import NucleiFinding, NucleiValidator, validate_with_nuclei


@patch("phpfossil.nuclei.subprocess.run")
def test_validate_with_nuclei(mock_run: MagicMock) -> None:
    """Test that validate_with_nuclei correctly parses Nuclei JSON output."""
    mock_run.return_value.returncode = 0
    mock_run.return_value.stdout = (
        b'[{"template-id":"php-cve","info":{"severity":"critical","name":"PHP RCE"}}]'
    )
    findings = validate_with_nuclei("https://example.com")
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].name == "php-cve"


def test_nuclei_finding_model() -> None:
    """Test NucleiFinding pydantic model validation and attributes."""
    finding = NucleiFinding(
        name="test-template",
        severity="high",
        description="Test description",
        reference="https://example.com",
    )
    assert finding.name == "test-template"
    assert finding.severity == "high"
    assert finding.description == "Test description"


@patch("phpfossil.nuclei.NucleiValidator")
def test_nuclei_validator(mock_validator_class: MagicMock) -> None:
    """Test NucleiValidator class instantiation and interface."""
    mock_validator = MagicMock()
    mock_validator_class.return_value = mock_validator
    validator = NucleiValidator()
    assert validator is not None
    mock_validator.validate.assert_not_called()
