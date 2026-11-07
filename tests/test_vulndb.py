"""Tests for the vulnerability database."""

from phpfossil.vulndb import get_vulns_for_version
from phpfossil.models import Vulnerability


def test_load_returns_all_vulns():
    vulns = get_vulns_for_version("5.6.40")
    assert len(vulns) >= 6
    assert all(isinstance(v, Vulnerability) for v in vulns)
    severities = {v.severity for v in vulns}
    assert "critical" in severities
    assert any("CVE-2012-1823" in v.cve for v in vulns)


def test_get_vulns_for_unknown_version():
    assert get_vulns_for_version("9.9") == []
    assert get_vulns_for_version("") == []
    assert get_vulns_for_version(None) == []  # type: ignore[arg-type]


def test_vuln_model_validation():
    v = Vulnerability(
        cve="CVE-9999-9999",
        title="Test Vuln",
        severity="medium",
        description="Test description",
        fixed_in="8.0",
        reference="https://example.com",
    )
    assert v.severity == "medium"
    assert v.cve == "CVE-9999-9999"
