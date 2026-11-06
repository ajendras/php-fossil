"""Tests for the vulnerability database."""

from phpfossil.models import Vulnerability
from phpfossil.vulndb import get_vulns_for_version, load


def test_get_vulns_for_version_known() -> None:
    """Test that known legacy versions return CVEs with correct severity."""
    vulns = get_vulns_for_version("5.6.20")
    assert len(vulns) >= 2
    cves = {v.cve for v in vulns}
    assert "CVE-2012-1823" in cves
    assert any(v.severity == "critical" for v in vulns)
    assert any(v.fixed_in for v in vulns)


def test_get_vulns_for_version_eol_fallback() -> None:
    """Test fallback for very old versions maps to the 5.x database."""
    vulns = get_vulns_for_version("4.3.10")
    assert len(vulns) > 0
    vulns = get_vulns_for_version("7.2.34")
    assert len(vulns) > 0


def test_get_vulns_for_version_modern() -> None:
    """Modern supported versions return empty list."""
    assert get_vulns_for_version("8.3.0") == []
    assert get_vulns_for_version("8.2.12") == []


def test_get_vulns_for_version_edge_cases() -> None:
    """Empty or invalid version returns empty list."""
    assert get_vulns_for_version("") == []
    assert get_vulns_for_version(None) == []  # type: ignore[arg-type]


def test_load_returns_all_vulns() -> None:
    """load() returns flattened list of all Vulnerability objects."""
    vulns = load()
    assert isinstance(vulns, list)
    assert len(vulns) >= 6
    assert all(isinstance(v, Vulnerability) for v in vulns)
    # ensure no duplicates by CVE
    cves = [v.cve for v in vulns]
    assert len(cves) == len(set(cves))


def test_vulnerability_model() -> None:
    """Direct model instantiation and validation."""
    v = Vulnerability(
        cve="CVE-2024-9999",
        title="Example Vuln",
        severity="high",
        description="Test description",
        fixed_in="8.0.0",
        reference="https://example.com",
    )
    assert v.severity == "high"
    assert v.cve == "CVE-2024-9999"
