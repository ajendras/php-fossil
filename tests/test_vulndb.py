"""Tests for the vulnerability database and EOL handling."""

import pytest

from phpfossil.models import Vulnerability
from phpfossil.vulndb import get_eol_date, get_vulns_for_version, is_version_eol


def test_get_vulns_for_eol_version_includes_eol_note():
    """EOL versions must always return at least one critical EOL entry.

    This test previously failed because EOL injection only occurred for
    versions that also had explicit CVE entries in the embedded DB.
    """
    eol_vulns = get_vulns_for_version("7.4.33")
    assert len(eol_vulns) > 0

    eol_entries = [
        v for v in eol_vulns if v.cve == "PHP-EOL" or "End-of-Life" in v.title
    ]
    assert len(eol_entries) == 1
    assert eol_entries[0].severity == "critical"
    assert "end-of-life" in eol_entries[0].description.lower()


def test_is_version_eol():
    """is_version_eol returns correct boolean for known EOL and supported releases."""
    assert is_version_eol("5.6.40") is True
    assert is_version_eol("7.4.33") is True
    assert is_version_eol("8.0.30") is True
    assert is_version_eol("8.3.12") is False
    assert is_version_eol("9.0.0") is False  # unknown = not EOL


def test_get_eol_date():
    """get_eol_date returns the expected date string or None."""
    assert get_eol_date("7.4.33") == "2022-11-28"
    assert get_eol_date("8.0.15") == "2023-11-26"
    assert get_eol_date("8.3.0") is None
    assert get_eol_date("invalid") is None
    assert get_eol_date("") is None


def test_get_vulns_for_supported_version():
    """Supported versions return CVE list (may be empty if not in embedded DB)."""
    vulns = get_vulns_for_version("8.3.12")
    assert isinstance(vulns, list)
    # We do not require >0 because the embedded DB is a representative subset


def test_get_vulns_for_version_with_cves():
    """Versions that have explicit CVEs in the DB return them."""
    vulns = get_vulns_for_version("8.1.0")
    assert len(vulns) >= 1
    assert any(v.cve.startswith("CVE-") for v in vulns)


def test_vulnerability_model_in_vulndb():
    """All returned items are valid Vulnerability instances."""
    for version in ("7.4.33", "8.1.0", "8.3.12"):
        vulns = get_vulns_for_version(version)
        for v in vulns:
            assert isinstance(v, Vulnerability)
            assert v.cve
            assert v.title
            assert v.severity


@pytest.mark.parametrize(
    "version,expected_count",
    [
        ("5.6.40", 1),  # at minimum the EOL note
        ("7.4.33", 2),  # EOL note + one CVE from embedded DB
        ("8.3.12", 0),  # supported, no embedded entry
    ],
)
def test_vuln_count_for_different_versions(version: str, expected_count: int):
    """Parametrized test covering EOL vs supported behaviour."""
    vulns = get_vulns_for_version(version)
    assert len(vulns) >= expected_count
