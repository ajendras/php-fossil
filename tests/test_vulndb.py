"""Tests for VulnDB lookup accuracy, EOL calculations and CVE mapping.

Verifies embedded vulnerability data, version prefix matching,
severity validation, EOL status for legacy PHP branches, and
integration with ScanResult objects.
"""

import json
from datetime import date
from typing import Dict, List

import pytest

from phpfossil.models import Vulnerability
from phpfossil.scanner import _get_embedded_vulndb, get_vulns_for_version
from phpfossil.vulndb import VulnDB  # type: ignore[attr-defined]  # module under construction


def test_vulndb_embedded_data_structure() -> None:
    """Verify the embedded JSON data can be loaded and contains expected CVEs."""
    db = _get_embedded_vulndb()
    assert isinstance(db, dict)
    assert "5." in db
    assert "7.0" in db
    assert "8.0" in db

    for prefix, vulns in db.items():
        assert isinstance(vulns, list)
        for v in vulns:
            assert isinstance(v, Vulnerability)
            assert v.cve.startswith("CVE-")
            assert v.severity in ("critical", "high", "medium", "low")
            assert v.title
            assert v.description


def test_get_vulns_for_version_accuracy() -> None:
    """Test version prefix matching returns correct CVE lists."""
    vulns_5 = get_vulns_for_version("5.6.38")
    assert len(vulns_5) >= 2
    cve_ids = {v.cve for v in vulns_5}
    assert "CVE-2012-1823" in cve_ids
    assert "CVE-2018-19518" in cve_ids

    vulns_7 = get_vulns_for_version("7.0.33")
    assert len(vulns_7) >= 1
    assert any(v.cve == "CVE-2019-11043" for v in vulns_7)

    vulns_8 = get_vulns_for_version("8.0.5")
    assert len(vulns_8) >= 1
    assert any("CVE-2021-21702" in v.cve for v in vulns_8)

    # Legacy fallback
    vulns_legacy = get_vulns_for_version("4.3.11")
    assert len(vulns_legacy) >= 2

    # No vulns for modern versions
    assert len(get_vulns_for_version("8.3.0")) == 0


def test_vulndb_load_method() -> None:
    """Test VulnDB.load() class method returns expected dictionary structure."""
    db = VulnDB.load()
    assert isinstance(db, dict)
    assert len(db) > 3  # at least the prefixes in the embedded JSON

    for version_prefix, entries in db.items():
        assert isinstance(entries, list)
        if entries:
            assert isinstance(entries[0], Vulnerability)


def test_eol_date_calculations() -> None:
    """Test EOL status for major PHP branches using known dates."""
    # These dates are well-known in the PHP community
    assert VulnDB.is_eol("5.6.40") is True   # EOL 2018-12-31
    assert VulnDB.is_eol("7.0.33") is True   # EOL 2018-12-03
    assert VulnDB.is_eol("7.1.33") is True   # EOL 2019-12-01
    assert VulnDB.is_eol("7.4.33") is True   # EOL 2022-11-28
    assert VulnDB.is_eol("8.0.28") is True   # EOL 2023-11-26
    assert VulnDB.is_eol("8.1.0") is False   # Still supported until 2024
    assert VulnDB.is_eol("8.2.0") is False


def test_vuln_severity_validation() -> None:
    """Test Pydantic severity validator rejects invalid values."""
    with pytest.raises(ValueError, match="severity must be one of"):
        Vulnerability(
            cve="CVE-9999-9999",
            title="Test",
            severity="INVALID",
            description="Bad severity",
        )


@pytest.mark.parametrize(
    "version,expected_min_count",
    [
        ("5.3.29", 2),
        ("5.6.0", 3),
        ("7.0", 1),
        ("7.4", 0),   # no specific entry, falls back
        ("8.0.11", 1),
    ],
)
def test_cve_mapping_parametrized(version: str, expected_min_count: int) -> None:
    """Parametrized test for different version branches."""
    vulns = get_vulns_for_version(version)
    assert len(vulns) >= expected_min_count
    for vuln in vulns:
        assert vuln.fixed_in is not None
        assert vuln.reference.startswith("http")


def test_vulndb_integration_with_scanresult() -> None:
    """Test that ScanResult can be populated from VulnDB results."""
    result = ScanResult(url="https://test.com", php_version="5.6.20")
    result.vulns = get_vulns_for_version(result.php_version)

    assert result.is_vulnerable() is True
    assert len(result.vulns) > 0
    assert result.vulns[0].severity == "critical"


def test_vulndb_json_roundtrip() -> None:
    """Ensure Vulnerability models can be serialized to JSON and back."""
    vulns = get_vulns_for_version("5.6.40")
    data = [v.model_dump(mode="json") for v in vulns]

    reloaded = [Vulnerability.model_validate(item) for item in data]
    assert len(reloaded) == len(vulns)
    assert reloaded[0].cve == vulns[0].cve
