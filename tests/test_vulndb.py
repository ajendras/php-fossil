"""Tests for the embedded vulnerability database."""

import pytest

from phpfossil.vulndb import get_vulns_for_version, is_version_eol, get_eol_date
from phpfossil.models import Vulnerability


def test_get_vulns_for_version_returns_list():
    vulns = get_vulns_for_version("7.4.33")
    assert isinstance(vulns, list)
    assert len(vulns) > 0
    assert all(isinstance(v, Vulnerability) for v in vulns)


def test_vuln_has_required_fields():
    vulns = get_vulns_for_version("8.1")
    v = vulns[0]
    assert v.cve.startswith("CVE-") or v.cve == "EOL"
    assert v.title
    assert v.severity in {"critical", "high", "medium", "low"}
    assert v.description


def test_new_php80_cves():
    vulns = get_vulns_for_version("8.0.30")
    cve_ids = {v.cve for v in vulns}
    assert "CVE-2021-21702" in cve_ids
    assert "CVE-2022-31628" in cve_ids
    assert "EOL" in cve_ids
    assert any("End-of-Life" in v.title for v in vulns)


def test_new_php81_cves():
    vulns = get_vulns_for_version("8.1.28")
    cve_ids = {v.cve for v in vulns}
    assert "CVE-2024-4577" in cve_ids
    assert "CVE-2023-0567" in cve_ids
    assert "EOL" in cve_ids


def test_php82_and_83_not_eol_yet():
    assert not is_version_eol("8.2")
    assert not is_version_eol("8.3.12")
    vulns82 = get_vulns_for_version("8.2.10")
    assert "EOL" not in {v.cve for v in vulns82}


def test_eol_functions():
    assert is_version_eol("8.0")
    assert is_version_eol("7.4.33")
    assert not is_version_eol("8.4")
    assert get_eol_date("8.0") == "2023-11-26"
    assert get_eol_date("7.4") == "2022-11-28"
    assert get_eol_date("8.3") is None


def test_severity_scoring_integration():
    vulns = get_vulns_for_version("8.0")
    eol_v = next((v for v in vulns if v.cve == "EOL"), None)
    assert eol_v is not None
    assert eol_v.severity == "critical"


def test_invalid_versions():
    assert get_vulns_for_version("") == []
    assert get_vulns_for_version("not-a-version") == []
    assert not is_version_eol("")
    assert get_eol_date("abc") is None


def test_total_cve_count():
    """Ensure we have the promised 30+ new CVEs across 8.x releases."""
    count = 0
    for v in ("8.0", "8.1", "8.2", "8.3"):
        vulns = get_vulns_for_version(v)
        count += len([v for v in vulns if not v.cve.startswith("EOL")])
    assert count >= 30
