"""Tests for the embedded vulnerability database."""

from phpfossil.models import Vulnerability
from phpfossil.vulndb import get_eol_date, get_vulns_for_version, is_version_eol


def test_get_vulns_for_version():
    """Test that get_vulns_for_version returns list of Vulnerability objects."""
    vulns = get_vulns_for_version("7.4.33")
    assert isinstance(vulns, list)
    assert len(vulns) > 0
    assert all(isinstance(v, Vulnerability) for v in vulns)
    assert any("CVE" in v.cve for v in vulns)


def test_is_version_eol():
    """Test EOL detection for old and new PHP versions."""
    assert is_version_eol("5.6.40") is True
    assert is_version_eol("7.4.33") is True
    assert is_version_eol("8.2.0") is False
    assert is_version_eol("8.3.2") is False


def test_get_eol_date():
    """Test retrieval of EOL date string."""
    eol_date = get_eol_date("7.4")
    assert eol_date is not None
    assert isinstance(eol_date, str)
    assert "2022" in eol_date


def test_get_vulns_for_eol_version_includes_eol_note():
    """Test that EOL versions have a special vulnerability entry."""
    vulns = get_vulns_for_version("5.6.40")
    eol_vulns = [v for v in vulns if "EOL" in v.title or "end of life" in v.title.lower()]
    assert len(eol_vulns) > 0
