"""Tests for the scanner module."""

from datetime import datetime

import pytest

from phpfossil.fingerprinter import detect_php_version
from phpfossil.models import ScanResult, SchemaResult, Vulnerability
from phpfossil.scanner import scan_targets


def test_scan_result_serialization():
    """Test that ScanResult serializes/deserializes correctly (including 'schema' key)."""
    schema = SchemaResult(
        tables=["users", "posts"],
        columns={"users": ["id", "name"]},
        row_counts={"users": 1, "posts": 42},
    )
    vuln = Vulnerability(
        cve="CVE-2021-1234",
        title="Remote code execution",
        severity="critical",
        description="Test vulnerability description",
        fixed_in="8.1.0",
        reference="https://example.com/cve",
    )

    result = ScanResult(
        url="https://example.com",
        php_version="7.4.33",
        detected_from=["http-response", "headers"],
        vulns=[vuln],
        schema=schema,
        errors=[],
        scan_time=datetime(2026, 11, 7, 11, 5, 39, 905979),
    )

    # Verify JSON serialization uses "schema" key (no KeyError)
    data = result.model_dump(mode="json")
    assert "schema" in data
    assert data["schema"]["tables"] == ["users", "posts"]
    assert data["schema"]["columns"]["users"] == ["id", "name"]
    assert data["url"] == "https://example.com"
    assert data["php_version"] == "7.4.33"

    # Roundtrip validation
    reloaded = ScanResult.model_validate(data)
    assert reloaded.php_version == "7.4.33"
    assert reloaded.schema is not None
    assert reloaded.schema.tables == ["users", "posts"]
    assert reloaded.schema.row_counts["users"] == 1
    assert len(reloaded.vulns) == 1
    assert reloaded.vulns[0].cve == "CVE-2021-1234"


def test_scan_targets_with_mock(httpx_mock):
    """Test scanning with mocked responses. Version comes via phpinfo probe."""
    # Main page has no version info
    httpx_mock.add_response(
        url="https://example.com",
        text="<h1>Welcome</h1>",
        headers={"Server": "Apache"},
        status_code=200,
    )
    # phpinfo probe succeeds and provides version + signature
    httpx_mock.add_response(
        url="https://example.com/phpinfo.php",
        text="<h1>PHP Version 7.4.33</h1>\nphpinfo()",
        status_code=200,
    )
    # Other phpinfo paths return 404
    httpx_mock.add_response(url="https://example.com/info.php", status_code=404)
    httpx_mock.add_response(url="https://example.com/php.php", status_code=404)
    # SQL dump probe returns parsable content
    httpx_mock.add_response(
        url="https://example.com/dump.sql",
        text="""CREATE TABLE users (id INT, name VARCHAR(255));
INSERT INTO users VALUES (1, 'test');""",
        status_code=200,
    )
    # Other SQL paths 404
    for path in ("/backup.sql", "/db.sql", "/database.sql", "/schema.sql"):
        httpx_mock.add_response(url=f"https://example.com{path}", status_code=404)
    # Error page fallback not needed
    httpx_mock.add_response(
        url="https://example.com/nonexistent-404.php", status_code=404
    )

    results = scan_targets(
        ["https://example.com"], config={"max_concurrency": 5, "timeout": 5}
    )

    assert len(results) == 1
    r = results[0]
    assert r.url == "https://example.com"
    assert r.php_version == "7.4.33"
    assert "http-response" in r.detected_from
    assert "phpinfo" in r.detected_from
    assert len(r.exposed_files) == 2  # phpinfo + sql_dump
    assert any(f.file_type == "phpinfo" for f in r.exposed_files)
    assert any(f.file_type == "sql_dump" for f in r.exposed_files)
    assert r.schema is not None
    assert "users" in r.schema.tables
    assert r.schema.columns["users"] == ["id", "name"]
    assert r.schema.row_counts["users"] == 1
    assert len(r.vulns) > 0  # populated by vulndb
    assert not r.errors


def test_detect_php_version_helpers():
    """Test individual fingerprinting functions used by the scanner."""
    assert detect_php_version(headers={"X-Powered-By": "PHP/7.4.33"}) == "7.4.33"
    assert detect_php_version(headers={"Server": "nginx PHP/8.0.1"}) == "8.0.1"
    assert (
        detect_php_version(body='<?php echo "PHP Version 5.6.40"; ?>') == "5.6.40"
    )
    assert detect_php_version(phpinfo_content="<h1>PHP Version 7.2.34</h1>") == "7.2.34"
    assert detect_php_version() is None
    # error page
    err_body = "PHP Parse error: ... (PHP 7.3.12)"
    assert detect_php_version(body=err_body) == "7.3.12"


def test_scan_result_validation():
    """Test Pydantic validation rules on ScanResult."""
    with pytest.raises(ValueError, match="URL must start with"):
        ScanResult(url="ftp://bad.com")

    with pytest.raises(ValueError, match="PHP version must match"):
        ScanResult(url="https://ok.com", php_version="7.x")

    # valid minimal case
    r = ScanResult(url="https://example.com", php_version="8.2.0")
    assert r.php_version == "8.2.0"
    assert not r.is_vulnerable()
