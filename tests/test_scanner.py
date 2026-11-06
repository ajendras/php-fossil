"""Tests for PHP Fossil scanner and fingerprinter.

Covers normal cases, edge cases, error handling, mocked HTTP interactions,
version detection from multiple sources, exposed file probing, and schema parsing.
Uses pytest, pytest-httpx and pytest-asyncio.
"""

import asyncio
from datetime import datetime
from typing import Any, Dict

import httpx
import pytest
from pytest_httpx import HTTPXMock
from pytest_asyncio import fixture as async_fixture

from phpfossil.fingerprinter import (
    detect_from_body,
    detect_from_error_page,
    detect_from_headers,
    detect_from_phpinfo,
    detect_php_version,
)
from phpfossil.models import ScanResult, SchemaResult, Vulnerability
from phpfossil.scanner import scan_targets
from phpfossil.schema import parse_sql_dump
from phpfossil.vulndb import get_vulns_for_version, load


def test_detect_from_headers_valid() -> None:
    """Test header-based PHP version detection with common header names."""
    headers: Dict[str, str] = {"X-Powered-By": "PHP/7.4.33"}
    assert detect_from_headers(headers) == "7.4.33"

    headers = {"Server": "nginx/1.18.0 PHP/8.1.12"}
    assert detect_from_headers(headers) == "8.1.12"

    assert detect_from_headers({}) is None
    assert detect_from_headers(None) is None


def test_detect_from_body() -> None:
    """Test body-based PHP version detection."""
    body = 'PHP Version</td><td>7.3.33'
    assert detect_from_body(body) == "7.3.33"

    body = "Powered by PHP 8.0.0"
    assert detect_from_body(body) == "8.0.0"

    assert detect_from_body("no version here") is None


def test_detect_from_phpinfo() -> None:
    """Test phpinfo specific parser."""
    content = "<h1>PHP Version 8.0.0</h1>"
    assert detect_from_phpinfo(content) == "8.0.0"

    content = "PHP Version </td><td class=\"v\">7.4.33"
    assert detect_from_phpinfo(content) == "7.4.33"


def test_detect_from_error_page() -> None:
    """Test error page version leak detection."""
    content = "PHP Version: 5.6.40"
    assert detect_from_error_page(content) == "5.6.40"

    content = "PHP Parse error: ... (PHP 7.4.33)"
    assert detect_from_error_page(content) == "7.4.33"

    assert detect_from_error_page("no version") is None


def test_detect_php_version_combined() -> None:
    """Test the combined detector prioritizes correctly."""
    headers = {"X-Powered-By": "PHP/7.2.24"}
    body = "PHP Version 7.4"
    assert detect_php_version(headers, body) == "7.2.24"  # headers first


def test_parse_sql_dump() -> None:
    """Test SQL dump parser extracts tables, columns and row counts."""
    sql = """
CREATE TABLE users (id INT PRIMARY KEY, name VARCHAR(255));
INSERT INTO users VALUES (1, 'test');
CREATE TABLE posts (`id` INT, title TEXT);
INSERT INTO posts VALUES (1, 'hello', 1), (2, 'world', 2);
    """
    schema = parse_sql_dump(sql)
    assert schema.tables == ["users", "posts"]
    assert "users" in schema.columns
    assert len(schema.columns["users"]) >= 2
    assert schema.row_counts["users"] == 1
    assert schema.row_counts["posts"] == 2


def test_get_vulns_for_version() -> None:
    """Test vuln lookup returns expected CVEs."""
    vulns = get_vulns_for_version("5.6.40")
    assert len(vulns) >= 2
    assert any(v.cve == "CVE-2012-1823" for v in vulns)
    assert any(v.severity == "critical" for v in vulns)

    assert get_vulns_for_version("") == []
    assert get_vulns_for_version("9.9.9") == []


def test_load_vulndb() -> None:
    """Test loading the full vulnerability list."""
    vulns = load()
    assert len(vulns) > 5
    assert all(isinstance(v, Vulnerability) for v in vulns)


def test_scan_targets_validation() -> None:
    """Test input validation in scan_targets."""
    with pytest.raises(ValueError, match="non-empty list"):
        scan_targets([])

    with pytest.raises(ValueError, match="valid http/https"):
        scan_targets(["ftp://bad.example.com"])


@pytest.mark.asyncio
async def test_scan_targets_with_mock(httpx_mock: HTTPXMock) -> None:
    """Test async scanning with mocked HTTP responses using pytest-httpx."""
    target = "https://example.com"
    httpx_mock.add_response(
        url=target,
        text="<h1>PHP Version 7.4.33</h1>",
        headers={"X-Powered-By": "PHP/7.4.33"},
        status_code=200,
    )
    httpx_mock.add_response(
        url="https://example.com/info.php",
        text="phpinfo() PHP Version 7.4.33",
        status_code=200,
    )
    httpx_mock.add_response(
        url="https://example.com/dump.sql",
        text="CREATE TABLE users (id INT); INSERT INTO users VALUES (1,'test');",
        status_code=200,
    )

    results = scan_targets([target], config={"max_concurrency": 5, "timeout": 5})
    assert len(results) == 1
    r: ScanResult = results[0]
    assert r.url == target
    assert r.php_version == "7.4.33"
    assert "headers" in r.detected_from
    assert len(r.exposed_files) >= 1
    if r.schema:
        assert len(r.schema.tables) > 0
    assert len(r.vulns) > 0
