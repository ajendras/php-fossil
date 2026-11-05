"""Tests for PHP Fossil scanner and fingerprinter.

Covers normal cases, edge cases, error handling, mocked HTTP interactions,
version detection from multiple sources, exposed file probing, and schema parsing.
Uses pytest, pytest-httpx and pytest-asyncio.
"""

import asyncio
from datetime import datetime
from typing import Any, Dict
from unittest.mock import patch

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
from phpfossil.models import ScanResult, SchemaResult
from phpfossil.scanner import (
    AsyncScanner,
    _get_embedded_vulndb,
    get_vulns_for_version,
    parse_sql_dump,
    scan,
)


def test_detect_from_headers_valid() -> None:
    """Test header-based PHP version detection with common header names."""
    headers: Dict[str, str] = {"X-Powered-By": "PHP/7.4.33"}
    assert detect_from_headers(headers) == "7.4.33"

    headers = {"Server": "nginx/1.18.0 PHP/8.1.12"}
    assert detect_from_headers(headers) == "8.1.12"

    headers = {"x-powered-by": "PHP/5.6.40"}
    assert detect_from_headers(headers) == "5.6.40"


def test_detect_from_headers_none() -> None:
    """Test that missing or malformed headers return None."""
    assert detect_from_headers({}) is None
    assert detect_from_headers(None) is None  # type: ignore[arg-type]
    assert detect_from_headers({"Server": "Apache/2.4"}) is None


def test_detect_from_body_patterns() -> None:
    """Test multiple body patterns used by real phpinfo and error pages."""
    body = '<table><tr><td>PHP Version</td><td>7.2.24</td></tr></table>'
    assert detect_from_body(body) == "7.2.24"

    body = 'var phpVersion = "8.0.11";'
    assert detect_from_body(body) == "8.0.11"

    body = "Powered by PHP 5.6.40"
    assert detect_from_body(body) == "5.6.40"


def test_detect_from_phpinfo() -> None:
    """Test phpinfo() specific extraction patterns."""
    content = "<h1>PHP Version 7.4.33</h1>"
    assert detect_from_phpinfo(content) == "7.4.33"

    content = 'PHP Version </td><td class="v">8.2.0'
    assert detect_from_phpinfo(content) == "8.2.0"


def test_detect_from_error_page() -> None:
    """Test version leakage on typical 404/error pages."""
    content = "PHP Parse error: ... (PHP 7.3.12)"
    assert detect_from_error_page(content) == "7.3.12"

    content = "Server: Apache/2.4.41 (Unix) PHP/5.6.40"
    assert detect_from_error_page(content) == "5.6.40"


def test_detect_php_version_combined_priority() -> None:
    """Test that headers take precedence over body and phpinfo."""
    headers = {"X-Powered-By": "PHP/7.4.33"}
    body = "PHP Version 8.0.0"
    phpinfo = "PHP Version 8.1.0"

    assert detect_php_version(headers, body, phpinfo) == "7.4.33"


def test_parse_sql_dump_normal() -> None:
    """Test schema extraction from realistic mysqldump output."""
    sql = """-- phpMyAdmin SQL Dump
CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `name` varchar(100) NOT NULL,
  `email` varchar(100) DEFAULT NULL
) ENGINE=InnoDB;
INSERT INTO `users` VALUES (1,'alice','alice@example.com'),(2,'bob',NULL);
CREATE TABLE `orders` (`id` int, `total` decimal(10,2));
"""
    schema: SchemaResult = parse_sql_dump(sql)

    assert schema.tables == ["users", "orders"]
    assert "users" in schema.columns
    assert "id" in schema.columns["users"]
    assert "name" in schema.columns["users"]
    assert schema.row_counts["users"] == 1
    assert schema.row_counts.get("orders", 0) == 0


def test_parse_sql_dump_edge_cases() -> None:
    """Test robustness against malformed, empty, or non-SQL content."""
    assert parse_sql_dump("").tables == []
    assert parse_sql_dump("just some text").tables == []
    assert parse_sql_dump(None).tables == []  # type: ignore[arg-type]


def test_get_vulns_for_version() -> None:
    """Test CVE mapping from embedded vulnerability database."""
    vulns = get_vulns_for_version("5.6.30")
    assert len(vulns) >= 2
    cves = {v.cve for v in vulns}
    assert "CVE-2012-1823" in cves
    assert any(v.severity == "critical" for v in vulns)

    vulns = get_vulns_for_version("7.0.99")
    assert len(vulns) >= 1
    assert any("CVE-2019-11043" in v.cve for v in vulns)

    assert len(get_vulns_for_version("9.0")) == 0
    assert len(get_vulns_for_version("")) == 0


@pytest.mark.asyncio
async def test_async_scanner_basic(httpx_mock: HTTPXMock) -> None:
    """Test AsyncScanner with mocked responses covering multiple detection paths."""
    target = "https://legacy.example.com"

    # Main page with version in header and body
    httpx_mock.add_response(
        url=target,
        status_code=200,
        headers={"X-Powered-By": "PHP/7.4.33"},
        text="<h1>Welcome</h1><p>Powered by PHP 7.4.33</p>",
    )

    # phpinfo probe
    httpx_mock.add_response(
        url=f"{target}/phpinfo.php",
        status_code=200,
        text="<title>phpinfo()</title><h1>PHP Version 7.4.33</h1>",
    )

    # SQL dump probe
    sql_content = "CREATE TABLE users (id INT); INSERT INTO users VALUES (1);"
    httpx_mock.add_response(
        url=f"{target}/dump.sql",
        status_code=200,
        text=sql_content,
    )

    # 404 error page (fallback)
    httpx_mock.add_response(
        url=f"{target}/nonexistent-404.php",
        status_code=404,
        text="PHP/7.4.33",
    )

    scanner = AsyncScanner(config={"timeout": 5.0, "max_concurrency": 5, "retries": 1})
    results: List[ScanResult] = await scanner.scan([target])

    assert len(results) == 1
    result = results[0]
    assert result.url == target
    assert result.php_version == "7.4.33"
    assert "headers" in result.detected_from
    assert len(result.exposed_files) >= 1

    phpinfo_files = [f for f in result.exposed_files if f.file_type == "phpinfo"]
    assert len(phpinfo_files) >= 1

    sql_files = [f for f in result.exposed_files if f.file_type == "sql_dump"]
    assert len(sql_files) >= 1
    assert result.schema is not None
    assert "users" in result.schema.tables


@pytest.mark.asyncio
async def test_async_scanner_error_handling(httpx_mock: HTTPXMock) -> None:
    """Test graceful degradation when all requests fail."""
    httpx_mock.add_exception(httpx.TimeoutException("timeout"), url="https://bad.example.com")

    scanner = AsyncScanner(config={"timeout": 3, "retries": 1})
    results = await scanner.scan(["https://bad.example.com"])

    assert len(results) == 1
    result = results[0]
    assert len(result.errors) > 0
    assert result.php_version is None


def test_sync_scan_wrapper(httpx_mock: HTTPXMock) -> None:
    """Test the synchronous scan() wrapper with mocked responses."""
    httpx_mock.add_response(
        url="https://example.com",
        status_code=200,
        headers={"Server": "PHP/8.0.0"},
        text="PHP Version 8.0.0",
    )

    results = scan(["https://example.com"], config={"timeout": 5})
    assert len(results) == 1
    assert results[0].php_version == "8.0.0"


def test_scanner_input_validation() -> None:
    """Test that invalid targets raise clear ValueError messages."""
    scanner = AsyncScanner()

    with pytest.raises(ValueError, match="non-empty list"):
        asyncio.run(scanner.scan([]))

    with pytest.raises(ValueError, match="valid http/https URLs"):
        asyncio.run(scanner.scan(["ftp://bad.com"]))
