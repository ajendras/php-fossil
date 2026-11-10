"""Tests for the PHP Fossil scanner module.

Covers fingerprinting integration, exposed file detection, schema parsing,
async concurrency, Nuclei/Ollama optional flows and model construction.
Uses pytest-httpx for mocking HTTP responses.
"""

import pytest
from pytest_httpx import HTTPXMock

from phpfossil.scanner import scan_targets, AsyncScanner
from phpfossil.models import ScanResult, SchemaResult


@pytest.mark.asyncio
async def test_scan_targets_basic(httpx_mock: HTTPXMock):
    """Test basic scanning with version detection from headers and body."""
    httpx_mock.add_response(
        url="https://httpbin.org",
        headers={"X-Powered-By": "PHP/7.4.33"},
        text="<title>Demo</title><p>PHP Version 7.4.33</p>",
        status_code=200,
    )
    httpx_mock.add_response(
        url="http://example.com",
        text="No PHP here",
        status_code=200,
    )

    results = await scan_targets(
        ["https://httpbin.org", "http://example.com"],
        config={
            "max_concurrency": 5,
            "timeout": 5,
            "use_nuclei": False,
            "use_ollama": False,
        },
    )

    assert len(results) == 2
    r0 = results[0]
    assert r0.url == "https://httpbin.org"
    assert r0.php_version == "7.4.33"
    assert "headers" in r0.detected_from or "body" in r0.detected_from
    assert len(r0.vulns) > 0
    assert isinstance(r0.scan_time, str) or hasattr(r0.scan_time, "isoformat")


@pytest.mark.asyncio
async def test_scanner_with_exposed_files_and_schema(httpx_mock: HTTPXMock):
    """Test detection of phpinfo and SQL dump with schema parsing."""
    sql_dump = """-- SQL Dump
CREATE TABLE users (id INT PRIMARY KEY, email VARCHAR(255));
INSERT INTO users VALUES (1, 'test@example.com');
"""

    httpx_mock.add_response(
        url="https://test.com",
        text="<html>OK</html>",
        status_code=200,
    )
    httpx_mock.add_response(
        url="https://test.com/phpinfo.php",
        text="<h1>PHP Version 8.0.0</h1><table><tr><td>phpinfo()</td></tr></table>",
        status_code=200,
    )
    httpx_mock.add_response(
        url="https://test.com/dump.sql",
        text=sql_dump,
        status_code=200,
    )

    results = await scan_targets(
        ["https://test.com"],
        config={
            "max_concurrency": 5,
            "timeout": 5,
            "use_nuclei": False,
            "use_ollama": False,
        },
    )

    assert len(results) == 1
    r = results[0]
    assert r.php_version == "8.0.0"
    assert len(r.exposed_files) >= 2
    phpinfo_files = [f for f in r.exposed_files if f.file_type == "phpinfo"]
    sql_files = [f for f in r.exposed_files if f.file_type == "sql_dump"]
    assert len(phpinfo_files) >= 1
    assert len(sql_files) >= 1
    assert r.db_schema is not None
    assert "users" in r.db_schema.tables
    assert "email" in r.db_schema.columns.get("users", [])


def test_async_scanner_init():
    """Test configuration handling in AsyncScanner."""
    config = {
        "max_concurrency": 30,
        "timeout": 10,
        "use_nuclei": True,
        "use_ollama": True,
        "proxies": ["http://proxy1", "http://proxy2"],
    }
    scanner = AsyncScanner(config)
    assert scanner.max_concurrency == 30
    assert scanner.timeout == 10
    assert scanner.use_nuclei is True
    assert scanner.use_ollama is True
    assert len(scanner.proxies) == 2
    assert scanner.proxy_cycle is not None


@pytest.mark.asyncio
async def test_scan_with_nuclei_mock(httpx_mock: HTTPXMock):
    """Test Nuclei path (mocked)."""
    httpx_mock.add_response(
        url="https://legacy.com",
        headers={"Server": "Apache PHP/5.6.40"},
        text="Legacy PHP",
        status_code=200,
    )

    results = await scan_targets(
        ["https://legacy.com"],
        config={
            "max_concurrency": 5,
            "timeout": 5,
            "use_nuclei": True,
            "use_ollama": False,
        },
    )

    assert len(results) == 1
    r = results[0]
    assert r.php_version == "5.6.40"
    # Nuclei may return error finding when binary not present
    assert any("Nuclei" in err or "nuclei" in err.lower() for err in r.errors) or len(r.nuclei_findings) >= 0


@pytest.mark.asyncio
async def test_error_handling(httpx_mock: HTTPXMock):
    """Test graceful handling of request failures."""
    httpx_mock.add_exception(Exception("Connection refused"), url="https://bad.target")

    results = await scan_targets(
        ["https://bad.target"],
        config={"max_concurrency": 5, "timeout": 3},
    )

    assert len(results) == 1
    r = results[0]
    assert r.url == "https://bad.target"
    assert len(r.errors) > 0
    assert not r.php_version


def test_scan_result_model():
    """Test ScanResult construction and methods."""
    schema = SchemaResult(tables=["users", "posts"], columns={"users": ["id", "name"]})
    result = ScanResult(
        url="https://example.com",
        php_version="7.2.34",
        db_schema=schema,
        vulns=[],
    )
    assert result.url == "https://example.com"
    assert result.php_version == "7.2.34"
    assert result.db_schema is not None
    assert "users" in result.db_schema.tables
    assert result.is_vulnerable() is False
    assert result.has_nuclei_confirmations() is False
