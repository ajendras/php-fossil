"""Tests for the PHP Fossil scanner.

Covers fingerprinting accuracy, async HTTP mocking with pytest-httpx,
live callbacks, Nuclei/Ollama integration, error handling, and schema extraction.
Updated to use is_optional=True and regex matchers so that all probe paths
(main URL, phpinfo endpoints, random nonexistent-*.php error pages) no longer
trigger mock assertion failures.
"""

import asyncio
import re
from typing import List

import httpx
import pytest

from phpfossil.models import ScanResult
from phpfossil.scanner import AsyncScanner, scan_targets


@pytest.fixture
def mock_nuclei(monkeypatch):
    """Mock validate_with_nuclei to avoid real subprocess calls."""

    def _mock_validate(*args, **kwargs):
        return []

    monkeypatch.setattr("phpfossil.scanner.validate_with_nuclei", _mock_validate)
    return _mock_validate


@pytest.fixture
def mock_ollama(monkeypatch):
    """Mock generate_summary to avoid real Ollama HTTP calls."""

    def _mock_summary(results, model="llama3"):
        return "Mock LLM summary: High risk due to legacy PHP 7.4.33 with exposed schema."

    monkeypatch.setattr("phpfossil.scanner.generate_summary", _mock_summary)
    return _mock_summary


@pytest.mark.asyncio
async def test_scan_targets(httpx_mock):
    """Test scanning multiple targets with version detection from headers/body."""
    httpx_mock.add_response(
        url="http://example.com",
        headers={"X-Powered-By": "PHP/5.6.40"},
        text="Welcome",
    )
    httpx_mock.add_response(
        url="https://httpbin.org",
        headers={"Server": "Apache PHP/7.4.33"},
        text="PHP Version 7.4.33",
    )
    # Register optional probes so "mocked but not requested" errors disappear
    for base in ("http://example.com", "https://httpbin.org"):
        httpx_mock.add_response(
            url=re.compile(re.escape(base) + r"/(phpinfo|info)\.php.*"),
            text="PHP info output",
            is_optional=True,
        )
        httpx_mock.add_response(
            url=re.compile(re.escape(base) + r"/\?phpinfo=1"),
            text="PHP Version info",
            is_optional=True,
        )
        httpx_mock.add_response(
            url=re.compile(re.escape(base) + r"/nonexistent-\d+\.php"),
            text="PHP Parse error: ... (PHP 7.4.33)",
            status_code=404,
            is_optional=True,
        )

    results: List[ScanResult] = await scan_targets(
        ["http://example.com", "https://httpbin.org"]
    )
    assert len(results) == 2
    versions = {r.php_version for r in results if r.php_version is not None}
    assert "5.6.40" in versions
    assert "7.4.33" in versions


@pytest.mark.asyncio
async def test_async_scanner_direct(httpx_mock):
    """Test direct usage of AsyncScanner (used by some internal tests)."""
    httpx_mock.add_response(
        url="http://example.com",
        headers={"X-Powered-By": "PHP/5.6.40"},
        text="<h1>PHP Version 5.6.40</h1>",
    )
    httpx_mock.add_response(
        url=re.compile(r"http://example\.com/.*"),
        text="PHP 5.6.40",
        is_optional=True,
    )

    scanner = AsyncScanner(config={"max_concurrency": 5, "timeout": 5})
    results = await scanner.scan(["http://example.com"])
    assert len(results) == 1
    assert results[0].php_version == "5.6.40"
    assert any(src in results[0].detected_from for src in ("headers", "body"))


@pytest.mark.asyncio
async def test_scanner_with_nuclei(httpx_mock, mock_nuclei):
    """Test Nuclei integration path (mocked)."""
    httpx_mock.add_response(
        url="https://httpbin.org",
        headers={"X-Powered-By": "PHP/7.4.33"},
        text="PHP Version 7.4.33",
    )
    httpx_mock.add_response(
        url=re.compile(r"https://httpbin\.org/nonexistent-\d+\.php"),
        text="PHP/7.4.33",
        status_code=404,
        is_optional=True,
    )
    httpx_mock.add_response(
        url=re.compile(r"https://httpbin\.org/(phpinfo|info).*"),
        text="info",
        is_optional=True,
    )

    results = await scan_targets(
        ["https://httpbin.org"], config={"use_nuclei": True}
    )
    assert len(results) == 1
    assert results[0].php_version == "7.4.33"
    assert isinstance(results[0].nuclei_findings, list)


@pytest.mark.asyncio
async def test_scanner_with_ollama(httpx_mock, mock_ollama):
    """Test Ollama integration (mocked). Also exercises is_ollama_available path."""
    httpx_mock.add_response(
        url="https://httpbin.org",
        headers={"X-Powered-By": "PHP/7.4.33"},
        text="PHP Version 7.4.33",
    )
    httpx_mock.add_response(
        url=re.compile(r"https://httpbin\.org/nonexistent-\d+\.php"),
        text="PHP Version 7.4.33",
        status_code=404,
        is_optional=True,
    )
    httpx_mock.add_response(
        url=re.compile(r"https://httpbin\.org/(phpinfo|info).*"),
        text="info",
        is_optional=True,
    )
    # Ollama availability check
    httpx_mock.add_response(
        url="http://localhost:11434/api/tags",
        json={"models": [{"name": "llama3"}]},
        is_optional=True,
    )

    results = await scan_targets(
        ["https://httpbin.org"], config={"use_ollama": True}
    )
    assert len(results) == 1
    assert results[0].php_version == "7.4.33"
    assert results[0].llm_summary is not None
    assert "Mock LLM summary" in results[0].llm_summary


@pytest.mark.asyncio
async def test_scanner_live_callback(httpx_mock):
    """Test live callback used by the TUI (previously asserted 0 == 1)."""
    callback_results: List[ScanResult] = []

    def live_callback(result: ScanResult) -> None:
        callback_results.append(result)

    httpx_mock.add_response(
        url="https://httpbin.org",
        headers={"Server": "PHP/8.0.0"},
        text="PHP Version 8.0.0",
    )
    httpx_mock.add_response(
        url=re.compile(r"https://httpbin\.org/.*"),
        text="PHP Version 8.0.0",
        is_optional=True,
    )

    results = await scan_targets(
        ["https://httpbin.org"], callback=live_callback
    )
    assert len(results) == 1
    assert len(callback_results) == 1
    assert results[0].php_version == "8.0.0"
    assert callback_results[0].php_version == "8.0.0"


def test_scan_error_handling(httpx_mock):
    """Test error handling for unreachable hosts (previously produced unexpected-request errors)."""
    # Broad regex covers all additional probes (/phpinfo.php, /info.php, ?phpinfo=1, nonexistent-*.php)
    httpx_mock.add_exception(
        httpx.ConnectError("Connection refused"),
        url=re.compile(r"https://bad\.example\.com.*"),
    )

    results = asyncio.run(scan_targets(["https://bad.example.com"]))
    assert len(results) == 1
    assert len(results[0].errors) > 0
    assert results[0].url == "https://bad.example.com"


@pytest.mark.asyncio
async def test_scanner_with_schema(httpx_mock):
    """Test schema extraction from exposed SQL dump."""
    sql_content = """-- PHP Fossil test dump
CREATE TABLE users (id INT, email VARCHAR(255));
CREATE TABLE orders (id INT, amount DECIMAL);
"""
    httpx_mock.add_response(
        url="https://httpbin.org",
        text='See backup at <a href="/backup.sql">backup.sql</a>',
    )
    httpx_mock.add_response(
        url="https://httpbin.org/backup.sql",
        text=sql_content,
    )
    httpx_mock.add_response(
        url=re.compile(r"https://httpbin\.org/.*"),
        text="placeholder",
        is_optional=True,
    )

    results = await scan_targets(["https://httpbin.org"])
    assert len(results) == 1
    assert results[0].db_schema is not None
    assert "users" in results[0].db_schema.tables
    assert "orders" in results[0].db_schema.tables
    assert len(results[0].exposed_files) > 0
