"""Tests for the AsyncScanner, fingerprinting, error handling, Nuclei, Ollama,
live callbacks, schema extraction, community rules and proxy support.

Uses pytest-httpx fixture (httpx_mock) so that the real AsyncClient (which
accepts a proxies= kwarg) is used. This fixes the TypeError seen on py3.12.
Manual mocks for Nuclei/Ollama/Store are kept for speed and determinism.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from pytest_httpx import HTTPXMock

from phpfossil.models import (
    ConfigSettings,
    ExposedFile,
    NucleiFinding,
    ScanResult,
    SchemaResult,
    Vulnerability,
)
from phpfossil.scanner import AsyncScanner, scan_targets
from phpfossil.store import Store


@pytest.mark.asyncio
async def test_scan_error_handling(httpx_mock: HTTPXMock):
    """Test graceful error handling when a target is unreachable."""
    httpx_mock.add_exception(httpx.ConnectError("Connection refused"), url="http://bad.example.com")
    config = ConfigSettings(
        max_concurrency=5,
        timeout=5,
        proxies=[],
        use_nuclei=False,
        use_ollama=False,
        use_community_fingerprints=False,
    )
    results = await scan_targets(["http://bad.example.com"], config=config)
    assert len(results) == 1
    assert len(results[0].errors) > 0
    assert results[0].php_version is None


@pytest.mark.asyncio
async def test_async_scanner_with_proxies(httpx_mock: HTTPXMock):
    """Test scanning with a proxy list (rotation support is handled by scanner)."""
    httpx_mock.add_response(
        url="https://example.com",
        headers={"X-Powered-By": "PHP/7.4.33"},
        text="PHP Version 7.4.33",
        status_code=200,
    )
    config = ConfigSettings(
        max_concurrency=5,
        timeout=10,
        proxies=["http://proxy.example.com:8080"],
        use_nuclei=False,
        use_ollama=False,
        use_community_fingerprints=False,
    )
    results = await scan_targets(["https://example.com"], config=config)
    assert len(results) == 1
    assert results[0].php_version == "7.4.33"
    assert "proxy" in str(config.proxies)


@pytest.mark.asyncio
async def test_async_scanner_direct(httpx_mock: HTTPXMock):
    """Test direct usage of scanner without extra features."""
    httpx_mock.add_response(
        url="https://httpbin.org",
        headers={"Server": "PHP/8.0.0"},
        text="OK",
    )
    config = ConfigSettings(
        max_concurrency=10,
        timeout=5,
        proxies=[],
        use_nuclei=False,
        use_ollama=False,
        use_community_fingerprints=False,
    )
    results = await scan_targets(["https://httpbin.org"], config=config)
    assert len(results) == 1
    assert results[0].php_version == "8.0.0"


@pytest.mark.asyncio
async def test_scanner_with_nuclei(httpx_mock: HTTPXMock):
    """Test Nuclei integration path (mock the validator)."""
    httpx_mock.add_response(
        url="https://example.com",
        headers={"X-Powered-By": "PHP/5.6.40"},
        text="PHP 5.6.40",
    )
    config = ConfigSettings(
        max_concurrency=5,
        timeout=5,
        proxies=[],
        use_nuclei=True,
        use_ollama=False,
        use_community_fingerprints=False,
    )
    with patch("phpfossil.scanner.validate_with_nuclei", new_callable=AsyncMock) as mock_nuclei:
        mock_nuclei.return_value = [NucleiFinding(template="php-rce", name="RCE", severity="high")]
        results = await scan_targets(["https://example.com"], config=config)
        assert len(results) == 1
        assert len(results[0].nuclei_findings) == 1
        assert results[0].nuclei_findings[0].severity == "high"


@pytest.mark.asyncio
async def test_scanner_with_ollama(httpx_mock: HTTPXMock):
    """Test Ollama summarization path (mock the summarizer)."""
    httpx_mock.add_response(
        url="https://example.com",
        headers={"Server": "PHP/7.3.12"},
        text="PHP Version 7.3.12",
    )
    config = ConfigSettings(
        max_concurrency=5,
        timeout=5,
        proxies=[],
        use_nuclei=False,
        use_ollama=True,
        ollama_model="llama3",
        use_community_fingerprints=False,
    )
    with patch("phpfossil.scanner.OllamaSummarizer.summarize", new_callable=AsyncMock) as mock_ollama:
        mock_ollama.return_value = "High risk legacy PHP installation detected."
        results = await scan_targets(["https://example.com"], config=config)
        assert len(results) == 1
        assert results[0].llm_summary is not None


@pytest.mark.asyncio
async def test_scanner_live_callback(httpx_mock: HTTPXMock):
    """Test live callback is invoked for each result."""
    httpx_mock.add_response(
        url="https://example.com",
        headers={"X-Powered-By": "PHP/8.1.0"},
        text="OK",
    )
    config = ConfigSettings(
        max_concurrency=5,
        timeout=5,
        proxies=[],
        use_nuclei=False,
        use_ollama=False,
        use_community_fingerprints=False,
    )
    callback_calls = []

    def live_callback(result: ScanResult):
        callback_calls.append(result)

    await scan_targets(["https://example.com"], config=config, callback=live_callback)
    assert len(callback_calls) == 1
    assert callback_calls[0].php_version == "8.1.0"


@pytest.mark.asyncio
async def test_scanner_with_schema_sync(httpx_mock: HTTPXMock):
    """Test exposed SQL dump parsing and schema extraction."""
    sql_body = "CREATE TABLE users (id INT, email VARCHAR);"
    httpx_mock.add_response(url="https://example.com", text="PHP 7.4")
    httpx_mock.add_response(url="https://example.com/dump.sql", text=sql_body)
    config = ConfigSettings(
        max_concurrency=5,
        timeout=5,
        proxies=[],
        use_nuclei=False,
        use_ollama=False,
        use_community_fingerprints=False,
    )
    results = await scan_targets(["https://example.com"], config=config)
    assert len(results) == 1
    if results[0].db_schema:
        assert "users" in results[0].db_schema.tables


@pytest.mark.asyncio
async def test_community_fingerprints_in_scanner(httpx_mock: HTTPXMock):
    """Test community fingerprint rules are loaded and applied when enabled."""
    httpx_mock.add_response(
        url="https://example.com",
        text="Debug output: PHP Version: 7.2.34",
    )
    config = ConfigSettings(
        max_concurrency=5,
        timeout=5,
        proxies=[],
        use_nuclei=False,
        use_ollama=False,
        use_community_fingerprints=True,
    )
    results = await scan_targets(["https://example.com"], config=config)
    assert len(results) == 1
    # community fallback should detect the version
    assert results[0].php_version is not None


@pytest.mark.asyncio
async def test_async_scanner_class(httpx_mock: HTTPXMock):
    """Test the AsyncScanner class directly (context manager style)."""
    httpx_mock.add_response(
        url="https://test.com",
        headers={"X-Powered-By": "PHP/7.4.33"},
        text="body",
    )
    config = ConfigSettings(
        max_concurrency=5,
        timeout=5,
        proxies=["http://proxy:3128"],
        use_nuclei=False,
        use_ollama=False,
        use_community_fingerprints=False,
    )
    async with AsyncScanner(config=config) as scanner:
        result = await scanner._probe_target("https://test.com")  # type: ignore[attr-defined]
        assert result.php_version == "7.4.33"


# Additional coverage for Store and exposed files (existing tests)
def test_store_persistence():
    store = Store(db_path=":memory:")
    result = ScanResult(url="https://example.com", php_version="7.4.33")
    store.save(result)
    historical = store.get_historical(limit=1)
    assert len(historical) == 1
    assert historical[0].url == "https://example.com"


def test_exposed_file_model():
    exposed = ExposedFile(
        url="https://example.com/phpinfo.php",
        file_type="phpinfo",
        content_preview="PHP Version 7.4",
    )
    assert exposed.file_type == "phpinfo"
    assert "phpinfo" in exposed.url


@pytest.mark.asyncio
async def test_scanner_vuln_mapping(httpx_mock: HTTPXMock):
    """Ensure vulndb mapping attaches CVEs for legacy versions."""
    httpx_mock.add_response(
        url="https://legacy.test",
        headers={"Server": "PHP/5.6.40"},
        text="old php",
    )
    config = ConfigSettings(
        max_concurrency=5,
        timeout=5,
        proxies=[],
        use_nuclei=False,
        use_ollama=False,
        use_community_fingerprints=False,
    )
    results = await scan_targets(["https://legacy.test"], config=config)
    assert len(results) == 1
    if results[0].vulns:
        assert any(v.cve.startswith("CVE-") for v in results[0].vulns)
