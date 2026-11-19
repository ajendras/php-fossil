"""Tests for the PHP Fossil scanner."""

import asyncio
from unittest.mock import patch

import httpx
import pytest

from phpfossil import (
    AsyncScanner,
    ConfigSettings,
    ScanResult,
    scan_targets,
)
from phpfossil.fingerprinter import CommunityFingerprinter
from phpfossil.models import NucleiFinding, SchemaResult, Vulnerability


@pytest.mark.asyncio
async def test_scan_error_handling(httpx_mock):
    """Test error handling for unreachable targets."""
    httpx_mock.add_exception(
        httpx.ConnectError("Connection failed"),
        url="http://bad.example.com",
    )
    results = await scan_targets(["http://bad.example.com"])
    assert len(results) == 1
    assert len(results[0].errors) > 0
    assert any("error" in e.lower() or "connect" in e.lower() for e in results[0].errors)


@pytest.mark.asyncio
async def test_async_scanner_with_proxies(httpx_mock):
    """Test scanning with proxy configuration."""
    httpx_mock.add_response(
        url="https://example.com",
        text='PHP Version 7.4.33 <meta name="generator" content="WordPress 5.8">',
        headers={"Server": "Apache/2 PHP/7.4.33"},
    )
    config = ConfigSettings(
        max_concurrency=5,
        timeout=10,
        proxies=["http://proxy.example.com:8080"],
        use_community_fingerprints=False,
    )
    results = await scan_targets(["https://example.com"], config=config)
    assert len(results) == 1
    assert results[0].php_version == "7.4.33"
    assert len(results[0].detected_from) >= 1


@pytest.mark.asyncio
async def test_async_scanner_direct(httpx_mock):
    """Test direct usage of scanner against httpbin."""
    httpx_mock.add_response(
        url="https://httpbin.org",
        text="PHP Version 8.0.0",
        headers={"X-Powered-By": "PHP/8.0.0"},
    )
    results = await scan_targets(["https://httpbin.org"], config={"max_concurrency": 3})
    assert len(results) == 1
    assert results[0].php_version == "8.0.0"


@pytest.mark.asyncio
async def test_scanner_with_nuclei(httpx_mock):
    """Test integration with Nuclei validator."""
    httpx_mock.add_response(
        url="https://example.com",
        text="PHP Version 7.2.0",
        headers={"X-Powered-By": "PHP/7.2.0"},
    )
    with patch("phpfossil.nuclei.validate_with_nuclei") as mock_nuclei:
        mock_nuclei.return_value = [
            NucleiFinding(
                template="php-cve",
                name="PHP RCE",
                severity="critical",
            )
        ]
        config = ConfigSettings(use_nuclei=True, max_concurrency=5)
        results = await scan_targets(["https://example.com"], config=config)
        assert len(results) == 1
        assert len(results[0].nuclei_findings) == 1
        assert results[0].nuclei_findings[0].severity == "critical"


@pytest.mark.asyncio
async def test_scanner_with_ollama(httpx_mock):
    """Test Ollama summarization from scanner."""
    httpx_mock.add_response(
        url="https://example.com",
        text="PHP Version 5.6.40",
        headers={"X-Powered-By": "PHP/5.6.40"},
    )
    httpx_mock.add_response(
        url="http://localhost:11434/api/generate",
        json={"response": "This is a test summary of the vulnerabilities found."},
    )
    config = ConfigSettings(
        use_ollama=True,
        ollama_model="llama3",
        use_nuclei=False,
        max_concurrency=5,
    )
    results = await scan_targets(["https://example.com"], config=config)
    assert len(results) == 1
    assert results[0].php_version == "5.6.40"
    assert results[0].llm_summary is not None


@pytest.mark.asyncio
async def test_scanner_live_callback(httpx_mock):
    """Test live callback during scanning."""
    httpx_mock.add_response(
        url="https://example.com",
        text="<h1>PHP Version 7.4.33</h1>",
        headers={"X-Powered-By": "PHP/7.4.33"},
    )
    callback_calls = []
    def live_callback(result: ScanResult):
        callback_calls.append(result)
    config = ConfigSettings(max_concurrency=5, use_community_fingerprints=False)
    results = await scan_targets(
        ["https://example.com"], config=config, callback=live_callback
    )
    assert len(results) == 1
    assert len(callback_calls) == 1
    assert results[0].php_version == "7.4.33"


@pytest.mark.asyncio
async def test_scanner_with_schema_sync(httpx_mock):
    """Test schema extraction with SQL dump (sync-named test for historical reasons)."""
    httpx_mock.add_response(
        url="https://example.com",
        text='... <a href="dump.sql">database backup</a> ... PHP 7.4',
        headers={},
    )
    httpx_mock.add_response(
        url="https://example.com/dump.sql",
        text="CREATE TABLE users (id INT, password VARCHAR(255));\n-- row count approx 500",
    )
    config = ConfigSettings(max_concurrency=5)
    results = await scan_targets(["https://example.com"], config=config)
    assert len(results) == 1
    assert results[0].db_schema is not None
    assert "users" in [t.lower() for t in results[0].db_schema.tables]


@pytest.mark.asyncio
async def test_community_fingerprints_in_scanner(httpx_mock):
    """Test community fingerprints loaded and applied by the scanner."""
    httpx_mock.add_response(
        url="https://raw.githubusercontent.com/ajendras/php-fossil/main/community-fingerprints.json",
        json=[
            {
                "type": "body",
                "pattern": r"PHP Version[:\s]+(\d+\.\d+\.\d+)",
                "version_group": 1,
            }
        ],
    )
    httpx_mock.add_response(
        url="https://example.com",
        text="Debug info: PHP Version: 7.3.12",
    )
    config = ConfigSettings(use_community_fingerprints=True, max_concurrency=5)
    results = await scan_targets(["https://example.com"], config=config)
    assert len(results) == 1
    assert results[0].php_version == "7.3.12"


@pytest.mark.asyncio
async def test_async_scanner_class(httpx_mock):
    """Test the AsyncScanner class directly."""
    httpx_mock.add_response(
        url="https://test.com",
        text="PHP Version 7.4.33",
        headers={"X-Powered-By": "PHP/7.4.33"},
    )
    scanner = AsyncScanner(config={"max_concurrency": 10})
    results = await scanner.scan(["https://test.com"])
    assert len(results) == 1
    assert results[0].php_version == "7.4.33"


@pytest.mark.asyncio
async def test_scanner_vuln_mapping(httpx_mock):
    """Test vulnerability mapping for a legacy PHP version."""
    httpx_mock.add_response(
        url="https://legacy.test",
        text="Powered by PHP 5.6.40",
        headers={"X-Powered-By": "PHP/5.6.40"},
    )
    results = await scan_targets(["https://legacy.test"], config={"use_nuclei": False})
    assert len(results) == 1
    assert results[0].php_version == "5.6.40"
    assert len(results[0].vulns) > 0
    assert any(v.severity in ("high", "critical") for v in results[0].vulns)


def test_config_settings_none():
    """Test that ConfigSettings accepts None (uses defaults)."""
    config = ConfigSettings(None)
    assert config.max_concurrency == 20
    assert not config.use_nuclei
    assert not config.use_ollama
