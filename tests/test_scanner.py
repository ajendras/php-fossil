"""Tests for the scanner module.

Covers error handling, async scanning (with/without proxies), Nuclei, Ollama,
live callbacks, schema extraction, community fingerprints integration and
the AsyncScanner class. Updated to work with ConfigSettings, community
fingerprint caching bypass, and pytest-httpx strictness (is_optional=True
for conditional/optional paths such as error handling, Nuclei, Ollama,
community rules and proxies).
"""

import asyncio
from unittest.mock import patch

import httpx
import pytest
from pytest_httpx import HTTPXMock

from phpfossil.models import (
    ConfigSettings,
    NucleiFinding,
    ScanResult,
    Vulnerability,
)
from phpfossil.scanner import AsyncScanner, scan_targets


@pytest.mark.asyncio
async def test_scan_error_handling(httpx_mock: HTTPXMock):
    """Test graceful handling of connection errors."""
    httpx_mock.add_exception(
        httpx.ConnectError("Connection refused"),
        url="https://bad.example.com",
        is_optional=True,
    )
    results = await scan_targets(
        ["https://bad.example.com"],
        config=ConfigSettings(
            max_concurrency=5,
            timeout=5,
            use_nuclei=False,
            use_ollama=False,
            use_community_fingerprints=False,
        ),
    )
    assert len(results) == 1
    assert len(results[0].errors) > 0
    assert any("connection" in err.lower() for err in results[0].errors)


@pytest.mark.asyncio
async def test_async_scanner_with_proxies(httpx_mock: HTTPXMock):
    """Test proxy rotation support in AsyncScanner."""
    httpx_mock.add_response(
        url="http://example.com",
        text='<meta name="generator" content="PHP Version 7.4.33">',
        is_optional=True,
    )
    config = ConfigSettings(
        max_concurrency=5,
        timeout=10,
        proxies=["http://proxy.example.com:8080"],
        use_nuclei=False,
        use_ollama=False,
        use_community_fingerprints=False,
    )
    results = await scan_targets(["http://example.com"], config=config)
    assert len(results) == 1
    assert results[0].php_version == "7.4.33"


@pytest.mark.asyncio
async def test_async_scanner_direct(httpx_mock: HTTPXMock):
    """Test direct (no-proxy) async scanning."""
    httpx_mock.add_response(
        url="http://example.com",
        text="PHP Version 7.4.33",
        is_optional=True,
    )
    results = await scan_targets(
        ["http://example.com"],
        config=ConfigSettings(
            max_concurrency=10,
            use_nuclei=False,
            use_ollama=False,
            use_community_fingerprints=False,
        ),
    )
    assert len(results) == 1
    assert results[0].php_version == "7.4.33"


@pytest.mark.asyncio
async def test_scanner_with_nuclei(httpx_mock: HTTPXMock):
    """Test Nuclei integration for exploit validation."""
    httpx_mock.add_response(
        url="https://httpbin.org",
        text="PHP Version 7.4.33",
        is_optional=True,
    )
    with patch("phpfossil.scanner.validate_with_nuclei") as mock_validate:
        mock_validate.return_value = [
            NucleiFinding(
                template="cve-2019-11043",
                name="PHP CGI Argument Injection",
                severity="high",
            )
        ]
        config = ConfigSettings(
            max_concurrency=5,
            use_nuclei=True,
            use_ollama=False,
            use_community_fingerprints=False,
        )
        results = await scan_targets(["https://httpbin.org"], config=config)
        assert len(results) == 1
        assert len(results[0].nuclei_findings) == 1
        assert results[0].nuclei_findings[0].severity == "high"


@pytest.mark.asyncio
async def test_scanner_with_ollama(httpx_mock: HTTPXMock):
    """Test Ollama LLM summarization path."""
    httpx_mock.add_response(
        url="https://httpbin.org",
        text="PHP Version 7.4.33",
        is_optional=True,
    )
    httpx_mock.add_response(
        url="http://localhost:11434/api/tags",
        json={"models": [{"name": "llama3"}]},
        is_optional=True,
    )
    httpx_mock.add_response(
        url="http://localhost:11434/api/chat",
        json={"response": "Legacy PHP 7.4 detected with high risk due to multiple CVEs."},
        is_optional=True,
    )
    config = ConfigSettings(
        max_concurrency=5,
        use_nuclei=False,
        use_ollama=True,
        ollama_model="llama3",
        use_community_fingerprints=False,
    )
    results = await scan_targets(["https://httpbin.org"], config=config)
    assert len(results) == 1
    assert results[0].llm_summary is not None
    assert "legacy" in results[0].llm_summary.lower()


@pytest.mark.asyncio
async def test_scanner_live_callback(httpx_mock: HTTPXMock):
    """Test live callback support for TUI/real-time UIs."""
    httpx_mock.add_response(
        url="https://httpbin.org",
        text="PHP Version 7.4.33",
        is_optional=True,
    )
    callback_called = []

    def live_callback(result: ScanResult) -> None:
        callback_called.append(result)

    config = ConfigSettings(
        max_concurrency=5,
        use_nuclei=False,
        use_ollama=False,
        use_community_fingerprints=False,
    )
    results = await scan_targets(
        ["https://httpbin.org"], config=config, callback=live_callback
    )
    assert len(results) == 1
    assert len(callback_called) == 1
    assert callback_called[0].php_version == "7.4.33"


@pytest.mark.asyncio
async def test_scanner_with_schema_sync(httpx_mock: HTTPXMock):
    """Test schema extraction from exposed SQL dumps."""
    httpx_mock.add_response(
        url="https://httpbin.org",
        text="See dump.sql for schema",
        is_optional=True,
    )
    httpx_mock.add_response(
        url="https://httpbin.org/dump.sql",
        text="CREATE TABLE users (id INT, email TEXT);\nINSERT INTO users VALUES (1, 'test@example.com');",
        is_optional=True,
    )
    config = ConfigSettings(
        max_concurrency=5,
        use_nuclei=False,
        use_ollama=False,
        use_community_fingerprints=False,
    )
    results = await scan_targets(["https://httpbin.org"], config=config)
    assert len(results) == 1
    if results[0].db_schema:
        assert "users" in results[0].db_schema.tables


@pytest.mark.asyncio
async def test_community_fingerprints_in_scanner(httpx_mock: HTTPXMock):
    """Test community fingerprint rules loaded and used by scanner."""
    community_rules = [
        {
            "type": "body",
            "pattern": r"PHP Version[:\s]+(?P<version>\d+\.\d+\.\d+)",
            "version_group": 1,
        },
        {
            "type": "body",
            "pattern": r"Debug: PHP Version: (?P<version>\d+\.\d+\.\d+)",
            "version_group": 1,
        },
    ]
    httpx_mock.add_response(
        url="https://raw.githubusercontent.com/ajendras/php-fossil/main/community-fingerprints.json",
        json=community_rules,
        is_optional=True,
    )
    httpx_mock.add_response(
        url="https://httpbin.org",
        text="Debug: PHP Version: 7.3.12",
        is_optional=True,
    )
    config = ConfigSettings(
        max_concurrency=5,
        use_nuclei=False,
        use_ollama=False,
        use_community_fingerprints=True,
        community_repo_url="https://raw.githubusercontent.com/ajendras/php-fossil/main/community-fingerprints.json",
    )
    results = await scan_targets(["https://httpbin.org"], config=config)
    assert len(results) == 1
    assert results[0].php_version == "7.3.12"
    assert any("community" in src.lower() for src in results[0].detected_from)


@pytest.mark.asyncio
async def test_async_scanner_class(httpx_mock: HTTPXMock):
    """Test the AsyncScanner class directly."""
    httpx_mock.add_response(
        url="https://httpbin.org",
        text="<h1>PHP Version 7.4.33</h1>",
        is_optional=True,
    )
    config = ConfigSettings(
        max_concurrency=10,
        use_nuclei=False,
        use_ollama=False,
        use_community_fingerprints=False,
    )
    scanner = AsyncScanner(config=config)
    results = await scanner.scan(["https://httpbin.org"])
    assert len(results) == 1
    assert results[0].php_version == "7.4.33"
    assert "body" in results[0].detected_from
