"""Tests for the PHP Fossil scanner.

Covers async scanning, fingerprinting, schema extraction, Nuclei, Ollama,
live callbacks, error handling and the new conditional proxies support.
All previously failing paths now exercise exactly the registered mocks.
"""

import asyncio
from unittest.mock import patch

import pytest
from pytest_httpx import HTTPXMock

from phpfossil.models import ScanResult
from phpfossil.scanner import AsyncScanner, scan_targets


@pytest.mark.asyncio
async def test_async_scanner_direct(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url="http://example.com",
        text="<title>PHP Version 8.0.1</title>",
        headers={"X-Powered-By": "PHP/8.0.1"},
        status_code=200,
    )

    results = await scan_targets(
        ["http://example.com"],
        config={
            "max_concurrency": 5,
            "timeout": 5,
            "use_community_fingerprints": False,
        },
    )
    assert len(results) == 1
    assert results[0].php_version == "8.0.1"
    assert "headers/body/community" in results[0].detected_from


@pytest.mark.asyncio
async def test_scanner_with_nuclei(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url="https://httpbin.org",
        text="PHP Version 7.4.33",
        headers={"Server": "Apache PHP/7.4.33"},
        status_code=200,
    )

    with patch("phpfossil.scanner.validate_with_nuclei") as mock_nuclei:
        mock_nuclei.return_value = [
            {
                "template": "cve-2019-11043",
                "name": "PHP CGI RCE",
                "severity": "critical",
            }
        ]
        results = await scan_targets(
            ["https://httpbin.org"],
            config={
                "max_concurrency": 5,
                "timeout": 5,
                "use_nuclei": True,
                "use_ollama": False,
                "use_community_fingerprints": False,
            },
        )

    assert len(results) == 1
    assert results[0].php_version == "7.4.33"
    assert len(results[0].nuclei_findings) == 1
    assert results[0].nuclei_findings[0].template == "cve-2019-11043"


@pytest.mark.asyncio
async def test_scanner_with_ollama(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url="https://httpbin.org",
        text="PHP 7.3.12",
        headers={"X-Powered-By": "PHP/7.3.12"},
        status_code=200,
    )
    httpx_mock.add_response(
        url="http://localhost:11434/api/tags",
        json={"models": [{"name": "llama3"}]},
        status_code=200,
    )
    httpx_mock.add_response(
        url="http://localhost:11434/api/chat",
        json={"message": {"content": "High risk legacy PHP site found."}},
        status_code=200,
    )

    results = await scan_targets(
        ["https://httpbin.org"],
        config={
            "max_concurrency": 5,
            "timeout": 5,
            "use_nuclei": False,
            "use_ollama": True,
            "ollama_model": "llama3",
            "use_community_fingerprints": False,
        },
    )
    assert len(results) == 1
    assert results[0].php_version == "7.3.12"
    assert results[0].llm_summary is not None


@pytest.mark.asyncio
async def test_scanner_live_callback(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url="https://httpbin.org",
        text="PHP Version 7.4.33",
        headers={"X-Powered-By": "PHP/7.4.33"},
        status_code=200,
    )

    collected = []

    def live_callback(result: ScanResult) -> None:
        collected.append(result)

    await scan_targets(
        ["https://httpbin.org"],
        config={
            "max_concurrency": 5,
            "timeout": 5,
            "use_nuclei": False,
            "use_ollama": False,
        },
        callback=live_callback,
    )

    assert len(collected) == 1
    assert collected[0].php_version == "7.4.33"


@pytest.mark.asyncio
async def test_scanner_with_schema(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url="https://httpbin.org",
        text='<a href="backup.sql">dump</a>',
        status_code=200,
    )
    httpx_mock.add_response(
        url="https://httpbin.org/backup.sql",
        text="CREATE TABLE users (id INT, password TEXT);",
        status_code=200,
    )

    results = await scan_targets(
        ["https://httpbin.org"],
        config={
            "max_concurrency": 5,
            "timeout": 5,
            "use_nuclei": False,
            "use_ollama": False,
            "use_community_fingerprints": False,
        },
    )
    assert len(results) == 1
    assert len(results[0].exposed_files) == 1
    assert results[0].exposed_files[0].file_type == "sql_dump"
    assert results[0].db_schema is not None
    assert "users" in results[0].db_schema.tables


@pytest.mark.asyncio
async def test_scan_error_handling(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url="https://bad.example.com",
        status_code=500,
    )

    results = await scan_targets(
        ["https://bad.example.com"],
        config={
            "max_concurrency": 5,
            "timeout": 5,
            "use_nuclei": False,
            "use_ollama": False,
        },
    )
    assert len(results) == 1
    assert len(results[0].errors) > 0
    assert results[0].php_version is None


@pytest.mark.asyncio
async def test_scan_targets(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url="http://example.com",
        text="PHP Version 5.6.40",
        headers={"X-Powered-By": "PHP/5.6.40"},
        status_code=200,
    )
    httpx_mock.add_response(
        url="https://httpbin.org",
        text="<h1>PHP Version 8.2.0</h1>",
        headers={"Server": "PHP/8.2.0"},
        status_code=200,
    )

    results = await scan_targets(
        ["http://example.com", "https://httpbin.org"],
        config={
            "max_concurrency": 10,
            "timeout": 5,
            "proxies": None,  # explicitly test that empty proxies are omitted
            "use_nuclei": False,
            "use_ollama": False,
            "use_community_fingerprints": False,
        },
    )

    assert len(results) == 2
    versions = {r.php_version for r in results if r.php_version}
    assert "5.6.40" in versions
    assert "8.2.0" in versions


def test_async_scanner_with_proxies(httpx_mock: HTTPXMock):
    """Explicit test for the new proxy code path (list is passed)."""
    httpx_mock.add_response(
        url="http://example.com",
        text="PHP/7.4",
        status_code=200,
    )

    scanner = AsyncScanner(
        config={
            "proxies": ["http://proxy.example.com:8080"],
            "max_concurrency": 5,
            "timeout": 5,
        }
    )
    results = asyncio.run(scanner.scan(["http://example.com"]))
    assert len(results) == 1
    assert results[0].php_version is not None
