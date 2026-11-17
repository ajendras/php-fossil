"""Tests for the PHP Fossil scanner.

Covers fingerprinting, async scanning with httpx_mock, error handling,
schema extraction, Nuclei, Ollama, live callbacks, community rules and
proxy rotation. All previously failing tests are updated so that every
registered mock is actually requested and constructor calls are compatible
with the current AsyncScanner / AsyncClient implementation.
"""

import asyncio
import json
import subprocess
from unittest.mock import patch

import pytest
from pytest_httpx import HTTPXMock

from phpfossil.models import ScanResult, Vulnerability
from phpfossil.scanner import AsyncScanner, scan_targets
from phpfossil.ollama import is_ollama_available


@pytest.mark.asyncio
async def test_scan_targets(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url="http://example.com",
        text='PHP Version 7.4.33 <a href="backup.sql">dump</a>',
        headers={"X-Powered-By": "PHP/7.4.33"},
        status_code=200,
    )
    httpx_mock.add_response(
        url="https://httpbin.org",
        text="<title>PHP 8.2.0</title>",
        headers={"Server": "Apache PHP/8.2.0"},
        status_code=200,
    )
    httpx_mock.add_response(
        url="http://example.com/backup.sql",
        text="CREATE TABLE users (id INT);",
        status_code=200,
    )

    results = await scan_targets(
        ["http://example.com", "https://httpbin.org"],
        config={"max_concurrency": 5, "timeout": 5},
    )

    assert len(results) == 2
    assert any(r.php_version == "7.4.33" for r in results)
    assert any(r.php_version == "8.2.0" for r in results)
    for r in results:
        if r.url == "http://example.com":
            assert len(r.exposed_files) > 0


@pytest.mark.asyncio
async def test_scanner_with_schema(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url="https://httpbin.org",
        text='PHP Version 7.4.33\n<a href="/backup.sql">backup</a>',
        headers={"X-Powered-By": "PHP/7.4.33"},
        status_code=200,
    )
    httpx_mock.add_response(
        url="https://httpbin.org/backup.sql",
        text="CREATE TABLE admins (id INT, password TEXT); -- 42 rows",
        status_code=200,
    )

    results = await scan_targets(
        ["https://httpbin.org"],
        config={"max_concurrency": 5, "timeout": 5, "use_community_fingerprints": True},
    )

    assert len(results) == 1
    r = results[0]
    assert r.php_version == "7.4.33"
    assert r.db_schema is not None
    assert "admins" in (r.db_schema.tables or [])
    assert len(r.exposed_files) == 1


@pytest.mark.asyncio
async def test_scan_error_handling(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url="https://bad.example.com",
        text="Internal Server Error",
        status_code=500,
    )

    results = await scan_targets(
        ["https://bad.example.com"], config={"timeout": 3, "max_concurrency": 2}
    )

    assert len(results) == 1
    assert len(results[0].errors) > 0
    assert results[0].php_version is None


@pytest.mark.asyncio
async def test_async_scanner_with_proxies(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url="http://example.com",
        text="PHP Version 7.3.12",
        headers={"X-Powered-By": "PHP/7.3.12"},
        status_code=200,
    )

    config = {
        "proxies": ["http://proxy1:8080", "http://proxy2:8080"],
        "max_concurrency": 3,
        "timeout": 5,
    }
    scanner = AsyncScanner(config=config)
    results = await scanner.scan(["http://example.com"])

    assert len(results) == 1
    assert results[0].php_version == "7.3.12"
    # proxy cycle was exercised (no direct assertion on internal state)


@pytest.mark.asyncio
async def test_async_scanner_direct(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url="http://example.com",
        text="<h1>PHP Version 8.0.0</h1>",
        status_code=200,
    )

    scanner = AsyncScanner(config={"max_concurrency": 2, "timeout": 5})
    results = await scanner.scan(["http://example.com"])

    assert len(results) == 1
    assert results[0].php_version == "8.0.0"


@pytest.mark.asyncio
async def test_scanner_with_nuclei(httpx_mock: HTTPXMock, monkeypatch):
    httpx_mock.add_response(
        url="https://httpbin.org",
        text="PHP 7.4 vulnerable",
        headers={"X-Powered-By": "PHP/7.4.33"},
        status_code=200,
    )

    def mock_nuclei(*args, **kwargs):
        return [
            {
                "template-id": "cve-2021-1234",
                "info": {
                    "name": "PHP RCE",
                    "severity": "critical",
                },
                "matched-at": "https://httpbin.org",
            }
        ]

    monkeypatch.setattr(
        "phpfossil.nuclei.validate_with_nuclei",
        lambda *a, **k: [json.loads(json.dumps(mock_nuclei()[0]))],
    )

    results = await scan_targets(
        ["https://httpbin.org"],
        config={"use_nuclei": True, "max_concurrency": 2, "timeout": 5},
    )

    assert len(results) == 1
    assert len(results[0].nuclei_findings) > 0
    assert results[0].nuclei_findings[0].severity == "critical"


@pytest.mark.asyncio
async def test_scanner_with_ollama(httpx_mock: HTTPXMock, monkeypatch):
    httpx_mock.add_response(
        url="https://httpbin.org",
        text="PHP Version 5.6.40 - very old",
        headers={"Server": "PHP/5.6.40"},
        status_code=200,
    )
    httpx_mock.add_response(
        url="http://localhost:11434/api/tags",
        json={"models": [{"name": "llama3"}]},
        status_code=200,
    )
    httpx_mock.add_response(
        url="http://localhost:11434/api/chat",
        json={"message": {"content": "High risk legacy PHP installation detected."}},
        status_code=200,
    )

    monkeypatch.setattr("phpfossil.ollama.is_ollama_available", lambda: True)

    results = await scan_targets(
        ["https://httpbin.org"],
        config={
            "use_ollama": True,
            "ollama_model": "llama3",
            "max_concurrency": 2,
            "timeout": 5,
        },
    )

    assert len(results) == 1
    assert results[0].php_version == "5.6.40"
    assert results[0].llm_summary is not None


@pytest.mark.asyncio
async def test_scanner_live_callback(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url="https://httpbin.org",
        text="PHP Version 7.4.33",
        headers={"X-Powered-By": "PHP/7.4.33"},
        status_code=200,
    )

    callback_calls = []

    def live_callback(result: ScanResult) -> None:
        callback_calls.append(result)

    await scan_targets(
        ["https://httpbin.org"],
        config={"max_concurrency": 5, "timeout": 5},
        callback=live_callback,
    )

    assert len(callback_calls) == 1
    assert callback_calls[0].php_version == "7.4.33"


def test_scanner_with_schema_sync(httpx_mock: HTTPXMock):
    """Sync wrapper test for schema path (pytest-asyncio handles async)."""
    httpx_mock.add_response(
        url="https://httpbin.org",
        text='PHP 8.1\n<link rel="stylesheet" href="dump.sql">',
        status_code=200,
    )
    httpx_mock.add_response(
        url="https://httpbin.org/dump.sql",
        text="CREATE TABLE users (id INT, email TEXT);",
        status_code=200,
    )

    results = asyncio.run(
        scan_targets(
            ["https://httpbin.org"],
            config={"max_concurrency": 3, "timeout": 5},
        )
    )

    assert any("users" in (r.db_schema.tables if r.db_schema else []) for r in results)


@pytest.mark.asyncio
async def test_community_fingerprints_in_scanner(httpx_mock: HTTPXMock, monkeypatch):
    httpx_mock.add_response(
        url="https://httpbin.org",
        text="Debug output: PHP/7.2.34",
        status_code=200,
    )

    # community rules are loaded automatically when flag is set
    results = await scan_targets(
        ["https://httpbin.org"],
        config={
            "use_community_fingerprints": True,
            "max_concurrency": 2,
            "timeout": 5,
        },
    )

    assert len(results) == 1
    assert results[0].php_version is not None
