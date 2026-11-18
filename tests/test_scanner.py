"""Tests for the PHP Fossil scanner module.

Covers schema extraction, error handling, proxies, Nuclei, Ollama, live callbacks,
community fingerprints and the AsyncScanner class. All HTTP mocks are exercised
so pytest-httpx does not complain about unused responses.
"""

import asyncio
import json
from unittest.mock import patch

import pytest

from phpfossil.models import ScanResult
from phpfossil.scanner import AsyncScanner, scan_targets


@pytest.mark.asyncio
async def test_scanner_with_schema(httpx_mock):
    """Test schema extraction from exposed SQL dump."""
    httpx_mock.add_response(
        url="https://httpbin.org",
        text='<html>PHP Version 7.4.33<br><a href="backup.sql">Download Backup</a></html>',
        headers={"X-Powered-By": "PHP/7.4.33"},
    )
    httpx_mock.add_response(
        url="https://httpbin.org/backup.sql",
        text="""CREATE TABLE users (id INT, username VARCHAR(50));
INSERT INTO users VALUES (1, 'admin');""",
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
    r = results[0]
    assert r.php_version == "7.4.33"
    assert r.db_schema is not None
    assert "users" in r.db_schema.tables
    assert len(r.exposed_files) > 0
    assert any("backup.sql" in f.url for f in r.exposed_files)


@pytest.mark.asyncio
async def test_scan_error_handling(httpx_mock):
    """Test graceful handling of network and HTTP errors."""
    httpx_mock.add_response(
        url="https://bad.example.com",
        status_code=503,
        text="Service Unavailable",
    )
    results = await scan_targets(
        ["https://bad.example.com"],
        config={"timeout": 5, "max_concurrency": 5},
    )
    assert len(results) == 1
    r = results[0]
    assert len(r.errors) > 0
    assert r.php_version is None


@pytest.mark.asyncio
async def test_async_scanner_with_proxies(httpx_mock):
    """Test scanning with proxy configuration."""
    httpx_mock.add_response(
        url="http://example.com",
        text="PHP Version 5.6.40",
        headers={"Server": "nginx PHP/5.6.40"},
    )
    config = {
        "max_concurrency": 5,
        "timeout": 5,
        "proxies": ["http://127.0.0.1:8080"],
        "use_nuclei": False,
        "use_ollama": False,
    }
    results = await scan_targets(["http://example.com"], config=config)
    assert len(results) == 1
    assert results[0].php_version == "5.6.40"


@pytest.mark.asyncio
async def test_async_scanner_direct(httpx_mock):
    """Test direct async scanning without extra features."""
    httpx_mock.add_response(
        url="http://example.com",
        text="<title>Example</title><h1>PHP 8.2.0</h1>",
        headers={"X-Powered-By": "PHP/8.2.0"},
    )
    results = await scan_targets(
        ["http://example.com"],
        config={
            "max_concurrency": 5,
            "timeout": 5,
            "use_nuclei": False,
            "use_ollama": False,
        },
    )
    assert len(results) == 1
    assert results[0].php_version == "8.2.0"


@pytest.mark.asyncio
async def test_scanner_with_nuclei(httpx_mock):
    """Test integration with Nuclei for exploit validation."""
    httpx_mock.add_response(
        url="https://httpbin.org",
        text="PHP Version 7.4.33",
        headers={"X-Powered-By": "PHP/7.4.33"},
    )
    nuclei_output = (
        '{"template":"cve-2019-11043","name":"PHP CGI Argument Injection",'
        '"severity":"critical","matched-at":"https://httpbin.org"}\n'
    )
    with patch("phpfossil.nuclei.subprocess.run") as mock_run:
        mock_run.return_value.stdout = nuclei_output
        mock_run.return_value.stderr = ""
        results = await scan_targets(
            ["https://httpbin.org"],
            config={
                "max_concurrency": 5,
                "timeout": 5,
                "use_nuclei": True,
                "use_ollama": False,
            },
        )
    assert len(results) == 1
    r = results[0]
    assert r.php_version == "7.4.33"
    assert len(r.nuclei_findings) > 0
    assert any(f.severity == "critical" for f in r.nuclei_findings)


@pytest.mark.asyncio
async def test_scanner_with_ollama(httpx_mock):
    """Test Ollama LLM summary generation."""
    httpx_mock.add_response(
        url="https://httpbin.org",
        text="PHP Version 7.3.12 - vulnerable",
        headers={"X-Powered-By": "PHP/7.3.12"},
    )
    httpx_mock.add_response(
        url="http://localhost:11434/api/tags",
        json={"models": [{"name": "llama3"}]},
    )
    httpx_mock.add_response(
        url="http://localhost:11434/api/chat",
        json={
            "model": "llama3",
            "message": {
                "content": (
                    "This target is using an EOL PHP version with multiple "
                    "high severity CVEs. Immediate upgrade to PHP 8.2+ is recommended."
                )
            },
        },
    )
    results = await scan_targets(
        ["https://httpbin.org"],
        config={
            "max_concurrency": 5,
            "timeout": 5,
            "use_nuclei": False,
            "use_ollama": True,
            "ollama_model": "llama3",
        },
    )
    assert len(results) == 1
    r = results[0]
    assert r.php_version == "7.3.12"
    assert r.llm_summary is not None
    assert "upgrade" in r.llm_summary.lower() or "eol" in r.llm_summary.lower()


@pytest.mark.asyncio
async def test_scanner_live_callback(httpx_mock):
    """Test live callback during scanning."""
    httpx_mock.add_response(
        url="https://httpbin.org",
        text="PHP Version 7.4.33",
        headers={"X-Powered-By": "PHP/7.4.33"},
    )

    callback_calls = []

    def live_callback(result: ScanResult) -> None:
        callback_calls.append(result)

    results = await scan_targets(
        ["https://httpbin.org"],
        config={
            "max_concurrency": 5,
            "timeout": 5,
            "use_nuclei": False,
            "use_ollama": False,
        },
        callback=live_callback,
    )
    assert len(results) == 1
    assert len(callback_calls) == 1
    assert callback_calls[0].php_version == "7.4.33"


@pytest.mark.asyncio
async def test_scanner_with_schema_sync(httpx_mock):
    """Test schema extraction using sync-like flow (still async under the hood)."""
    httpx_mock.add_response(
        url="https://httpbin.org",
        text="PHP 7.2.0 <a href='/dump.sql'>SQL Dump</a>",
        headers={"X-Powered-By": "PHP/7.2.0"},
    )
    httpx_mock.add_response(
        url="https://httpbin.org/dump.sql",
        text="CREATE TABLE admins (id INT, pass VARCHAR(255));",
    )
    results = await scan_targets(
        ["https://httpbin.org"],
        config={
            "max_concurrency": 5,
            "timeout": 5,
            "use_nuclei": False,
            "use_ollama": False,
        },
    )
    assert len(results) == 1
    r = results[0]
    assert r.php_version == "7.2.0"
    assert r.db_schema is not None
    assert any("admins" in t.lower() for t in r.db_schema.tables)


@pytest.mark.asyncio
async def test_community_fingerprints_in_scanner(httpx_mock):
    """Test community fingerprint rules are loaded and applied in scanner."""
    community_json = [
        {
            "type": "body",
            "pattern": r"PHP Version[:\s]+(\d+\.\d+\.\d+)",
            "version_group": 1,
            "description": "Generic PHP version in body",
        }
    ]
    httpx_mock.add_response(
        url="https://raw.githubusercontent.com/ajendras/php-fossil/main/community-fingerprints.json",
        json=community_json,
    )
    httpx_mock.add_response(
        url="https://httpbin.org",
        text="Debug info: PHP Version: 7.1.33",
        headers={},
    )
    results = await scan_targets(
        ["https://httpbin.org"],
        config={
            "max_concurrency": 5,
            "timeout": 5,
            "use_nuclei": False,
            "use_ollama": False,
            "use_community_fingerprints": True,
        },
    )
    assert len(results) == 1
    r = results[0]
    assert r.php_version == "7.1.33"
    assert r.detected_from


@pytest.mark.asyncio
async def test_async_scanner_class(httpx_mock):
    """Test AsyncScanner class directly (used by several test names)."""
    httpx_mock.add_response(
        url="https://httpbin.org",
        text="PHP/7.4",
        headers={"X-Powered-By": "PHP/7.4.33"},
    )
    scanner = AsyncScanner(
        config={
            "max_concurrency": 10,
            "timeout": 10,
            "use_nuclei": False,
            "use_ollama": False,
        }
    )
    results = await scanner.scan(["https://httpbin.org"])
    assert len(results) == 1
    assert results[0].php_version == "7.4.33"
