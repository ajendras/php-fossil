"""Tests for the PHP Fossil scanner, AsyncScanner, live callbacks,
schema extraction, error handling, Nuclei/Ollama integration and
community fingerprint support. Uses pytest-httpx for HTTP mocking
and pytest-asyncio for async tests."""

import asyncio
from unittest.mock import patch, MagicMock

import httpx
import pytest
from pytest_httpx import HTTPXMock

from phpfossil import (
    scan_targets,
    ScanResult,
    Vulnerability,
    NucleiFinding,
    SchemaResult,
    ExposedFile,
)
from phpfossil.scanner import AsyncScanner
from phpfossil.fingerprinter import CommunityFingerprinter, load_community_fingerprints
from phpfossil.models import FingerprintRule


@pytest.fixture
def live_callback():
    """Fixture for live callback tests."""
    return MagicMock()


def test_scanner_with_schema(httpx_mock: HTTPXMock):
    """Test schema extraction when an SQL dump is discovered."""
    httpx_mock.assert_all_requests_are_fired = False
    httpx_mock.add_response(
        url="https://httpbin.org",
        text="<h1>PHP Version 7.4.33</h1>",
        headers={"X-Powered-By": "PHP/7.4.33"},
        status_code=200,
    )
    httpx_mock.add_response(
        url="https://httpbin.org/backup.sql",
        text="CREATE TABLE users (id INT, email VARCHAR(255));\nINSERT INTO users VALUES (1, 'test@example.com');",
        status_code=200,
    )

    results = asyncio.run(
        scan_targets(
            ["https://httpbin.org"],
            config={
                "max_concurrency": 5,
                "timeout": 10,
                "use_nuclei": False,
                "use_ollama": False,
                "use_community_fingerprints": False,
            },
        )
    )

    assert len(results) == 1
    result: ScanResult = results[0]
    assert result.php_version == "7.4.33"
    assert result.detected_from
    assert result.db_schema is not None
    assert "users" in result.db_schema.tables
    assert result.risk_score > 35
    assert any(f.file_type == "sql_dump" for f in result.exposed_files)


def test_scan_error_handling(httpx_mock: HTTPXMock):
    """Test graceful error handling when a target is unreachable."""
    httpx_mock.assert_all_requests_are_fired = False
    httpx_mock.add_exception(
        httpx.ConnectError("Connection refused"),
        url="https://bad.example.com",
    )

    results = asyncio.run(
        scan_targets(
            ["https://bad.example.com"],
            config={
                "max_concurrency": 5,
                "timeout": 5,
                "use_nuclei": False,
                "use_ollama": False,
            },
        )
    )

    assert len(results) == 1
    result: ScanResult = results[0]
    assert result.url == "https://bad.example.com"
    assert result.php_version is None
    assert len(result.errors) > 0
    assert not result.is_vulnerable()


@pytest.mark.asyncio
async def test_async_scanner_with_proxies(httpx_mock: HTTPXMock):
    """Test AsyncScanner with proxy configuration."""
    httpx_mock.assert_all_requests_are_fired = False
    httpx_mock.add_response(
        url="http://example.com",
        text="PHP Version 8.1.0",
        headers={"Server": "Apache/2.4 PHP/8.1.0"},
        status_code=200,
    )

    config = {
        "max_concurrency": 10,
        "timeout": 10,
        "proxies": ["http://proxy.example.com:8080"],
        "use_nuclei": False,
        "use_ollama": False,
        "use_community_fingerprints": False,
    }

    scanner = AsyncScanner(config=config)
    result = await scanner._probe_target("http://example.com")

    assert result.php_version == "8.1.0"
    assert "headers" in result.detected_from


@pytest.mark.asyncio
async def test_async_scanner_direct(httpx_mock: HTTPXMock):
    """Test direct usage of AsyncScanner without the public scan_targets wrapper."""
    httpx_mock.assert_all_requests_are_fired = False
    httpx_mock.add_response(
        url="http://example.com",
        text="<title>PHP 7.4.33 - Info</title>",
        status_code=200,
    )

    scanner = AsyncScanner(
        config={
            "max_concurrency": 5,
            "timeout": 10,
            "use_nuclei": False,
            "use_ollama": False,
        }
    )
    result = await scanner._probe_target("http://example.com")

    assert result.url == "http://example.com"
    assert result.php_version == "7.4.33"
    assert len(result.vulns) > 0


def test_scanner_with_nuclei(httpx_mock: HTTPXMock):
    """Test integration with Nuclei for exploit validation."""
    httpx_mock.assert_all_requests_are_fired = False
    httpx_mock.add_response(
        url="https://httpbin.org",
        text="PHP Version 7.4.33",
        headers={"X-Powered-By": "PHP/7.4.33"},
        status_code=200,
    )

    with patch("phpfossil.scanner.validate_with_nuclei") as mock_validate:
        mock_validate.return_value = [
            NucleiFinding(
                template="cve-2021-1234",
                name="PHP RCE",
                severity="critical",
                matched_at="https://httpbin.org",
            )
        ]

        results = asyncio.run(
            scan_targets(
                ["https://httpbin.org"],
                config={
                    "max_concurrency": 5,
                    "timeout": 10,
                    "use_nuclei": True,
                    "use_ollama": False,
                    "use_community_fingerprints": False,
                },
            )
        )

    assert len(results) == 1
    result: ScanResult = results[0]
    assert result.php_version == "7.4.33"
    assert len(result.nuclei_findings) == 1
    assert result.nuclei_findings[0].severity == "critical"
    assert result.has_nuclei_confirmations()
    assert result.risk_score > 50


def test_scanner_with_ollama(httpx_mock: HTTPXMock):
    """Test Ollama LLM summarization integration."""
    httpx_mock.assert_all_requests_are_fired = False
    httpx_mock.add_response(
        url="https://httpbin.org",
        text="PHP Version 5.6.40 - vulnerable",
        headers={"X-Powered-By": "PHP/5.6.40"},
        status_code=200,
    )
    httpx_mock.add_response(
        url="http://localhost:11434/api/tags",
        json={"models": [{"name": "llama3"}]},
        status_code=200,
    )
    httpx_mock.add_response(
        url="http://localhost:11434/api/chat",
        json={"message": {"content": "This legacy PHP 5.6 instance has multiple critical CVEs."}},
        status_code=200,
    )

    results = asyncio.run(
        scan_targets(
            ["https://httpbin.org"],
            config={
                "max_concurrency": 5,
                "timeout": 10,
                "use_nuclei": False,
                "use_ollama": True,
                "ollama_model": "llama3",
                "use_community_fingerprints": False,
            },
        )
    )

    assert len(results) == 1
    result: ScanResult = results[0]
    assert result.php_version == "5.6.40"
    assert result.llm_summary is not None
    assert "critical" in result.llm_summary.lower()


def test_scanner_live_callback(httpx_mock: HTTPXMock, live_callback):
    """Test live callback functionality for TUI and real-time updates."""
    httpx_mock.assert_all_requests_are_fired = False
    httpx_mock.add_response(
        url="https://httpbin.org",
        text="PHP Version 7.4.33",
        headers={"X-Powered-By": "PHP/7.4.33"},
        status_code=200,
    )

    results = asyncio.run(
        scan_targets(
            ["https://httpbin.org"],
            config={
                "max_concurrency": 5,
                "timeout": 10,
                "use_nuclei": False,
                "use_ollama": False,
                "use_community_fingerprints": False,
            },
            callback=live_callback,
        )
    )

    assert len(results) == 1
    live_callback.assert_called_once()
    args, _ = live_callback.call_args
    assert isinstance(args[0], ScanResult)
    assert args[0].php_version == "7.4.33"


def test_scanner_with_schema_sync(httpx_mock: HTTPXMock):
    """Test schema extraction in a synchronous wrapper context."""
    httpx_mock.assert_all_requests_are_fired = False
    httpx_mock.add_response(
        url="https://httpbin.org",
        text="PHP Version 7.4.33",
        headers={"X-Powered-By": "PHP/7.4.33"},
        status_code=200,
    )
    httpx_mock.add_response(
        url="https://httpbin.org/dump.sql",
        text="CREATE TABLE admins (id INT, password VARCHAR(255));",
        status_code=200,
    )

    # Simulate sync call (real usage wraps with asyncio.run)
    results = asyncio.run(
        scan_targets(
            ["https://httpbin.org"],
            config={
                "max_concurrency": 5,
                "timeout": 10,
                "use_nuclei": False,
                "use_ollama": False,
                "use_community_fingerprints": False,
            },
        )
    )

    assert len(results) == 1
    result: ScanResult = results[0]
    assert result.db_schema is not None
    assert "admins" in result.db_schema.tables
    assert any(
        f.file_type == "sql_dump" and "dump.sql" in f.url
        for f in result.exposed_files
    )


def test_community_fingerprints_in_scanner(httpx_mock: HTTPXMock):
    """Test community fingerprint rules are loaded and applied during scanning."""
    httpx_mock.assert_all_requests_are_fired = False
    # Mock community repo (falls back gracefully but we ensure cache path is exercised)
    httpx_mock.add_response(
        url="https://raw.githubusercontent.com/ajendras/php-fossil/main/community-fingerprints.json",
        json=[
            {
                "type": "body",
                "pattern": r"PHP Version[:\s]+(\d+\.\d+\.\d+)",
                "version_group": 1,
            }
        ],
        status_code=200,
    )
    httpx_mock.add_response(
        url="https://httpbin.org",
        text="Debug output: PHP Version: 7.2.24",
        status_code=200,
    )

    config = {
        "max_concurrency": 5,
        "timeout": 10,
        "use_nuclei": False,
        "use_ollama": False,
        "use_community_fingerprints": True,
    }

    results = asyncio.run(scan_targets(["https://httpbin.org"], config=config))

    assert len(results) == 1
    result: ScanResult = results[0]
    assert result.php_version == "7.2.24"
    assert "community" in result.detected_from or any(
        "community" in src for src in result.detected_from
    )


# Additional coverage for core scanner behaviors
def test_scanner_empty_targets():
    """Edge case: empty target list returns empty results."""
    results = asyncio.run(scan_targets([]))
    assert results == []


def test_scanner_vuln_mapping():
    """Ensure detected PHP version maps to expected vulnerabilities."""
    httpx_mock = pytest.importorskip("pytest_httpx").HTTPXMock()
    httpx_mock.assert_all_requests_are_fired = False
    httpx_mock.add_response(
        url="https://httpbin.org",
        text="PHP/5.6.40",
        headers={"X-Powered-By": "PHP/5.6.40"},
        status_code=200,
    )

    results = asyncio.run(
        scan_targets(
            ["https://httpbin.org"],
            config={
                "max_concurrency": 5,
                "timeout": 10,
                "use_nuclei": False,
                "use_ollama": False,
                "use_community_fingerprints": False,
            },
        )
    )

    assert len(results) == 1
    result = results[0]
    assert result.php_version == "5.6.40"
    assert len(result.vulns) > 0
    assert any(v.severity in ("high", "critical") for v in result.vulns)
