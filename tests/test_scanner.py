"""Tests for the PHP Fossil async scanner.

Covers integration with fingerprinter, exposed file & schema detection,
Nuclei/Ollama post-processing (via mocks), live callbacks, error handling
and persistence. Updated to register all additional probe requests that
the scanner performs (phpinfo.php, .env, backup.sql, random nonexistent
PHP file for error-page fingerprinting).
"""

import asyncio
import re
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from pytest_httpx import HTTPXMock

from phpfossil.models import ScanResult
from phpfossil.scanner import AsyncScanner, scan_targets
from phpfossil.store import Store


@pytest.mark.asyncio
async def test_scan_targets(httpx_mock: HTTPXMock) -> None:
    """Test full scan_targets with realistic mocks for all probed paths.

    The scanner issues GETs to a set of common sensitive paths on every
    target plus a random nonexistent-*.php to trigger error-page version
    leakage. All must be registered or the pytest-httpx strict checker fails.
    """
    # Main target responses (used by detect_from_headers/body/phpinfo)
    httpx_mock.add_response(
        url="https://httpbin.org",
        text="<h1>PHP Version 7.4.33</h1>",
        headers={"X-Powered-By": "PHP/7.4.33"},
        status_code=200,
    )
    httpx_mock.add_response(
        url="http://example.com",
        text="Example Domain - no version leak",
        headers={},
        status_code=200,
    )

    # All additional probe paths the scanner exercises
    common_probes = [
        "/phpinfo.php",
        "/info.php",
        "/test.php",
        "/.env",
        "/backup.sql",
    ]

    for base_url in ("https://httpbin.org", "http://example.com"):
        for path in common_probes:
            url = base_url + path
            if "phpinfo" in path or "info.php" in path:
                httpx_mock.add_response(
                    url=url,
                    text="PHP Version 7.4.33\nphpinfo()",
                    status_code=200,
                )
            elif ".env" in path:
                httpx_mock.add_response(
                    url=url,
                    text="DB_PASSWORD=secret123\nAPP_ENV=prod",
                    status_code=200,
                )
            elif "backup.sql" in path or "test.php" in path:
                httpx_mock.add_response(
                    url=url,
                    text="-- MySQL dump\nCREATE TABLE users;",
                    status_code=200,
                )
            else:
                httpx_mock.add_response(url=url, status_code=404)

    # The random nonexistent file used for error-page fingerprinting.
    # Because the numeric suffix is random we use a regex matcher.
    httpx_mock.add_response(
        url=re.compile(r"http://example\.com/nonexistent-\d+\.php"),
        text="PHP Parse error: ... (PHP 7.3.12)",
        status_code=500,
    )
    httpx_mock.add_response(
        url=re.compile(r"https://httpbin\.org/nonexistent-\d+\.php"),
        status_code=404,
    )

    results: list[ScanResult] = await scan_targets(
        ["https://httpbin.org", "http://example.com"],
        config={
            "max_concurrency": 5,
            "timeout": 5,
            "use_nuclei": False,
            "use_ollama": False,
        },
    )

    assert len(results) == 2
    httpbin = next(r for r in results if "httpbin" in r.url.lower())
    assert httpbin.php_version == "7.4.33"
    assert "headers" in httpbin.detected_from or "body" in httpbin.detected_from
    assert len(httpbin.exposed_files) >= 2  # at least phpinfo + .env or sql
    assert httpbin.risk_score >= 35

    example = next(r for r in results if "example.com" in r.url.lower())
    assert isinstance(example.errors, list)
    # The error page on the nonexistent file may have contributed a version
    assert example.php_version is None or "7.3" in (example.php_version or "")


@pytest.mark.asyncio
async def test_scanner_live_callback(httpx_mock: HTTPXMock) -> None:
    """Live callback (used by TUI) is invoked for every finished target."""
    httpx_mock.add_response(
        url="https://httpbin.org",
        text="PHP Version 8.1.0",
        headers={"Server": "PHP/8.1.0"},
        status_code=200,
    )
    for p in ("/phpinfo.php", "/.env", "/backup.sql"):
        httpx_mock.add_response(
            url=f"https://httpbin.org{p}",
            text="mocked content",
            status_code=200,
        )
    httpx_mock.add_response(
        url=re.compile(r"https://httpbin\.org/nonexistent-\d+\.php"),
        status_code=404,
    )

    calls: list[ScanResult] = []

    def cb(result: ScanResult) -> None:
        calls.append(result)

    await scan_targets(
        ["https://httpbin.org"],
        config={
            "max_concurrency": 5,
            "timeout": 5,
            "use_nuclei": False,
            "use_ollama": False,
        },
        callback=cb,
    )

    assert len(calls) == 1
    assert calls[0].php_version == "8.1.0"


@patch("phpfossil.scanner.validate_with_nuclei")
@pytest.mark.asyncio
async def test_scanner_with_nuclei(
    mock_validate: MagicMock, httpx_mock: HTTPXMock
) -> None:
    """Nuclei integration path (subprocess mocked)."""
    mock_validate.return_value = [
        {
            "template": "cve-2019-11043",
            "name": "PHP CGI RCE",
            "severity": "critical",
        }
    ]

    httpx_mock.add_response(
        url="https://httpbin.org",
        text="PHP Version 7.2.0",
        status_code=200,
    )
    for p in ("/phpinfo.php", "/.env", "/backup.sql"):
        httpx_mock.add_response(url=f"https://httpbin.org{p}", status_code=404)
    httpx_mock.add_response(
        url=re.compile(r"https://httpbin\.org/nonexistent-\d+\.php"),
        status_code=404,
    )

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
    assert len(results[0].nuclei_findings) == 1
    assert results[0].nuclei_findings[0].severity == "critical"
    mock_validate.assert_called_once()


@patch("phpfossil.scanner.generate_summary")
@pytest.mark.asyncio
async def test_scanner_with_ollama(
    mock_summary: MagicMock, httpx_mock: HTTPXMock
) -> None:
    """Ollama summarization path (HTTP calls to localhost mocked by httpx)."""
    mock_summary.return_value = "# High Risk\nLegacy PHP 5.6 detected."

    httpx_mock.add_response(
        url="https://httpbin.org",
        text="PHP Version 5.6.40",
        status_code=200,
    )
    for p in ("/phpinfo.php", "/.env", "/backup.sql"):
        httpx_mock.add_response(url=f"https://httpbin.org{p}", status_code=200)
    httpx_mock.add_response(
        url=re.compile(r"https://httpbin\.org/nonexistent-\d+\.php"),
        status_code=404,
    )

    results = await scan_targets(
        ["https://httpbin.org"],
        config={
            "max_concurrency": 5,
            "timeout": 5,
            "use_nuclei": False,
            "use_ollama": True,
        },
    )

    assert len(results) == 1
    assert results[0].llm_summary == "# High Risk\nLegacy PHP 5.6 detected."
    mock_summary.assert_called_once()


def test_async_scanner_config() -> None:
    """Configuration defaults and capping."""
    scanner = AsyncScanner(
        {"max_concurrency": 100, "timeout": 30, "use_nuclei": True, "proxies": ["http://proxy"]}
    )
    assert scanner.max_concurrency == 50  # enforced cap
    assert scanner.timeout == 30
    assert scanner.use_nuclei is True
    assert len(scanner.proxies) == 1


@pytest.mark.asyncio
async def test_scan_error_handling(httpx_mock: HTTPXMock) -> None:
    """Scanner records errors when a target is unreachable."""
    httpx_mock.add_response(url="https://bad.example", status_code=500)
    for p in ("/phpinfo.php", "/.env"):
        httpx_mock.add_response(url=f"https://bad.example{p}", status_code=500)
    httpx_mock.add_response(
        url=re.compile(r"https://bad\.example/nonexistent-\d+\.php"),
        status_code=500,
    )

    results = await scan_targets(
        ["https://bad.example"],
        config={"max_concurrency": 5, "timeout": 5, "use_nuclei": False, "use_ollama": False},
    )

    assert len(results) == 1
    assert len(results[0].errors) > 0
    assert results[0].php_version is None
