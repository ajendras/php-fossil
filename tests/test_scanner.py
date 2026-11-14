"""Tests for the PHP Fossil scanner.

Covers async scanning, fingerprinting vectors, error handling, live callbacks,
Nuclei integration (mocked), Ollama integration (mocked) and HTTP mocking
via pytest-httpx. All tests are marked async and use await to avoid
RuntimeError from asyncio.run() inside a running event loop and to ensure
the coroutine executes (preventing "never awaited" warnings).
"""

import re
from unittest.mock import patch

import pytest
from pytest_httpx import HTTPXMock

from phpfossil.models import ScanResult
from phpfossil.scanner import AsyncScanner, scan_targets


@pytest.fixture(autouse=True)
def mock_nuclei_validation():
    """Prevent real subprocess calls to nuclei in CI."""
    with patch("phpfossil.scanner.validate_with_nuclei", return_value=[]):
        yield


@pytest.mark.asyncio
async def test_scan_targets(httpx_mock: HTTPXMock):
    """Basic scan with two targets; version found from primary responses."""
    httpx_mock.add_response(
        url="http://example.com",
        text="<title>Example</title><p>PHP Version 7.4.33</p>",
        headers={"X-Powered-By": "PHP/7.4.33"},
    )
    httpx_mock.add_response(
        url="https://httpbin.org",
        text="<html>No version leak here</html>",
        headers={},
    )
    # One error-page probe will be triggered for the second target
    httpx_mock.add_response(
        url=re.compile(r"https://httpbin\.org/nonexistent-\d+\.php"),
        text="PHP Parse error ... (PHP 8.0.1)",
        status_code=404,
    )

    httpx_mock.assert_all_requests_are_fired = False

    results = await scan_targets(
        ["http://example.com", "https://httpbin.org"],
        config={
            "max_concurrency": 5,
            "timeout": 5,
            "use_nuclei": False,
            "use_ollama": False,
        },
    )

    assert len(results) == 2
    assert results[0].php_version == "7.4.33"
    assert "headers" in results[0].detected_from
    assert results[1].php_version == "8.0.1"
    assert len(results[1].detected_from) > 0
    for r in results:
        assert isinstance(r.risk_score, int)
        assert r.scan_time is not None


@pytest.mark.asyncio
async def test_scanner_with_nuclei(httpx_mock: HTTPXMock):
    """Scan with nuclei flag enabled (validation is patched)."""
    httpx_mock.add_response(
        url="https://httpbin.org",
        text="<h1>PHP Version 7.2.5</h1>",
        headers={"Server": "PHP/7.2.5"},
    )
    httpx_mock.add_response(
        url=re.compile(r"https://httpbin\.org/nonexistent-\d+\.php"),
        text="",
        status_code=404,
    )

    httpx_mock.assert_all_requests_are_fired = False

    results = await scan_targets(
        ["https://httpbin.org"],
        config={
            "max_concurrency": 3,
            "timeout": 5,
            "use_nuclei": True,
            "use_ollama": False,
        },
    )

    assert len(results) == 1
    assert results[0].php_version == "7.2.5"
    assert isinstance(results[0].nuclei_findings, list)


@pytest.mark.asyncio
async def test_scan_error_handling(httpx_mock: HTTPXMock):
    """Ensure errors are captured in ScanResult.errors."""
    httpx_mock.add_response(
        url=re.compile(r"https://bad\.example.*"),
        status_code=500,
        text="Internal Server Error",
    )

    httpx_mock.assert_all_requests_are_fired = False

    results = await scan_targets(
        ["https://bad.example.com"],
        config={"max_concurrency": 1, "timeout": 3},
    )

    assert len(results) == 1
    assert len(results[0].errors) > 0
    assert "Probe failed" in results[0].errors[0] or "Request error" in results[0].errors[0]


@pytest.mark.asyncio
async def test_scanner_live_callback(httpx_mock: HTTPXMock):
    """Live callback is invoked for each result (no 'never awaited' warning)."""
    httpx_mock.add_response(
        url="https://httpbin.org",
        text="PHP Version 8.1.0 detected",
        headers={"X-Powered-By": "PHP/8.1.0"},
    )

    httpx_mock.assert_all_requests_are_fired = False

    callback_calls: list[ScanResult] = []

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
    assert callback_calls[0].php_version == "8.1.0"
    assert results[0] is callback_calls[0]


@pytest.mark.asyncio
async def test_scanner_with_ollama(httpx_mock: HTTPXMock):
    """Ollama path is exercised when flag is enabled (localhost calls mocked)."""
    httpx_mock.add_response(
        url="https://httpbin.org",
        text="PHP Version 7.4.33 in footer",
        headers={},
    )
    httpx_mock.add_response(
        url=re.compile(r"https://httpbin\.org/nonexistent-\d+\.php"),
        text="PHP Version 7.4.33",
        status_code=404,
    )
    # Ollama availability + chat endpoint
    httpx_mock.add_response(
        url="http://localhost:11434/api/tags",
        json={"models": [{"name": "llama3"}]},
    )
    httpx_mock.add_response(
        url="http://localhost:11434/api/chat",
        json={"message": {"content": "# Test Summary\n\nRisk Level: High"}},
    )

    httpx_mock.assert_all_requests_are_fired = False

    results = await scan_targets(
        ["https://httpbin.org"],
        config={
            "max_concurrency": 3,
            "timeout": 5,
            "use_nuclei": False,
            "use_ollama": True,
            "ollama_model": "llama3",
        },
    )

    assert len(results) == 1
    assert results[0].php_version == "7.4.33"
    assert results[0].llm_summary is not None
    assert "Risk Level" in results[0].llm_summary or "Summary" in results[0].llm_summary


@pytest.mark.asyncio
async def test_async_scanner_direct(httpx_mock: HTTPXMock):
    """Direct usage of AsyncScanner.scan (used by TUI etc)."""
    httpx_mock.add_response(
        url="http://example.com",
        text="<body>PHP 5.6.40</body>",
        headers={"X-Powered-By": "PHP/5.6.40"},
    )

    scanner = AsyncScanner(config={"use_nuclei": False, "use_ollama": False})
    results = await scanner.scan(["http://example.com"])

    assert len(results) == 1
    assert results[0].php_version == "5.6.40"
