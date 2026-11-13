"""Tests for the PHP Fossil scanner module.

Uses pytest-httpx to mock HTTP interactions and monkeypatch for optional
Nuclei / Ollama dependencies. Covers fingerprinting, error handling,
live callbacks, nuclei integration and Ollama summarization.
"""

import re
from typing import Any
import pytest
import httpx
from pytest_httpx import HTTPXMock

from phpfossil import scan_targets, ScanResult
from phpfossil.models import NucleiFinding, Vulnerability


@pytest.mark.asyncio
async def test_scan_targets(httpx_mock: HTTPXMock):
    """Test basic scanning with version detection from headers and body."""
    httpx_mock.add_response(
        url="http://example.com",
        headers={"X-Powered-By": "PHP/7.4.33"},
        text="<title>Site</title><p>PHP Version 7.4.33</p>",
    )
    httpx_mock.add_response(
        url="https://httpbin.org",
        text='{"message": "PHP Version 7.2.0 detected in footer"}',
    )
    # The following are registered for potential error-page probes but may not
    # be requested if version is already detected from primary response.
    # We disable strict assertion per pytest-httpx docs.
    httpx_mock.add_response(
        url=re.compile(r"http://example\.com/nonexistent-\d+\.php"),
        status_code=404,
        text="PHP Parse error: ... (PHP 7.4.33)",
    )
    httpx_mock.add_response(
        url=re.compile(r"https://httpbin\.org/nonexistent-\d+\.php"),
        status_code=404,
        text="PHP 7.2.0",
    )

    httpx_mock.assert_all_responses_were_requested = False

    results: list[ScanResult] = await scan_targets(
        ["http://example.com", "https://httpbin.org"],
        config={
            "max_concurrency": 10,
            "timeout": 5,
            "use_nuclei": False,
            "use_ollama": False,
        },
    )

    assert len(results) == 2
    ex = next(r for r in results if "example.com" in r.url)
    assert ex.php_version == "7.4.33"
    assert len(ex.detected_from) > 0
    assert ex.risk_score >= 35
    hb = next(r for r in results if "httpbin.org" in r.url)
    assert hb.php_version == "7.2.0"
    assert "body" in hb.detected_from


@pytest.mark.asyncio
async def test_scanner_with_nuclei(httpx_mock: HTTPXMock, monkeypatch):
    """Test integration with Nuclei when enabled."""
    httpx_mock.add_response(
        url="https://httpbin.org",
        headers={"Server": "PHP/7.2.0"},
        text="PHP Version 7.2.0",
    )
    httpx_mock.add_response(
        url=re.compile(r"https://httpbin\.org/nonexistent-\d+\.php"),
        status_code=404,
        text="PHP/7.2.0",
    )

    httpx_mock.assert_all_responses_were_requested = False

    # Mock nuclei since binary may not be present in CI
    mock_findings = [
        NucleiFinding(
            template="php-cgi-arg-injection",
            name="PHP CGI Argument Injection",
            severity="high",
            matched_at="https://httpbin.org/index.php",
        )
    ]
    monkeypatch.setattr(
        "phpfossil.scanner.validate_with_nuclei", lambda *_, **__: mock_findings
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
    result = results[0]
    assert result.php_version == "7.2.0"
    assert len(result.nuclei_findings) == 1
    assert result.nuclei_findings[0].severity == "high"


@pytest.mark.asyncio
async def test_scan_error_handling(httpx_mock: HTTPXMock):
    """Test that connection errors and bad responses are captured in .errors."""
    # Match any request to the bad domain to prevent "requests not expected" error
    httpx_mock.add_exception(
        httpx.ConnectError("Connection refused"),
        url=re.compile(r"https://bad\.example.*"),
    )

    results = await scan_targets(
        ["https://bad.example"],
        config={
            "max_concurrency": 5,
            "timeout": 5,
            "use_nuclei": False,
            "use_ollama": False,
        },
    )

    assert len(results) == 1
    result = results[0]
    assert result.php_version is None
    assert len(result.errors) > 0
    assert any("Connection refused" in err for err in result.errors)
    assert result.risk_score == 0


@pytest.mark.asyncio
async def test_scanner_live_callback(httpx_mock: HTTPXMock):
    """Test the optional live callback for TUI integration."""
    httpx_mock.add_response(
        url="https://httpbin.org",
        text="PHP Version 7.4.33",
    )
    httpx_mock.add_response(
        url=re.compile(r"https://httpbin\.org/nonexistent-\d+\.php"),
        status_code=404,
    )
    httpx_mock.assert_all_responses_were_requested = False

    called = []

    def live_callback(result: ScanResult) -> None:
        called.append(result)

    results = await scan_targets(
        ["https://httpbin.org"],
        config={"max_concurrency": 5, "timeout": 5, "use_nuclei": False, "use_ollama": False},
        callback=live_callback,
    )

    assert len(results) == 1
    assert len(called) == 1
    assert called[0].php_version == "7.4.33"


@pytest.mark.asyncio
async def test_scanner_with_ollama(httpx_mock: HTTPXMock, monkeypatch):
    """Test Ollama summarization path."""
    httpx_mock.add_response(
        url="https://httpbin.org",
        text="<h1>PHP Version 7.2.0</h1>",
    )
    httpx_mock.add_response(
        url=re.compile(r"https://httpbin\.org/nonexistent-\d+\.php"),
        status_code=404,
        text="PHP Version 7.2.0",
    )
    httpx_mock.assert_all_responses_were_requested = False

    monkeypatch.setattr("phpfossil.ollama.is_ollama_available", lambda: True)
    monkeypatch.setattr(
        "phpfossil.ollama.generate_summary",
        lambda *a, **k: "# Mock Summary\n\nHigh risk due to old PHP 7.2.0.",
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
    assert results[0].llm_summary is not None
    assert "High risk" in results[0].llm_summary
