"""Tests for ollama.py using mocked HTTP responses."""

import pytest
import httpx

from phpfossil.ollama import (
    is_ollama_available,
    generate_summary,
    OllamaSummarizer,
)
from phpfossil.models import ScanResult, Vulnerability


def test_is_ollama_available(httpx_mock):
    """Test successful availability check."""
    httpx_mock.add_response(
        url="http://localhost:11434/api/tags",
        json={"models": [{"name": "llama3"}]},
        status_code=200,
    )
    assert is_ollama_available(timeout=1) is True


def test_is_ollama_available_failure(httpx_mock):
    """Test when Ollama is not running."""
    httpx_mock.add_response(
        url="http://localhost:11434/api/tags",
        status_code=404,
    )
    assert is_ollama_available(timeout=1) is False


def test_generate_summary(httpx_mock):
    """Test summary generation with mocked Ollama response."""
    httpx_mock.add_response(
        url="http://localhost:11434/api/generate",
        json={"response": "High risk legacy PHP installations were identified. Immediate patching to PHP 8.2+ and removal of exposed phpinfo() and SQL dumps is recommended. Risk score average 72."},
        status_code=200,
    )

    results = [
        ScanResult(
            url="https://legacy.example.com",
            php_version="7.4.33",
            vulns=[Vulnerability(cve="CVE-2021-1234", title="RCE", severity="high", description="test")],
        )
    ]

    summary = generate_summary(results, model="llama3")
    assert "legacy PHP" in summary.lower() or "high risk" in summary.lower()
    assert len(httpx_mock.get_requests()) == 1


def test_generate_summary_no_results():
    assert "No scan results" in generate_summary([])


def test_generate_summary_error(httpx_mock):
    """Test graceful error handling when Ollama is unreachable."""
    httpx_mock.add_exception(httpx.ConnectError("Connection refused"), url="http://localhost:11434/api/generate")

    summary = generate_summary([ScanResult(url="http://test.com")])
    assert "Could not connect to Ollama" in summary or "failed" in summary.lower()


def test_ollama_summarizer_class(httpx_mock):
    httpx_mock.add_response(
        url="http://localhost:11434/api/tags",
        json={"models": []},
        status_code=200,
    )
    httpx_mock.add_response(
        url="http://localhost:11434/api/generate",
        json={"response": "Class test summary."},
    )
    summarizer = OllamaSummarizer(model="llama3")
    summary = summarizer.summarize([ScanResult(url="https://example.com")])
    assert "Class test summary" in summary
    assert summarizer.is_available() is True
