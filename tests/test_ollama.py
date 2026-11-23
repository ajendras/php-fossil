"""Tests for ollama.py using mocked HTTP responses."""

import httpx
from unittest.mock import patch

from phpfossil.models import ScanResult, Vulnerability
from phpfossil.ollama import (
    OllamaSummarizer,
    generate_summary,
    is_ollama_available,
)


def test_is_ollama_available(mock_httpx):
    """Test that Ollama availability check works with successful response."""
    mock_httpx.add_response(
        url="http://localhost:11434/api/tags",
        json={"models": [{"name": "llama3:8b"}]},
        status_code=200,
    )
    assert is_ollama_available() is True


def test_is_ollama_available_connection_error(mock_httpx):
    """Test graceful handling when Ollama is not running."""
    mock_httpx.add_exception(httpx.ConnectError("Connection refused"))
    assert is_ollama_available() is False


def test_generate_summary():
    """Test LLM summary generation with mocked Ollama response."""
    results = [
        ScanResult(
            url="https://example.com",
            php_version="7.4.33",
            vulns=[
                Vulnerability(
                    cve="CVE-2021-1234",
                    title="Test vulnerability",
                    severity="high",
                    description="Test",
                )
            ],
            risk_score=72,
            exposed_files=[],
            nuclei_findings=[],
        )
    ]

    expected_part = (
        "Upgrading to PHP 8.2+ and removal of exposed phpinfo() and SQL dumps is "
        "recommended. Risk score average 72."
    )
    with patch("phpfossil.ollama.httpx.post") as mock_post:
        mock_post.return_value.raise_for_status.return_value = None
        mock_post.return_value.json.return_value = {
            "response": f"Test summary. {expected_part}"
        }
        summary = generate_summary(results, model="llama3")
        assert "Test summary" in summary
        assert "PHP 8.2" in summary
        assert "72" in summary


def test_ollama_summarizer_class():
    """Test the OllamaSummarizer class directly."""
    summarizer = OllamaSummarizer(model="llama3")
    assert summarizer.model == "llama3"
    assert summarizer.url == "http://localhost:11434/api/generate"
