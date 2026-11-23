"""Tests for ollama.py using mocked HTTP responses."""

from unittest.mock import MagicMock, patch

import httpx
import pytest

from phpfossil.models import ScanResult, Vulnerability
from phpfossil.ollama import (
    OllamaSummarizer,
    generate_summary,
    is_ollama_available,
)


def test_is_ollama_available() -> None:
    """Test Ollama availability check via /api/tags endpoint."""
    with patch("phpfossil.ollama.httpx.get") as mock_get:
        mock_get.return_value.status_code = 200
        assert is_ollama_available() is True

        mock_get.return_value.status_code = 404
        assert is_ollama_available() is False

        mock_get.side_effect = httpx.ConnectError("connection refused")
        assert is_ollama_available() is False


@patch("phpfossil.ollama.httpx.post")
def test_generate_summary(mock_post: MagicMock) -> None:
    """Test LLM summary generation with mocked Ollama response."""
    results = [
        ScanResult(
            url="https://example.com",
            php_version="7.4.33",
            vulns=[
                Vulnerability(
                    cve="CVE-2021-1234",
                    title="Test Vuln",
                    severity="high",
                )
            ],
        )
    ]

    mock_post.return_value.json.return_value = {
        "response": "Legacy PHP 7.4 instances are EOL and expose multiple CVEs."
    }

    summary = generate_summary(results, model="llama3")
    assert "EOL" in summary
    assert "CVEs" in summary
    mock_post.assert_called_once()


def test_ollama_summarizer_class() -> None:
    """Test OllamaSummarizer wrapper class."""
    summarizer = OllamaSummarizer(model="mistral")
    assert summarizer.model == "mistral"
    with patch.object(summarizer, "_call_ollama") as mock_call:
        mock_call.return_value = "Mocked summary"
        assert summarizer.summarize([]) == "Mocked summary"
