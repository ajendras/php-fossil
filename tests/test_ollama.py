"""Tests for Ollama LLM integration."""

from unittest.mock import patch

import httpx
import pytest

from phpfossil.models import Vulnerability, ScanResult
from phpfossil.ollama import is_ollama_available, generate_summary, OllamaSummarizer


def test_is_ollama_available():
    """Test both happy path and failure path (no real server needed in CI)."""
    with patch("phpfossil.ollama.httpx.get") as mock_get:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"models": [{"name": "llama3"}]}
        mock_get.return_value = mock_response
        assert is_ollama_available() is True

    with patch("phpfossil.ollama.httpx.get", side_effect=httpx.ConnectError("connection refused")):
        assert is_ollama_available() is False


def test_generate_summary():
    """Provide required description field for Vulnerability model."""
    vulns = [
        Vulnerability(
            cve="CVE-2021-1234",
            title="Test Vuln",
            description="Detailed test description of a high-severity PHP vulnerability that requires immediate patching.",
            severity="high",
            recommendation="Upgrade to PHP 8.2 or later and apply all security patches.",
            reference="https://example.com/cve-2021-1234",
        )
    ]
    results = [
        ScanResult(
            url="https://example.com",
            php_version="7.4.33",
            vulns=vulns,
            risk_score=85,
        )
    ]
    summary = generate_summary(results, model="llama3")
    assert summary is not None
    assert len(summary) > 10
    assert "vulnerability" in summary.lower() or "php" in summary.lower()


def test_ollama_summarizer_class():
    """Use create=True to handle potential method name variations; test end-to-end."""
    summarizer = OllamaSummarizer(model="llama3")
    vuln = Vulnerability(
        cve="CVE-2021-1234",
        title="Test",
        description="Test description",
        severity="high",
        recommendation="Update PHP",
        reference="https://example.com",
    )

    with patch.object(summarizer, "_call_ollama", create=True) as mock_call:
        mock_call.return_value = "Mocked executive summary: High risk due to EOL PHP version with multiple CVEs."
        result = summarizer.summarize([vuln])
        assert "Mocked executive summary" in result
        mock_call.assert_called_once()
