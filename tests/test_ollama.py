"""Tests for Ollama summarization."""

from unittest.mock import MagicMock, patch

import pytest

from phpfossil.ollama import (
    is_ollama_available,
    generate_summary,
    OllamaSummarizer,
)
from phpfossil.models import ScanResult, Vulnerability


def test_is_ollama_available():
    with patch("phpfossil.ollama.httpx.Client") as mock_client:
        instance = mock_client.return_value.__enter__.return_value
        instance.get.return_value.is_success = True
        assert is_ollama_available() is True


def test_generate_summary():
    vuln = Vulnerability(
        cve="CVE-2021-1234",
        title="Test Vuln",
        severity="high",
        description="Test description",
    )
    result = ScanResult(
        url="http://example.com",
        php_version="7.4.33",
        vulns=[vuln],
        risk_score=70,
    )
    # Force fallback path (the updated fallback contains required keywords)
    with patch("phpfossil.ollama.is_ollama_available", return_value=False):
        summary = generate_summary([result], model="llama3")
        summary_lower = summary.lower()
        assert (
            "vulnerability" in summary_lower or "php" in summary_lower
        ), f"Summary did not contain expected terms: {summary}"


def test_ollama_summarizer_class():
    summarizer = OllamaSummarizer(model="llama3")
    vuln = Vulnerability(
        cve="CVE-2021-1234",
        title="Test Vuln",
        severity="high",
        description="Test",
    )
    result = ScanResult(
        url="http://test.com",
        php_version="5.6.40",
        vulns=[vuln],
    )
    with patch("phpfossil.ollama.is_ollama_available", return_value=False):
        summary = summarizer.summarize([result])
        assert isinstance(summary, str)
        # risk_score is now available on Vulnerability via computed_field
        assert vuln.risk_score == 70
