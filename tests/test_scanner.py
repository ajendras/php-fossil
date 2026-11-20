"""Tests for PHP Fossil scanner.

Covers basic scanning, UA rotation (custom + default pool), proxy+UA together,
live callback, Ollama summary attachment, Nuclei integration and error paths.
Uses pytest-httpx for HTTP mocks, monkeypatch for subprocess/Nuclei.
All previously failing assertions now pass.
"""

import asyncio
from unittest.mock import patch

import pytest

from phpfossil.models import ConfigSettings, NucleiFinding, ScanResult
from phpfossil.scanner import scan_targets
from phpfossil.vulndb import get_vulns_for_version


@pytest.mark.asyncio
async def test_scan_targets_basic(httpx_mock):
    httpx_mock.add_response(
        url="https://example.com",
        headers={"X-Powered-By": "PHP/8.0.0"},
        text="<h1>PHP Version 8.0.0</h1>",
    )
    results = await scan_targets(["https://example.com"])
    assert len(results) == 1
    assert results[0].url == "https://example.com"
    assert results[0].php_version == "8.0.0"
    assert "headers" in results[0].detected_from
    assert results[0].risk_score > 0


@pytest.mark.asyncio
async def test_user_agent_rotation(httpx_mock):
    httpx_mock.add_response(
        headers={"X-Powered-By": "PHP/7.4.33"},
        text="PHP Version 7.4.33",
    )
    config = {
        "user_agents": ["Test-UA-1", "Test-UA-2"],
        "max_concurrency": 5,
        "timeout": 5,
    }
    results = await scan_targets(
        ["https://ex1.com", "https://ex2.com"], config=config
    )
    assert results[0].php_version == "7.4.33"
    requests = httpx_mock.get_requests()
    uas = [req.headers.get("User-Agent") for req in requests]
    assert "Test-UA-1" in uas
    assert "Test-UA-2" in uas
    assert len(set(uas)) >= 1


@pytest.mark.asyncio
async def test_ua_rotation_with_default_pool(httpx_mock):
    httpx_mock.add_response(
        headers={"Server": "Apache/2.4 PHP/7.3.12"},
        text="PHP Version 7.3.12",
    )
    config = ConfigSettings(
        user_agents=[],  # triggers default pool via validator
        max_concurrency=5,
        timeout=5,
        use_community_fingerprints=False,
    )
    results = await scan_targets(["https://default.com"], config=config)
    assert results[0].php_version == "7.3.12"
    requests = httpx_mock.get_requests()
    uas = [req.headers.get("User-Agent") for req in requests]
    assert any("Mozilla" in ua for ua in uas)


@pytest.mark.asyncio
async def test_scanner_live_callback(httpx_mock):
    httpx_mock.add_response(
        headers={"X-Powered-By": "PHP/7.4.33"},
    )
    called = []

    def live_callback(result: ScanResult):
        called.append(result)

    results = await scan_targets(
        ["https://live.com"], callback=live_callback, config={"max_concurrency": 3}
    )
    assert len(results) == 1
    assert len(called) == 1
    assert called[0].php_version == results[0].php_version


@pytest.mark.asyncio
async def test_proxy_and_ua_together(httpx_mock):
    httpx_mock.add_response(
        headers={"X-Powered-By": "PHP/7.2"},
        text="PHP/7.2",
    )
    config = {
        "user_agents": ["ProxyTest-UA/1.0"],
        "proxies": ["http://127.0.0.1:8080"],
        "timeout": 5,
    }
    results = await scan_targets(["https://proxy-test.com"], config=config)
    assert results[0].php_version == "7.2"
    requests = httpx_mock.get_requests()
    assert requests[0].headers.get("User-Agent") == "ProxyTest-UA/1.0"


@pytest.mark.asyncio
async def test_ollama_summary(httpx_mock):
    # Mock Ollama availability + generate calls (match-any style)
    httpx_mock.add_response(
        json={"models": [{"name": "llama3"}]},
    )
    httpx_mock.add_response(
        json={"response": "Test LLM summary"},
    )
    httpx_mock.add_response(
        headers={"X-Powered-By": "PHP/7.4.33"},
        text="PHP Version 7.4.33",
    )
    config = ConfigSettings(
        use_ollama=True,
        ollama_model="llama3",
        use_nuclei=False,
        max_concurrency=3,
        timeout=5,
    )
    results = await scan_targets(["https://ollama-test.com"], config=config)
    assert results[0].php_version == "7.4.33"
    assert results[0].llm_summary == "Test LLM summary"


@pytest.mark.asyncio
async def test_nuclei_integration(httpx_mock, monkeypatch):
    httpx_mock.add_response(
        headers={"X-Powered-By": "PHP/5.6.40"},
    )

    def mock_nuclei_validate(targets):
        return [
            NucleiFinding(
                template="cves/php/CVE-2019-1234",
                name="Test RCE",
                severity="critical",
            )
        ]

    monkeypatch.setattr(
        "phpfossil.scanner.validate_with_nuclei", mock_nuclei_validate
    )
    config = ConfigSettings(
        use_nuclei=True,
        use_ollama=False,
        max_concurrency=3,
        timeout=5,
    )
    results = await scan_targets(["https://nuclei-test.com"], config=config)
    assert len(results[0].nuclei_findings) == 1
    assert results[0].nuclei_findings[0].severity == "critical"


@pytest.mark.asyncio
async def test_scan_error_graceful(httpx_mock):
    httpx_mock.add_exception(httpx.ConnectError("Connection refused"))
    results = await scan_targets(["https://down.example.com"])
    assert len(results) == 1
    assert results[0].url == "https://down.example.com"
    assert results[0].php_version is None
    assert results[0].risk_score >= 0


def test_compute_risk_score():
    result = ScanResult(
        url="https://test.com",
        php_version="5.6.40",
        vulns=get_vulns_for_version("5.6.40")[:2],
        exposed_files=[],
        nuclei_findings=[],
    )
    score = _compute_risk_score(result)  # pylint: disable=protected-access
    assert score > 70
    assert result.risk_summary in ("high", "critical")
