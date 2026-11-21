"""Tests for the PHP Fossil scanner.

Covers version detection, UA/proxy rotation, live callbacks, Nuclei/Ollama integration,
error handling and risk scoring. Uses pytest-httpx for HTTP mocking and monkeypatch
for subprocess based Nuclei.
"""

import asyncio
from unittest.mock import patch

import httpx
import pytest
from pytest_httpx import HTTPXMock

from phpfossil.models import (
    ConfigSettings,
    ExposedFile,
    NucleiFinding,
    ScanResult,
    Vulnerability,
)
from phpfossil.scanner import _compute_risk_score, scan_targets


@pytest.mark.asyncio
async def test_scan_targets_basic(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url="https://example.com",
        headers={"X-Powered-By": "PHP/8.0.0"},
        text="PHP Version 8.0.0",
    )
    results = await scan_targets(["https://example.com"])
    assert len(results) == 1
    assert results[0].php_version == "8.0.0"
    assert any(src in results[0].detected_from for src in ("headers", "body"))


@pytest.mark.asyncio
async def test_user_agent_rotation(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url="https://ex1.com",
        headers={"X-Powered-By": "PHP/7.4.33"},
    )
    config = ConfigSettings(
        user_agents=["Custom-UA-1", "Custom-UA-2"], max_concurrency=1
    )
    results = await scan_targets(["https://ex1.com"], config=config)
    assert results[0].php_version == "7.4.33"
    # verify UA was used (inspect sent request)
    requests = httpx_mock.get_requests()
    assert len(requests) > 0
    ua_header = requests[0].headers.get("User-Agent")
    assert ua_header in ("Custom-UA-1", "Custom-UA-2")


@pytest.mark.asyncio
async def test_ua_rotation_with_default_pool(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url="https://default.com",
        headers={"Server": "Apache/2.4 PHP/7.3.12"},
    )
    results = await scan_targets(
        ["https://default.com"], config={"max_concurrency": 5}
    )
    assert results[0].php_version == "7.3.12"


@pytest.mark.asyncio
async def test_proxy_and_ua_together(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url="https://proxy-test.com",
        headers={"X-Powered-By": "PHP/7.2"},
    )
    config = ConfigSettings(
        proxies=["http://proxy1:8080"],
        user_agents=["Test-UA"],
        use_nuclei=False,
        max_concurrency=1,
    )
    results = await scan_targets(["https://proxy-test.com"], config=config)
    assert results[0].php_version == "7.2"
    requests = httpx_mock.get_requests()
    assert any("Test-UA" in str(r.headers) for r in requests)


@pytest.mark.asyncio
async def test_scanner_live_callback(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url="https://live.example.com",
        headers={"X-Powered-By": "PHP/8.1.0"},
    )
    collected = []

    def callback(result: ScanResult):
        collected.append(result)

    await scan_targets(
        ["https://live.example.com"],
        config=ConfigSettings(max_concurrency=1),
        callback=callback,
    )
    assert len(collected) == 1
    assert collected[0].php_version == "8.1.0"


@pytest.mark.asyncio
async def test_ollama_summary(httpx_mock: HTTPXMock):
    # Mock for target
    httpx_mock.add_response(
        url="https://ollama-test.com",
        headers={"X-Powered-By": "PHP/7.4.33"},
        text="PHP Version 7.4.33",
    )
    # Mock for is_ollama_available and generate_summary (optional to prevent unused-mock errors)
    httpx_mock.add_response(
        url="http://localhost:11434/api/tags",
        json={"models": [{"name": "llama3"}]},
        is_optional=True,
    )
    httpx_mock.add_response(
        url="http://localhost:11434/api/generate",
        json={"response": "High risk legacy PHP installation detected with multiple CVEs."},
        is_optional=True,
    )
    config = ConfigSettings(
        use_ollama=True, ollama_model="llama3", max_concurrency=1
    )
    results = await scan_targets(["https://ollama-test.com"], config=config)
    assert results[0].php_version == "7.4.33"
    assert results[0].llm_summary is not None


@pytest.mark.asyncio
async def test_nuclei_integration(httpx_mock: HTTPXMock, monkeypatch):
    httpx_mock.add_response(
        url="https://nuclei-test.com",
        headers={"X-Powered-By": "PHP/7.4.33"},
    )

    # Mock nuclei since it uses subprocess (not HTTP) - this fixes the len==0 failure
    def mock_nuclei_validate(targets):
        return [
            NucleiFinding(
                template="php-cve.yaml",
                name="Remote Code Execution",
                severity="critical",
            )
        ]

    monkeypatch.setattr(
        "phpfossil.scanner.validate_with_nuclei", mock_nuclei_validate
    )
    config = ConfigSettings(use_nuclei=True, max_concurrency=1)
    results = await scan_targets(["https://nuclei-test.com"], config=config)
    assert results[0].php_version == "7.4.33"
    assert len(results[0].nuclei_findings) == 1
    assert results[0].risk_score > 0


@pytest.mark.asyncio
async def test_scan_error_graceful(httpx_mock: HTTPXMock):
    httpx_mock.add_exception(
        httpx.ReadTimeout("timeout"), url="https://error.example.com"
    )
    results = await scan_targets(
        ["https://error.example.com"], config={"timeout": 1, "max_concurrency": 1}
    )
    assert len(results) == 1
    assert results[0].php_version is None
    assert results[0].url == "https://error.example.com"


def test_compute_risk_score():
    vulns = [
        Vulnerability(
            cve="CVE-2021-1234", title="Test", severity="high", description="desc"
        )
    ]
    findings = [
        NucleiFinding(
            template="t", name="n", severity="critical", description="desc"
        )
    ]
    result = ScanResult(
        url="https://test.com",
        php_version="7.2.0",
        vulns=vulns,
        nuclei_findings=findings,
        exposed_files=[ExposedFile(url="https://test.com/dump.sql")],
    )
    score = _compute_risk_score(result)
    assert score >= 70
    assert isinstance(score, int)
