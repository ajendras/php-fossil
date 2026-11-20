"""Tests for the scanner module.

Covers basic scanning, UA rotation, proxy usage, live callbacks and
integration with fingerprinter. Updated to ensure all registered mocks
are consumed by the conditional phpinfo probe and version detection now
succeeds for every test case.
"""

import asyncio
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from phpfossil.models import ConfigSettings, ScanResult
from phpfossil.scanner import scan_targets


@pytest.mark.asyncio
async def test_scan_targets_basic(httpx_mock):
    httpx_mock.add_response(
        url="https://example.com",
        headers={"X-Powered-By": "PHP/8.0.0"},
        text="<h1>Example Site</h1>",
    )
    results = await scan_targets(
        ["https://example.com"],
        config={"max_concurrency": 5, "timeout": 5, "use_nuclei": False, "use_ollama": False},
    )
    assert len(results) == 1
    assert results[0].php_version == "8.0.0"
    assert "headers" in results[0].detected_from
    assert results[0].risk_score >= 0


@pytest.mark.asyncio
async def test_user_agent_rotation(httpx_mock):
    httpx_mock.add_response(
        url="https://example.com",
        text="no version string here",
    )
    httpx_mock.add_response(
        url="https://example.com/phpinfo.php",
        text="PHP Version 7.4.33",
    )
    httpx_mock.add_response(
        url="https://test.com",
        headers={"Server": "Apache PHP/7.4.33"},
    )

    config = ConfigSettings(
        user_agents=["UA-TEST-1", "UA-TEST-2", "UA-TEST-3"],
        max_concurrency=5,
        timeout=5,
        use_nuclei=False,
        use_ollama=False,
    )
    results = await scan_targets(["https://example.com", "https://test.com"], config=config)

    assert len(results) == 2
    assert results[0].php_version == "7.4.33"
    assert results[1].php_version == "7.4.33"

    # verify rotation occurred
    requests = httpx_mock.get_requests()
    user_agents = [r.headers.get("User-Agent") for r in requests]
    assert len(set(user_agents)) >= 2


@pytest.mark.asyncio
async def test_ua_rotation_with_default_pool(httpx_mock):
    httpx_mock.add_response(
        url="https://httpbin.org",
        headers={"X-Powered-By": "PHP/7.3.12"},
        text="OK",
    )
    results = await scan_targets(
        ["https://httpbin.org"],
        config={
            "user_agents": [],  # triggers default pool
            "max_concurrency": 5,
            "timeout": 5,
            "use_nuclei": False,
            "use_ollama": False,
        },
    )
    assert len(results) == 1
    assert results[0].php_version == "7.3.12"


@pytest.mark.asyncio
async def test_scanner_live_callback(httpx_mock):
    calls = []

    def live_callback(result: ScanResult):
        calls.append(result)

    httpx_mock.add_response(
        url="https://example.com",
        headers={"X-Powered-By": "PHP/8.0.0"},
    )
    results = await scan_targets(
        ["https://example.com"],
        config={"max_concurrency": 5, "timeout": 5, "use_nuclei": False, "use_ollama": False},
        callback=live_callback,
    )
    assert len(results) == 1
    assert len(calls) == 1
    assert calls[0].php_version == "8.0.0"
    assert results[0].php_version == "8.0.0"


@pytest.mark.asyncio
async def test_proxy_and_ua_together(httpx_mock):
    httpx_mock.add_response(
        url="https://target.com",
        headers={"Server": "nginx PHP/7.2"},
        text="PHP Version 7.2",
    )
    config = {
        "user_agents": ["ProxyTest-UA"],
        "proxies": ["http://127.0.0.1:8080"],
        "max_concurrency": 5,
        "timeout": 5,
        "use_nuclei": False,
        "use_ollama": False,
    }
    results = await scan_targets(["https://target.com"], config=config)
    assert len(results) == 1
    assert results[0].php_version == "7.2"


# remaining tests (nuclei, ollama, exposed files, store integration) kept for coverage
@patch("phpfossil.scanner.validate_with_nuclei")
@pytest.mark.asyncio
async def test_nuclei_integration(mock_nuclei, httpx_mock):
    mock_nuclei.return_value = [NucleiFinding(template="php-cve", name="RCE", severity="critical")]
    httpx_mock.add_response(
        url="https://example.com",
        headers={"X-Powered-By": "PHP/5.6.40"},
    )
    results = await scan_targets(
        ["https://example.com"],
        config={"max_concurrency": 5, "use_nuclei": True, "use_ollama": False},
    )
    assert results[0].nuclei_findings
    assert results[0].risk_score > 0


@patch("phpfossil.scanner.generate_summary")
@pytest.mark.asyncio
async def test_ollama_summary(mock_summary, httpx_mock):
    mock_summary.return_value = "Test LLM summary"
    httpx_mock.add_response(
        url="https://example.com",
        headers={"X-Powered-By": "PHP/7.4.33"},
    )
    results = await scan_targets(
        ["https://example.com"],
        config={"max_concurrency": 5, "use_nuclei": False, "use_ollama": True},
    )
    assert results[0].llm_summary == "Test LLM summary"


def test_config_settings_validation():
    cfg = ConfigSettings(max_concurrency=10, timeout=20, user_agents=[])
    assert cfg.max_concurrency == 10
    assert len(cfg.user_agents) == len(DEFAULT_USER_AGENTS)
    assert cfg.db_path is not None
