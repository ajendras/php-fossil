"""Tests for the scanner module."""

import pytest
import asyncio
from unittest.mock import patch
from phpfossil import (
    scan_targets,
    ConfigSettings,
    DEFAULT_USER_AGENTS,
    ScanResult,
    NucleiFinding,
)
from phpfossil.ollama import generate_summary


@pytest.mark.asyncio
async def test_scan_targets_basic(httpx_mock):
    httpx_mock.add_response(
        headers={"X-Powered-By": "PHP/8.0.0"},
        text="<h1>PHP Version 8.0.0</h1>",
    )
    config = ConfigSettings(
        max_concurrency=5,
        timeout=5,
        use_nuclei=False,
        use_ollama=False,
        use_community_fingerprints=False,
    )
    results = await scan_targets(["https://httpbin.org"], config=config)
    assert len(results) == 1
    assert results[0].php_version == "8.0.0"
    assert results[0].detected_from


@pytest.mark.asyncio
async def test_user_agent_rotation(httpx_mock):
    httpx_mock.add_response(
        headers={"X-Powered-By": "PHP/7.4.33"},
        text="PHP Version 7.4.33",
    )
    config = ConfigSettings(
        user_agents=["UA1", "UA2"],
        max_concurrency=5,
        use_nuclei=False,
        use_ollama=False,
    )
    results = await scan_targets(["https://example.com"], config=config)
    assert results[0].php_version == "7.4.33"
    requests = httpx_mock.get_requests()
    assert len(requests) > 0
    uas = [r.headers.get("User-Agent") for r in requests if "User-Agent" in r.headers]
    assert any(ua.startswith("UA") or ua in DEFAULT_USER_AGENTS for ua in uas)


@pytest.mark.asyncio
async def test_ua_rotation_with_default_pool(httpx_mock):
    httpx_mock.add_response(
        headers={"X-Powered-By": "PHP/7.3.12"},
        text="Version: 7.3.12",
    )
    config = ConfigSettings(
        user_agents=[],
        max_concurrency=5,
        use_nuclei=False,
        use_ollama=False,
    )
    results = await scan_targets(["https://httpbin.org"], config=config)
    assert results[0].php_version == "7.3.12"


@pytest.mark.asyncio
async def test_scanner_live_callback(httpx_mock):
    calls = []
    def callback(result: ScanResult):
        calls.append(result)
    httpx_mock.add_response(
        headers={"Server": "PHP/7.4"},
        text="PHP Version 7.4",
    )
    config = ConfigSettings(
        max_concurrency=5,
        use_nuclei=False,
        use_ollama=False,
    )
    results = await scan_targets(
        ["https://example.com"], config=config, callback=callback
    )
    assert len(results) == 1
    assert len(calls) == 1
    assert calls[0].php_version is not None


@pytest.mark.asyncio
async def test_proxy_and_ua_together(httpx_mock):
    httpx_mock.add_response(
        headers={"X-Powered-By": "PHP/7.2"},
        text="PHP/7.2",
    )
    config = ConfigSettings(
        proxies=["http://fakeproxy:8080"],
        user_agents=["ProxyTest-UA"],
        max_concurrency=5,
        use_nuclei=False,
        use_ollama=False,
    )
    results = await scan_targets(["https://target.com"], config=config)
    assert results[0].php_version == "7.2"


@pytest.mark.asyncio
async def test_ollama_summary(httpx_mock):
    httpx_mock.add_response(
        headers={"X-Powered-By": "PHP/8.1.0"},
        text="PHP Version 8.1.0",
    )
    with patch("phpfossil.ollama.generate_summary", return_value="Test LLM summary"):
        config = ConfigSettings(
            max_concurrency=5,
            use_nuclei=False,
            use_ollama=True,
            ollama_model="llama3",
        )
        results = await scan_targets(["https://example.com"], config=config)
        assert len(results) == 1
        assert results[0].llm_summary == "Test LLM summary"


def test_config_settings_validation():
    config = ConfigSettings(user_agents=[])
    assert config.user_agents == DEFAULT_USER_AGENTS
    assert config.max_concurrency == 20
    assert config.timeout == 12
    assert not config.use_nuclei
    with pytest.raises(ValueError):
        ConfigSettings(max_concurrency=100)


@pytest.mark.asyncio
async def test_nuclei_integration(httpx_mock):
    httpx_mock.add_response(
        headers={"X-Powered-By": "PHP/5.6.40"},
        text="old version",
    )
    with patch("phpfossil.nuclei.validate_with_nuclei") as mock_nuclei:
        mock_nuclei.return_value = [
            NucleiFinding(
                template="php-cve.yaml",
                name="Remote Code Execution",
                severity="high",
            )
        ]
        config = ConfigSettings(
            max_concurrency=5,
            use_nuclei=True,
            use_ollama=False,
        )
        results = await scan_targets(["https://example.com"], config=config)
        assert len(results) == 1
        assert len(results[0].nuclei_findings) == 1
        assert results[0].nuclei_findings[0].severity == "high"
