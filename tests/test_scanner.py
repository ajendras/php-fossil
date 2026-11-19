"""Tests for the scanner module (including new UA rotation)."""

import asyncio
import json
from unittest.mock import MagicMock, patch

import pytest
from pytest_httpx import HTTPXMock

from phpfossil.models import ConfigSettings, ScanResult
from phpfossil.scanner import AsyncScanner, scan_targets


@pytest.mark.asyncio
async def test_scan_targets_basic(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url="https://example.com/",
        text="<title>PHP Version 8.0.0</title>",
        headers={"X-Powered-By": "PHP/8.0.0"},
    )
    results = await scan_targets(
        ["https://example.com"],
        config={"use_nuclei": False, "use_ollama": False, "use_community_fingerprints": False},
    )
    assert len(results) == 1
    assert results[0].php_version == "8.0.0"
    assert "headers+body" in results[0].detected_from


@pytest.mark.asyncio
async def test_user_agent_rotation(httpx_mock: HTTPXMock):
    """Test that User-Agents are rotated across requests."""
    custom_uas = [
        "Mozilla/5.0 (Custom-UA-1)",
        "Mozilla/5.0 (Custom-UA-2)",
        "Mozilla/5.0 (Custom-UA-3)",
    ]
    config = ConfigSettings(
        max_concurrency=5,
        timeout=5,
        user_agents=custom_uas,
        use_nuclei=False,
        use_ollama=False,
        use_community_fingerprints=False,
    )

    # Multiple targets to force multiple UA usages
    httpx_mock.add_response(
        url="https://example.com/",
        text="PHP Version 7.4.33",
        headers={"Server": "Apache PHP/7.4.33"},
    )
    httpx_mock.add_response(
        url="https://example.com/phpinfo.php",
        text="PHP Version 7.4.33",
    )
    httpx_mock.add_response(
        url="https://test.com/",
        text="PHP 8.1 detected",
    )

    results = await scan_targets(
        ["https://example.com", "https://test.com"],
        config=config,
    )

    assert len(results) == 2
    assert results[0].php_version == "7.4.33"
    assert results[1].php_version == "8.1"

    requests = httpx_mock.get_requests()
    used_uas = [req.headers.get("User-Agent") for req in requests if "User-Agent" in req.headers]
    # At least two different UAs should have been used due to rotation
    assert len(set(used_uas)) >= 2
    for ua in used_uas:
        assert ua in custom_uas


@pytest.mark.asyncio
async def test_ua_rotation_with_default_pool(httpx_mock: HTTPXMock):
    """Ensure default UA pool is used when none provided."""
    config = ConfigSettings(
        max_concurrency=3,
        user_agents=[],  # triggers default
        use_nuclei=False,
        use_ollama=False,
        use_community_fingerprints=False,
    )
    httpx_mock.add_response(
        url="https://httpbin.org",
        text="PHP Version 7.3.12",
    )
    results = await scan_targets(["https://httpbin.org"], config=config)
    assert len(results) == 1
    assert results[0].php_version == "7.3.12"

    requests = httpx_mock.get_requests()
    uas = [r.headers.get("User-Agent") for r in requests]
    # At least one UA from the built-in default list should appear
    assert any("Mozilla/5.0" in ua for ua in uas)


@pytest.mark.asyncio
async def test_scanner_live_callback(httpx_mock: HTTPXMock):
    callback = MagicMock()
    httpx_mock.add_response(
        url="https://example.com",
        text="<h1>PHP Version 5.6.40</h1>",
    )
    await scan_targets(
        ["https://example.com"],
        config={"use_nuclei": False, "use_ollama": False},
        callback=callback,
    )
    callback.assert_called_once()
    assert isinstance(callback.call_args[0][0], ScanResult)


def test_config_with_user_agents():
    cfg = ConfigSettings(user_agents=["UA1", "UA2"])
    assert len(cfg.user_agents) == 2
    assert cfg.user_agents[0] == "UA1"


@pytest.mark.asyncio
async def test_proxy_and_ua_together(httpx_mock: HTTPXMock):
    config = ConfigSettings(
        proxies=["http://proxy1:8080", "http://proxy2:8080"],
        user_agents=["UA-Proxy-Test"],
        use_nuclei=False,
        use_ollama=False,
        use_community_fingerprints=False,
    )
    httpx_mock.add_response(url="https://target.com", text="PHP 7.2")
    results = await scan_targets(["https://target.com"], config=config)
    assert results[0].php_version == "7.2"
    requests = httpx_mock.get_requests()
    assert any("UA-Proxy-Test" in str(r.headers) for r in requests)
