import asyncio
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone

import httpx
import pytest

from phpfossil.models import ConfigSettings, ScanResult
from phpfossil.scanner import scan_targets
from phpfossil.ollama import generate_summary
from phpfossil.nuclei import validate_with_nuclei


def test_scan_targets_basic(httpx_mock):
    httpx_mock.add_response(
        url="https://example.com",
        headers={"X-Powered-By": "PHP/8.0.0"},
    )
    results = asyncio.run(scan_targets(["https://example.com"]))
    assert len(results) == 1
    assert results[0].php_version == "8.0.0"
    assert "headers" in results[0].detected_from
    assert results[0].risk_summary == "low"


def test_user_agent_rotation(httpx_mock):
    httpx_mock.add_response(
        url="https://ex1.com",
        headers={"X-Powered-By": "PHP/7.4.33"},
    )
    config = {
        "user_agents": ["Mozilla/5.0 (Custom) AppleWebKit/537.36"],
        "max_concurrency": 5,
        "timeout": 5,
    }
    results = asyncio.run(scan_targets(["https://ex1.com"], config=config))
    assert results[0].php_version == "7.4.33"
    requests = httpx_mock.get_requests()
    assert len(requests) == 1
    assert "Custom" in requests[0].headers["User-Agent"]


def test_ua_rotation_with_default_pool(httpx_mock):
    httpx_mock.add_response(
        url="https://default.com",
        headers={"Server": "Apache PHP/7.3.12"},
    )
    results = asyncio.run(scan_targets(["https://default.com"], config={}))
    assert results[0].php_version == "7.3.12"
    requests = httpx_mock.get_requests()
    assert len(requests) == 1
    ua = requests[0].headers["User-Agent"]
    assert any("Mozilla" in ua or "Googlebot" in ua for ua in [ua])


def test_proxy_and_ua_together(httpx_mock):
    httpx_mock.add_response(
        url="https://proxy-test.com",
        headers={"X-Powered-By": "PHP/7.2"},
    )
    config = {
        "proxies": ["http://test-proxy:8080"],
        "user_agents": ["Custom-UA/1.0"],
        "max_concurrency": 5,
        "timeout": 5,
    }
    results = asyncio.run(scan_targets(["https://proxy-test.com"], config=config))
    assert results[0].php_version == "7.2"
    requests = httpx_mock.get_requests()
    assert len(requests) == 1
    assert requests[0].headers["User-Agent"] == "Custom-UA/1.0"


def test_scanner_live_callback(httpx_mock):
    called = []
    def callback(result: ScanResult):
        called.append(result)

    httpx_mock.add_response(
        url="https://live.example.com",
        headers={"X-Powered-By": "PHP/8.1.0"},
    )
    config = {
        "max_concurrency": 5,
        "timeout": 5,
        "use_community_fingerprints": False,
    }
    results = asyncio.run(
        scan_targets(
            ["https://live.example.com"],
            config=config,
            callback=callback,
        )
    )
    assert len(called) == 1
    assert called[0].php_version == "8.1.0"
    assert results[0].php_version == "8.1.0"
    assert len(results[0].detected_from) > 0


def test_ollama_summary(httpx_mock):
    httpx_mock.add_response(
        url="https://ollama-test.com",
        headers={"X-Powered-By": "PHP/7.4.33"},
    )
    httpx_mock.add_response(
        url="http://localhost:11434/api/generate",
        json={"response": "Ollama summary for PHP 7.4.33: high risk due to EOL."},
    )
    config = {
        "use_ollama": True,
        "ollama_model": "llama3",
        "use_community_fingerprints": False,
        "max_concurrency": 5,
        "timeout": 5,
    }
    results = asyncio.run(scan_targets(["https://ollama-test.com"], config=config))
    assert results[0].php_version == "7.4.33"
    assert results[0].llm_summary is not None


def test_nuclei_integration(httpx_mock, monkeypatch):
    httpx_mock.add_response(
        url="https://nuclei-test.com",
        headers={"X-Powered-By": "PHP/7.4.33"},
    )
    mock_nuclei = MagicMock(return_value=[{"template": "php/cve-2021-1234", "name": "RCE", "severity": "high"}])
    monkeypatch.setattr("phpfossil.scanner.validate_with_nuclei", mock_nuclei)
    config = {
        "use_nuclei": True,
        "use_community_fingerprints": False,
        "max_concurrency": 5,
        "timeout": 5,
    }
    results = asyncio.run(scan_targets(["https://nuclei-test.com"], config=config))
    assert results[0].php_version == "7.4.33"
    assert len(results[0].nuclei_findings) > 0


def test_scan_error_graceful(httpx_mock):
    httpx_mock.add_exception(
        httpx.ConnectError("connection failed"),
        url="https://error.example.com",
    )
    config = {
        "max_concurrency": 5,
        "timeout": 5,
        "use_community_fingerprints": False,
    }
    results = asyncio.run(scan_targets(["https://error.example.com"], config=config))
    assert len(results) == 1
    assert results[0].php_version is None
    assert results[0].url == "https://error.example.com"
