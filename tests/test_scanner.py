import asyncio
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import httpx
import pytest
from pytest_httpx import HTTPXMock

from phpfossil import (
    ScanResult,
    generate_summary,
    get_historical_results,
    scan_targets,
    store_results,
    validate_with_nuclei,
)
from phpfossil.models import Vulnerability


@pytest.mark.asyncio
async def test_scan_targets_basic(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url="https://httpbin.org",
        headers={"X-Powered-By": "PHP/7.4.33"},
        text="<title>PHP 7.4.33</title>",
    )
    results = await scan_targets(
        ["https://httpbin.org"], config={"max_concurrency": 5, "timeout": 5}
    )
    assert len(results) == 1
    assert results[0].php_version == "7.4.33"
    assert any("headers" in d or "combined" in d for d in results[0].detected_from)
    assert results[0].scan_time.tzinfo is not None


@pytest.mark.asyncio
async def test_scan_targets_cms_detection(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url="https://wp.example.com",
        text='<meta name="generator" content="WordPress 6.4.2" />',
    )
    results = await scan_targets(
        ["https://wp.example.com"], config={"max_concurrency": 5, "timeout": 5}
    )
    assert len(results) == 1
    assert any("cms" in item for item in results[0].detected_from)


@pytest.mark.asyncio
async def test_scan_targets_with_callback(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url="http://example.com",
        headers={"Server": "Apache/2 PHP/8.0.0"},
    )
    callback = MagicMock()
    results = await scan_targets(
        ["http://example.com"],
        config={"max_concurrency": 5, "timeout": 5},
        callback=callback,
    )
    assert len(results) == 1
    assert results[0].php_version == "8.0.0"
    assert callback.call_count == 1


@pytest.mark.asyncio
async def test_async_scanner_proxy_support(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url="https://test.com",
        headers={"X-Powered-By": "PHP/7.2.24"},
    )
    config = {
        "proxies": ["http://proxy.test:8080"],
        "max_concurrency": 5,
        "timeout": 5,
    }
    results = await scan_targets(["https://test.com"], config=config)
    assert len(results) == 1
    assert results[0].php_version == "7.2.24"


@pytest.mark.asyncio
async def test_scan_with_error(httpx_mock: HTTPXMock):
    httpx_mock.add_exception(httpx.RequestError("connection failed"), url="https://bad.url")
    results = await scan_targets(["https://bad.url"], config={"timeout": 3})
    assert len(results) == 1
    assert len(results[0].errors) > 0


@pytest.mark.asyncio
async def test_live_callback_is_called_exactly_once_per_target(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url="https://one.com", headers={"X-Powered-By": "PHP/7.4.33"}
    )
    httpx_mock.add_response(
        url="https://two.com", headers={"X-Powered-By": "PHP/8.1.0"}
    )
    calls = []

    def callback(result: ScanResult) -> None:
        calls.append(result.url)

    results = await scan_targets(
        ["https://one.com", "https://two.com"],
        config={"max_concurrency": 10, "timeout": 5},
        callback=callback,
    )
    assert len(results) == 2
    assert len(calls) == 2
    assert set(calls) == {"https://one.com", "https://two.com"}


@patch("phpfossil.scanner.validate_with_nuclei")
@patch("phpfossil.scanner.generate_summary")
@pytest.mark.asyncio
async def test_nuclei_ollama_and_exposed_files(mock_generate_summary, mock_validate, httpx_mock: HTTPXMock):
    mock_validate.return_value = [
        {"template": "php-rce-generic", "name": "RCE", "severity": "critical"}
    ]
    mock_generate_summary.return_value = "# Test Summary\nHigh risk."

    httpx_mock.add_response(
        url="https://httpbin.org",
        headers={"X-Powered-By": "PHP/7.4.33"},
        text="CREATE TABLE users (id INT);",
    )
    config = {
        "use_nuclei": True,
        "use_ollama": True,
        "max_concurrency": 5,
        "timeout": 5,
    }
    results = await scan_targets(["https://httpbin.org"], config=config)
    assert len(results) == 1
    assert results[0].php_version == "7.4.33"
    assert len(results[0].exposed_files) > 0
    assert len(results[0].nuclei_findings) > 0
    assert results[0].llm_summary == "# Test Summary\nHigh risk."


def test_persistent_store(tmp_path):
    db_path = tmp_path / "test_history.db"
    vuln = Vulnerability(
        cve="CVE-2021-1234",
        title="Test vuln",
        severity="high",
        description="Test",
    )
    result = ScanResult(
        url="https://example.com",
        php_version="7.4.33",
        vulns=[vuln],
        scan_time=datetime.now(timezone.utc),
    )
    store_results([result], db_path=str(db_path))
    history = get_historical_results(limit=5, db_path=str(db_path))
    assert len(history) >= 1
    assert any(r.url == "https://example.com" for r in history)
