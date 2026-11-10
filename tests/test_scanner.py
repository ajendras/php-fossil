"""Tests for the scanner module including live callback support for TUI."""

import asyncio
from unittest.mock import patch

import pytest
from pytest_httpx import HTTPXMock

from phpfossil.models import ScanResult
from phpfossil.scanner import AsyncScanner, scan_targets


@pytest.mark.asyncio
async def test_scan_targets_basic(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url="https://httpbin.org",
        text="<title>Test</title><h1>PHP Version 7.4.33</h1>",
        headers={"X-Powered-By": "PHP/7.4.33"},
    )
    results = await scan_targets(["https://httpbin.org"])
    assert len(results) == 1
    assert results[0].php_version == "7.4.33"
    assert "headers" in results[0].detected_from


@pytest.mark.asyncio
async def test_scan_targets_with_callback(httpx_mock: HTTPXMock):
    calls = []

    def callback(result: ScanResult) -> None:
        calls.append(result)
        assert isinstance(result, ScanResult)

    httpx_mock.add_response(
        url="http://example.com",
        text="PHP Version 8.0.0",
        headers={},
    )
    results = await scan_targets(
        ["http://example.com"],
        config={"max_concurrency": 3},
        callback=callback,
    )
    assert len(results) == 1
    assert len(calls) == 1
    assert calls[0].url == "http://example.com"


@pytest.mark.asyncio
async def test_async_scanner_proxy_support(httpx_mock: HTTPXMock):
    scanner = AsyncScanner(config={"proxies": ["http://proxy1:8080"]})
    httpx_mock.add_response(url="https://test.com", text="PHP 7.3")
    results = await scanner.scan(["https://test.com"])
    assert len(results) == 1


@pytest.mark.asyncio
async def test_scan_with_error(httpx_mock: HTTPXMock):
    httpx_mock.add_exception(Exception("Connection error"), url="https://bad.url")
    results = await scan_targets(["https://bad.url"])
    assert len(results) == 1
    assert len(results[0].errors) > 0


@pytest.mark.asyncio
async def test_scan_targets_cms_detection(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url="https://wp.example.com",
        text='<meta name="generator" content="WordPress 6.1.1">',
    )
    results = await scan_targets(["https://wp.example.com"])
    assert len(results) == 1
    assert any("cms:wordpress" in d for d in results[0].detected_from)


@pytest.mark.asyncio
async def test_live_callback_is_called_exactly_once_per_target(httpx_mock: HTTPXMock):
    calls = 0

    def callback(result: ScanResult) -> None:
        nonlocal calls
        calls += 1

    httpx_mock.add_response(url="https://one.com", text="PHP 7.4")
    httpx_mock.add_response(url="https://two.com", text="PHP 8.1")
    await scan_targets(
        ["https://one.com", "https://two.com"],
        config={"max_concurrency": 2},
        callback=callback,
    )
    assert calls == 2
