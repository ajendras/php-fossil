"""Tests for the PHP Fossil scanner module.

Covers fingerprinting, schema extraction, Nuclei and Ollama integration,
live callbacks, error handling and async operation using pytest-httpx mocks.
"""

import asyncio
import re
from unittest.mock import MagicMock, patch

import pytest
from pytest_httpx import HTTPXMock

from phpfossil import scan_targets, ScanResult
from phpfossil.models import SchemaResult
from phpfossil.schema import parse_sql_dump


@pytest.mark.asyncio
async def test_scan_targets(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url="http://example.com",
        headers={"X-Powered-By": "PHP/7.2.5"},
        text="PHP Version 7.2.5",
    )
    httpx_mock.add_response(
        url="https://httpbin.org",
        headers={"X-Powered-By": "PHP/8.1.0"},
        text="PHP Version 8.1.0",
    )

    results = await scan_targets(
        ["http://example.com", "https://httpbin.org"],
        config={
            "max_concurrency": 2,
            "timeout": 5,
            "use_nuclei": False,
            "use_ollama": False,
            "use_community_fingerprints": False,
        },
    )

    assert len(results) == 2
    versions = {r.php_version for r in results if r.php_version}
    assert "7.2.5" in versions
    assert "8.1.0" in versions


@pytest.mark.asyncio
async def test_async_scanner_direct(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url="http://example.com",
        headers={"Server": "PHP/7.4.33"},
        text="PHP Version 7.4.33",
    )

    results = await scan_targets(
        ["http://example.com"],
        config={"timeout": 5, "use_nuclei": False, "use_ollama": False},
    )

    assert len(results) == 1
    assert results[0].php_version == "7.4.33"
    assert "headers" in results[0].detected_from or "body" in results[0].detected_from


def test_scanner_with_nuclei(httpx_mock: HTTPXMock):
    with patch("phpfossil.nuclei.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            stdout='{"template-id": "phpinfo-detect", "info": {"name": "PHPInfo", "severity": "info"}}\n',
            returncode=0,
            stderr="",
        )
        httpx_mock.add_response(
            url="https://httpbin.org",
            headers={"X-Powered-By": "PHP/5.6.40"},
            text="<h1>PHP Version 5.6.40</h1>",
        )

        results = asyncio.run(
            scan_targets(
                ["https://httpbin.org"],
                config={
                    "use_nuclei": True,
                    "timeout": 5,
                    "use_ollama": False,
                    "use_community_fingerprints": False,
                },
            )
        )

        assert len(results) == 1
        assert results[0].php_version == "5.6.40"
        assert len(results[0].nuclei_findings) >= 0


@pytest.mark.asyncio
async def test_scanner_with_ollama(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url="https://httpbin.org",
        headers={"X-Powered-By": "PHP/7.4.33"},
        text="PHP Version 7.4.33",
    )
    httpx_mock.add_response(
        url="http://localhost:11434/api/tags",
        json={"models": [{"name": "llama3"}]},
    )
    httpx_mock.add_response(
        url="http://localhost:11434/api/chat",
        json={"message": {"content": "# Test Ollama Summary\n\nRisk Level: Medium"}},
    )

    results = await scan_targets(
        ["https://httpbin.org"],
        config={
            "use_ollama": True,
            "ollama_model": "llama3",
            "timeout": 5,
            "max_concurrency": 5,
            "use_nuclei": False,
            "use_community_fingerprints": False,
        },
    )

    assert len(results) == 1
    assert results[0].php_version == "7.4.33"
    assert results[0].llm_summary is not None
    assert "body" in results[0].detected_from or "headers" in results[0].detected_from


def test_scanner_live_callback(httpx_mock: HTTPXMock):
    callback_results: list[ScanResult] = []

    def live_callback(result: ScanResult) -> None:
        callback_results.append(result)

    httpx_mock.add_response(
        url="https://httpbin.org",
        headers={"X-Powered-By": "PHP/8.0.0"},
        text="PHP Version 8.0.0",
    )

    results = asyncio.run(
        scan_targets(
            ["https://httpbin.org"],
            config={"timeout": 5, "use_nuclei": False, "use_ollama": False},
            callback=live_callback,
        )
    )

    assert len(results) == 1
    assert results[0].php_version == "8.0.0"
    assert len(callback_results) == 1
    assert callback_results[0].php_version == "8.0.0"


@pytest.mark.asyncio
async def test_scanner_with_schema(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url="https://httpbin.org",
        text="Test site index",
        headers={},
    )
    sql_dump = """-- phpMyAdmin SQL Dump
CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `username` varchar(50) NOT NULL
);
CREATE TABLE `payments` (
  `id` int(11),
  `amount` decimal(10,2)
);
INSERT INTO `users` VALUES (1,'admin');
"""
    httpx_mock.add_response(
        url="https://httpbin.org/backup.sql",
        text=sql_dump,
        headers={"Content-Type": "application/sql"},
    )

    results = await scan_targets(
        ["https://httpbin.org"],
        config={"timeout": 5, "use_nuclei": False, "use_ollama": False},
    )

    assert len(results) == 1
    assert results[0].db_schema is not None
    assert len(results[0].db_schema.tables) >= 2
    assert "users" in results[0].db_schema.tables
    assert "payments" in results[0].db_schema.tables
    # sensitive tables + schema exposure raises risk score
    assert results[0].risk_score > 30
    assert any(f.file_type == "sql_dump" for f in results[0].exposed_files)


def test_scan_error_handling(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=re.compile(r"https://bad\.example\.com.*"),
        status_code=503,
        text="Service unavailable",
    )

    results = asyncio.run(
        scan_targets(
            ["https://bad.example.com"],
            config={"timeout": 5, "use_nuclei": False, "use_ollama": False},
        )
    )

    assert len(results) == 1
    assert len(results[0].errors) > 0
    assert results[0].php_version is None


def test_parse_sql_dump():
    sql = """CREATE TABLE admins (id INT, pass TEXT);
INSERT INTO admins VALUES (1, 'secret');
CREATE TABLE `orders` (id INT);"""
    schema = parse_sql_dump(sql)
    assert "admins" in schema.tables
    assert "orders" in schema.tables
    assert schema.row_counts["admins"] > 0
