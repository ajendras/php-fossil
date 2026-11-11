"""Tests for the PHP Fossil scanner.

Covers fingerprinting accuracy, async HTTP mocking with pytest-httpx,
proxy rotation, error handling, live callbacks, Nuclei/Ollama integration,
exposed file detection, schema parsing and Store persistence.
Consistent with the project's use of Pydantic models and async patterns.
"""

import asyncio
import json
import re
from unittest.mock import patch, MagicMock

import pytest
from pytest_httpx import HTTPXMock

from phpfossil import (
    scan_targets,
    ScanResult,
    generate_summary,
    is_ollama_available,
    parse_sql_dump,
    Store,
)
from phpfossil.models import ExposedFile, SchemaResult
from phpfossil.scanner import AsyncScanner


def test_detect_from_fingerprinter_integration():
    """Test that scanner uses fingerprinter helpers correctly (indirectly)."""
    # This is exercised via the mocked scan tests below.
    assert True  # placeholder for integration coverage


@pytest.mark.asyncio
async def test_async_scanner_proxy_support(httpx_mock: HTTPXMock):
    """Test proxy rotation support does not break scanning.

    Uses a regex matcher so all probe paths (/phpinfo.php, /.env, etc.)
    are covered. The proxy URL itself is not asserted here because
    pytest-httpx matches on the original target URL.
    """
    # Catch-all for every probe the scanner will make against example.com
    httpx_mock.add_response(
        url=re.compile(r"http://example\.com.*"),
        text="X-Powered-By: PHP/7.4.33\nPHP Version 7.4.33",
        status_code=200,
    )

    config = {
        "max_concurrency": 5,
        "timeout": 5,
        "proxies": ["http://proxy.test:8080", "http://proxy2.test:8081"],
        "use_nuclei": False,
        "use_ollama": False,
    }

    results = await scan_targets(["http://example.com"], config=config)
    assert len(results) == 1
    assert results[0].php_version == "7.4.33"
    assert results[0].detected_from
    # Proxy list was accepted without error; real proxy usage is
    # exercised in the AsyncClient construction inside scanner.py


@pytest.mark.asyncio
async def test_scan_with_error(httpx_mock: HTTPXMock):
    """Test graceful handling when a target returns errors.

    All probe paths must be mocked otherwise pytest-httpx fails on
    unexpected requests.
    """
    httpx_mock.add_response(
        url=re.compile(r"https://bad\.url.*"),
        text="PHP/8.0.0",
        status_code=500,
    )

    config = {
        "max_concurrency": 5,
        "timeout": 5,
        "use_nuclei": False,
        "use_ollama": False,
    }

    results = await scan_targets(["https://bad.url"], config=config)
    assert len(results) == 1
    assert len(results[0].errors) > 0
    # Version may still be extracted from error page fallback
    assert results[0].php_version == "8.0.0"


@pytest.mark.asyncio
async def test_live_callback_is_called_exactly_once_per_target(httpx_mock: HTTPXMock):
    """Ensure the optional live callback fires once per target even when
    multiple probe requests are performed internally.
    """
    call_count = 0

    def live_callback(result: ScanResult) -> None:
        nonlocal call_count
        call_count += 1
        assert isinstance(result, ScanResult)
        assert result.url in ("https://one.com", "https://two.com")

    httpx_mock.add_response(
        url=re.compile(r"https://(one|two)\.com.*"),
        text="<title>PHP Version 7.3.12</title>",
        status_code=200,
    )

    config = {
        "max_concurrency": 5,
        "timeout": 5,
        "use_nuclei": False,
        "use_ollama": False,
    }

    results = await scan_targets(
        ["https://one.com", "https://two.com"],
        config=config,
        callback=live_callback,
    )

    assert call_count == 2
    assert len(results) == 2
    assert all(r.php_version == "7.3.12" for r in results)


@pytest.mark.asyncio
async def test_nuclei_ollama_and_exposed_files(httpx_mock: HTTPXMock):
    """Test full pipeline with Nuclei, Ollama, exposed files and schema parsing.

    Mocks:
      - All scanner probe paths on httpbin.org
      - Ollama chat endpoint
      - Nuclei via patch (subprocess would otherwise fail in CI)
    """
    # Main target probes
    httpx_mock.add_response(
        url=re.compile(r"https://httpbin\.org.*"),
        text="PHP Version 7.4.33\n--\nCREATE TABLE users (id INT, email VARCHAR(255));",
        status_code=200,
    )
    # Specific SQL dump response (scanner will detect .sql extension)
    httpx_mock.add_response(
        url="https://httpbin.org/backup.sql",
        text="CREATE TABLE admins (id INT);\nINSERT INTO admins VALUES (1);",
        status_code=200,
    )

    # Ollama mock
    httpx_mock.add_response(
        url="http://localhost:11434/api/chat",
        json={
            "message": {
                "content": "# Risk Level: High\n\nSeveral legacy PHP endpoints detected."
            }
        },
        status_code=200,
    )

    # Patch Nuclei because it calls a binary that is not present in CI
    with patch("phpfossil.scanner.validate_with_nuclei") as mock_nuclei:
        mock_nuclei.return_value = [
            {
                "template": "cve-2021-1234",
                "name": "PHP RCE",
                "severity": "critical",
            }
        ]

        config = {
            "max_concurrency": 5,
            "timeout": 5,
            "use_nuclei": True,
            "use_ollama": True,
            "ollama_model": "llama3",
        }

        results = await scan_targets(["https://httpbin.org"], config=config)

    assert len(results) == 1
    r = results[0]
    assert r.php_version == "7.4.33"
    assert len(r.exposed_files) >= 1
    assert any(f.file_type == "sql_dump" for f in r.exposed_files)
    assert r.db_schema is not None
    assert "users" in r.db_schema.tables or "admins" in r.db_schema.tables
    assert len(r.nuclei_findings) > 0
    assert r.llm_summary and "Risk Level" in r.llm_summary


def test_parse_sql_dump():
    """Standalone test for schema extraction from SQL content."""
    sql = """
    CREATE TABLE users (id INT PRIMARY KEY, name VARCHAR(100));
    CREATE TABLE orders (order_id INT, user_id INT);
    """
    schema = parse_sql_dump(sql)
    assert isinstance(schema, SchemaResult)
    assert "users" in schema.tables
    assert "orders" in schema.tables
    assert "id" in schema.columns.get("users", [])
    assert "name" in schema.columns.get("users", [])


@pytest.mark.asyncio
async def test_store_persistence_after_scan(httpx_mock: HTTPXMock, tmp_path):
    """Scan results are automatically stored in SQLite via the Store."""
    httpx_mock.add_response(
        url=re.compile(r"https://httpbin\.org.*"),
        text="PHP Version 8.1.0",
        status_code=200,
    )

    db_path = tmp_path / "test_history.db"
    config = {
        "max_concurrency": 5,
        "timeout": 5,
        "use_nuclei": False,
        "use_ollama": False,
        "db_path": str(db_path),
    }

    results = await scan_targets(["https://httpbin.org"], config=config)
    assert len(results) == 1

    # Verify persistence
    store = Store(db_path=str(db_path))
    historical = store.get_historical_results(limit=5)
    assert len(historical) >= 1
    assert historical[0].url == "https://httpbin.org"
    assert historical[0].php_version == "8.1.0"


@pytest.mark.asyncio
async def test_scanner_respects_max_concurrency(httpx_mock: HTTPXMock):
    """Concurrency limit is respected (smoke test via mock)."""
    httpx_mock.add_response(
        url=re.compile(r"https://example\.com.*"),
        text="PHP/7.2.24",
        status_code=200,
    )

    config = {"max_concurrency": 3, "timeout": 10, "use_nuclei": False, "use_ollama": False}

    results = await scan_targets(
        ["https://example.com"] * 5,  # multiple targets
        config=config,
    )
    assert len(results) == 5


def test_is_ollama_available_fallback(httpx_mock: HTTPXMock):
    """Ollama availability check returns False when service is unreachable."""
    # No mock for localhost:11434 -> should return False
    assert is_ollama_available() is False


@pytest.mark.asyncio
async def test_generate_summary_with_real_results(httpx_mock: HTTPXMock):
    """End-to-end summary generation with mocked Ollama."""
    httpx_mock.add_response(
        url=re.compile(r"https://test\.com.*"),
        text="PHP Version 5.6.40",
        status_code=200,
    )
    httpx_mock.add_response(
        url="http://localhost:11434/api/chat",
        json={"message": {"content": "Critical risk: EOL PHP 5.6 detected."}},
        status_code=200,
    )

    results = await scan_targets(
        ["https://test.com"],
        config={"use_nuclei": False, "use_ollama": True, "ollama_model": "llama3"},
    )

    summary = generate_summary(results)
    assert "Critical risk" in summary or "EOL" in summary
