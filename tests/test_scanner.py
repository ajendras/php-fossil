"""Tests for the scanner module."""

import asyncio
from datetime import datetime
import pytest
from pytest_httpx import HTTPXMock

from phpfossil.scanner import scan_targets, _validate_proxies
from phpfossil.models import ScanResult
from phpfossil.store import store_results, get_historical_results


def test_validate_proxies():
    """Test proxy list validation helper."""
    assert _validate_proxies(None) == []
    assert _validate_proxies([]) == []
    assert _validate_proxies(["http://proxy1:8080"]) == ["http://proxy1:8080"]
    with pytest.raises(ValueError, match="must be a list"):
        _validate_proxies("not-a-list")
    with pytest.raises(ValueError, match="Invalid proxy URL"):
        _validate_proxies([123])


@pytest.mark.asyncio
async def test_scan_targets_validation():
    """Test input validation for scan_targets."""
    with pytest.raises(ValueError, match="non-empty list of URL strings"):
        await scan_targets([])

    with pytest.raises(ValueError, match="All targets must be valid http/https URLs"):
        await scan_targets(["ftp://bad.target"])


@pytest.mark.asyncio
async def test_scan_targets_with_mock(httpx_mock: HTTPXMock):
    """Test full scan flow with httpx mocks for common PHP/exposed file paths."""
    base = "https://example.com"
    paths = [
        "",
        "/phpinfo.php",
        "/info.php",
        "/php.php",
        "/dump.sql",
        "/backup.sql",
        "/db.sql",
        "/database.sql",
        "/schema.sql",
        "/nonexistent-404.php",
    ]
    for path in paths:
        url = base + path
        if any(p in path for p in ("phpinfo", "info", "php.php")):
            httpx_mock.add_response(
                url=url,
                text="<title>phpinfo()</title><h1>PHP Version 7.4.33</h1>",
                status_code=200,
            )
        elif any(p in path for p in ("dump", "backup", "db", "database", "schema")):
            httpx_mock.add_response(
                url=url,
                text="CREATE TABLE users (id INT);\n-- mysqldump",
                status_code=200,
            )
        else:
            httpx_mock.add_response(
                url=url, text="Not Found", status_code=404
            )

    results = await scan_targets(
        [base],
        config={
            "max_concurrency": 10,
            "timeout": 5,
            "use_nuclei": False,
        },
    )

    assert len(results) == 1
    r: ScanResult = results[0]
    assert r.url == base
    assert r.php_version == "7.4.33"
    assert len(r.exposed_files) >= 2
    assert any(f.file_type == "phpinfo" for f in r.exposed_files)
    assert any(f.file_type == "sql_dump" for f in r.exposed_files)
    assert any(src in r.detected_from for src in ("headers", "body", "phpinfo"))
    assert len(r.vulns) > 0
    assert not r.errors


@pytest.mark.asyncio
async def test_scan_targets_proxy_rotation(httpx_mock: HTTPXMock):
    """Test proxy rotation with multiple targets and verify no errors."""
    bases = ["https://a.test", "https://b.test"]
    paths = [
        "",
        "/phpinfo.php",
        "/info.php",
        "/php.php",
        "/dump.sql",
        "/backup.sql",
        "/db.sql",
        "/database.sql",
        "/schema.sql",
        "/nonexistent-404.php",
    ]
    for base in bases:
        for path in paths:
            url = base if not path else base + path
            if any(p in path for p in ("phpinfo", "info", "php.php")):
                httpx_mock.add_response(
                    url=url,
                    text="<h1>PHP Version 8.1.0</h1>",
                    status_code=200,
                )
            elif any(sql in path for sql in ("dump", "backup", "db", "database", "schema")):
                httpx_mock.add_response(
                    url=url,
                    text="CREATE TABLE test (id INT);",
                    status_code=200,
                )
            else:
                httpx_mock.add_response(url=url, text="Not Found", status_code=404)

    proxies = ["http://proxy1:8080", "http://proxy2:8080"]
    results = await scan_targets(
        bases,
        config={
            "max_concurrency": 5,
            "timeout": 5,
            "proxies": proxies,
            "use_nuclei": False,
        },
    )

    assert len(results) == 2
    for r in results:
        assert r.php_version is not None
        assert len(r.exposed_files) > 0 or any(
            "phpinfo" in src for src in r.detected_from
        )
        assert not r.errors


def test_store_integration():
    """Test integration with persistent store via models."""
    results = [
        ScanResult(
            url="https://test.example.com",
            php_version="7.4.33",
            detected_from=["headers", "phpinfo"],
            vulns=[],
        )
    ]
    store_results(results)

    history = get_historical_results(limit=3)
    assert len(history) >= 1
    assert any(r.url == "https://test.example.com" for r in history)

    # Test with in-memory store for isolation
    from phpfossil.store import Store
    mem_store = Store(db_path=":memory:")
    mem_store.save_scan_results(results)
    mem_history = mem_store.get_recent_results(limit=1)
    assert len(mem_history) == 1
