"""Tests for the scanner module, schema parsing, proxy rotation and related components."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
from pytest_httpx import HTTPXMock

from phpfossil.models import ScanResult, SchemaResult, Vulnerability
from phpfossil.scanner import scan_targets, _validate_proxies
from phpfossil.schema import parse_sql_dump, locate_sql_urls
from phpfossil.store import Store, get_historical_results, store_results


def test_parse_sql_dump_multiple_tables():
    """Test parsing SQL with multiple tables (was asserting 1==2)."""
    sql = """CREATE TABLE `users` (
  `id` integer NOT NULL,
  `name` varchar(100) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `posts` (
  `id` int(11) NOT NULL,
  `title` text NOT NULL,
  `content` longtext
) ENGINE=InnoDB;

INSERT INTO `users` VALUES (1, 'Alice');
INSERT INTO `posts` VALUES (1, 'Hello', 'World');
"""

    schema: SchemaResult = parse_sql_dump(sql)
    assert len(schema.tables) == 2
    assert schema.tables == ["users", "posts"]
    assert len(schema.columns.get("users", [])) == 2
    assert len(schema.columns.get("posts", [])) == 3
    assert schema.row_counts["users"] == 1
    assert schema.row_counts["posts"] == 1


@pytest.mark.asyncio
async def test_scan_targets_with_mock(httpx_mock: HTTPXMock):
    """Test scan_targets with mocked responses (was missing 'phpinfo' in detected_from)."""
    base_url = "https://example.com"

    # Main response triggers header detection
    httpx_mock.add_response(
        url=base_url,
        headers={"X-Powered-By": "PHP/7.4.33"},
        text="<html><body>Legacy PHP site</body></html>",
    )

    # phpinfo page (triggers exposed file + phpinfo detection flag)
    phpinfo_content = """<html><head><title>phpinfo()</title></head>
<body><h1>PHP Version 7.4.33</h1>
<table><tr><td>Version</td><td>7.4.33</td></tr></table></body></html>"""
    httpx_mock.add_response(
        url=f"{base_url}/phpinfo.php",
        text=phpinfo_content,
    )

    # SQL dump with multiple tables (triggers schema parsing)
    sql_content = """CREATE TABLE users (id integer, name varchar(50));
CREATE TABLE posts (id int, title text, content longtext);
INSERT INTO users VALUES (1, 'test');
INSERT INTO posts VALUES (1, 'post1');"""
    httpx_mock.add_response(
        url=f"{base_url}/dump.sql",
        text=sql_content,
    )

    # All other probed paths return non-triggering responses
    for path in [
        "/info.php",
        "/php.php",
        "/backup.sql",
        "/db.sql",
        "/database.sql",
        "/schema.sql",
        "/nonexistent-404.php",
    ]:
        httpx_mock.add_response(
            url=base_url + path,
            status_code=404,
            text="Not Found",
        )

    results = scan_targets(
        [base_url], config={"max_concurrency": 5, "timeout": 5}
    )
    assert len(results) == 1
    r: ScanResult = results[0]
    assert r.url == base_url
    assert r.php_version == "7.4.33"
    assert "http-response" in r.detected_from
    assert "headers" in r.detected_from
    assert "phpinfo" in r.detected_from
    assert len(r.exposed_files) == 2
    assert any(f.file_type == "phpinfo" for f in r.exposed_files)
    assert any(f.file_type == "sql_dump" for f in r.exposed_files)
    assert r.schema is not None
    assert len(r.schema.tables) == 2
    assert r.schema.row_counts == {"users": 1, "posts": 1}
    assert len(r.vulns) > 0
    assert len(r.errors) == 0


@pytest.mark.asyncio
async def test_scan_targets_proxy_rotation(httpx_mock: HTTPXMock):
    """Test proxy rotation no longer raises 'proxies' keyword error (was assert 1==0)."""
    targets = ["https://a.test", "https://b.test"]
    proxies = [
        "http://proxy1.example.com:8080",
        "http://proxy2.example.com:8080",
    ]

    for base in targets:
        httpx_mock.add_response(
            url=base,
            headers={"X-Powered-By": "PHP/7.4.33"},
            text="OK",
        )
        for p in ("/phpinfo.php", "/info.php", "/php.php"):
            httpx_mock.add_response(url=base + p, status_code=200, text="no phpinfo")
        for s in (
            "/dump.sql",
            "/backup.sql",
            "/db.sql",
            "/database.sql",
            "/schema.sql",
        ):
            httpx_mock.add_response(url=base + s, status_code=404)
        httpx_mock.add_response(
            url=base + "/nonexistent-404.php",
            status_code=404,
            text="PHP Version 7.4.33",
        )

    config: dict[str, Any] = {
        "max_concurrency": 10,
        "timeout": 5,
        "proxies": proxies,
    }
    results = scan_targets(targets, config=config)
    assert len(results) == 2
    for r in results:
        assert len(r.errors) == 0
        assert r.php_version is not None
        assert "http-response" in r.detected_from


def test_validate_proxies():
    """Test internal proxy list validation."""
    assert _validate_proxies(None) == []
    assert _validate_proxies([]) == []
    assert _validate_proxies(["http://p1"]) == ["http://p1"]
    with pytest.raises(ValueError, match="must be a list"):
        _validate_proxies("bad")
    with pytest.raises(ValueError, match="Invalid proxy URL"):
        _validate_proxies([None])


def test_scan_targets_validation():
    """Test input validation in scan_targets."""
    with pytest.raises(ValueError, match="non-empty list"):
        scan_targets([])
    with pytest.raises(ValueError, match="valid http/https"):
        scan_targets(["ftp://bad"])


def test_locate_sql_urls():
    """Test SQL URL locator."""
    urls = locate_sql_urls("https://example.com/path")
    assert len(urls) >= 10
    assert any("dump.sql" in u for u in urls)
    assert all(u.startswith("https://example.com/path/") for u in urls)


def test_store_integration(tmp_path: Path):
    """Test persistence roundtrip (Store integration)."""
    db_path = tmp_path / "history.db"
    result = ScanResult(
        url="https://test.example.com",
        php_version="7.4.33",
        detected_from=["headers"],
        vulns=[
            Vulnerability(
                cve="CVE-2019-1234",
                title="Test vuln",
                severity="high",
                description="Test",
            )
        ],
        schema=SchemaResult(tables=["users"], columns={"users": ["id"]}, row_counts={"users": 5}),
    )
    store_results([result], db_path=db_path)
    history = get_historical_results(limit=10, db_path=db_path)
    assert len(history) >= 1
    assert history[0].url == "https://test.example.com"
    assert history[0].php_version == "7.4.33"
