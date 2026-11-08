"""Tests for the scanner module.

Covers async target scanning with pytest-httpx mocks, schema parsing,
error handling, input validation and CMS fingerprint integration.
Consistent with the production _probe_target behaviour (all paths
are probed for completeness).
"""

import re
from datetime import datetime
from typing import Any

import httpx
import pytest
from pytest_httpx import HTTPXMock

from phpfossil.models import ScanResult, SchemaResult
from phpfossil.scanner import scan_targets
from phpfossil.schema import parse_sql_dump


def test_parse_sql_dump_multiple_tables() -> None:
    """Test that parse_sql_dump correctly extracts multiple tables, columns and row counts.

    Uses realistic mysqldump-style content that exercises all regex branches.
    """
    content = """-- phpMyAdmin SQL Dump
CREATE TABLE users (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `posts` (
  `id` bigint(20) unsigned NOT NULL,
  `title` text NOT NULL,
  `user_id` int(11) DEFAULT NULL
) ENGINE=InnoDB;

INSERT INTO `users` (`id`, `name`) VALUES (1, 'Alice');
INSERT INTO `posts` (`id`, `title`, `user_id`) VALUES (1, 'Hello World', 1), (2, 'Test Post', 1);
"""

    schema: SchemaResult = parse_sql_dump(content)
    assert len(schema.tables) == 2
    assert schema.tables == ["users", "posts"]
    assert set(schema.columns.keys()) == {"users", "posts"}
    assert len(schema.columns["users"]) >= 2  # id, name
    assert len(schema.columns["posts"]) >= 3
    assert schema.row_counts["users"] == 1
    assert schema.row_counts["posts"] == 2


def test_scan_targets_with_mock(httpx_mock: HTTPXMock) -> None:
    """Test successful scan with version detection, exposed files and schema extraction.

    Registers responses for every URL probed by _probe_target so that
    pytest-httpx does not complain about unmatched requests.
    """
    base_url = "https://example.com"
    phpinfo_url = f"{base_url}/phpinfo.php"
    sql_url = f"{base_url}/dump.sql"

    # Main page – version in header
    httpx_mock.add_response(
        url=base_url,
        headers={"X-Powered-By": "PHP/7.4.33"},
        text="Welcome to our legacy PHP site",
    )

    # phpinfo page that also supplies a version
    httpx_mock.add_response(
        url=phpinfo_url,
        text="<h1>PHP Version 7.4.33</h1><p>Additional info here.</p>",
    )

    # SQL dump with two tables (matches test_parse_sql_dump_multiple_tables pattern)
    sql_content = """CREATE TABLE users (id int, name varchar(50));
CREATE TABLE posts (id int, title text);
INSERT INTO users VALUES (1, 'test');
INSERT INTO posts VALUES (1, 'hello');"""
    httpx_mock.add_response(url=sql_url, text=sql_content)

    # All other probed paths must return a non-matching response (404 or empty)
    other_paths = [
        "/info.php",
        "/php.php",
        "/backup.sql",
        "/db.sql",
        "/database.sql",
        "/schema.sql",
        "/nonexistent-404.php",
    ]
    for path in other_paths:
        httpx_mock.add_response(
            url=f"{base_url}{path}",
            status_code=404,
            text="Not Found",
        )

    results: list[ScanResult] = scan_targets(
        [base_url], config={"max_concurrency": 5, "timeout": 3}
    )

    assert len(results) == 1
    r = results[0]
    assert r.url == base_url
    assert r.php_version == "7.4.33"
    assert "headers" in r.detected_from
    assert "phpinfo" in r.detected_from
    assert len(r.exposed_files) >= 2  # phpinfo + sql_dump
    assert r.schema is not None
    assert len(r.schema.tables) >= 2
    assert len(r.errors) == 0
    assert isinstance(r.scan_time, datetime)


def test_scan_targets_with_error(httpx_mock: HTTPXMock) -> None:
    """Test error path using an exception so that the broad except block
    populates result.errors and the additional probes are never executed.
    """
    bad_url = "https://bad.example.com"

    httpx_mock.add_exception(
        httpx.ConnectTimeout("Connection timeout to bad host"),
        url=bad_url,
    )

    results: list[ScanResult] = scan_targets(
        [bad_url], config={"max_concurrency": 5, "timeout": 3}
    )

    assert len(results) == 1
    r = results[0]
    assert r.url == bad_url
    assert r.php_version is None
    assert len(r.errors) > 0
    assert any(
        keyword in err.lower()
        for err in r.errors
        for keyword in ("timeout", "connect", "connection")
    )
    assert r.schema is None
    assert len(r.exposed_files) == 0


def test_scan_targets_invalid_input() -> None:
    """Validate input guards in scan_targets."""
    with pytest.raises(ValueError, match="targets must be a non-empty list"):
        scan_targets([])

    with pytest.raises(
        ValueError, match="All targets must be valid http/https URLs"
    ):
        scan_targets(["ftp://bad.com", "http://good.com"])


def test_scan_targets_multiple_targets(httpx_mock: HTTPXMock) -> None:
    """Concurrent scan of several targets (verifies semaphore and proxy logic path)."""
    urls = ["https://site1.test", "https://site2.test"]

    for url in urls:
        httpx_mock.add_response(
            url=url,
            headers={"Server": "nginx PHP/8.1.2"},
            text="OK",
        )
        for path in (
            "/phpinfo.php",
            "/info.php",
            "/php.php",
            "/dump.sql",
            "/backup.sql",
            "/db.sql",
            "/database.sql",
            "/schema.sql",
            "/nonexistent-404.php",
        ):
            httpx_mock.add_response(url=f"{url}{path}", status_code=404)

    results: list[ScanResult] = scan_targets(
        urls, config={"max_concurrency": 10, "timeout": 5}
    )

    assert len(results) == 2
    for r in results:
        assert r.php_version == "8.1.2"
        assert "headers" in r.detected_from
        assert len(r.errors) == 0


def test_scan_targets_with_schema_only(httpx_mock: HTTPXMock) -> None:
    """Target that only exposes a SQL dump (no PHP version)."""
    url = "https://schema-only.test"
    sql_content = "CREATE TABLE config (key varchar(50), value text);"

    httpx_mock.add_response(url=url, text="No version strings here")
    httpx_mock.add_response(url=f"{url}/dump.sql", text=sql_content)

    for path in (
        "/phpinfo.php",
        "/info.php",
        "/php.php",
        "/backup.sql",
        "/db.sql",
        "/database.sql",
        "/schema.sql",
        "/nonexistent-404.php",
    ):
        httpx_mock.add_response(url=f"{url}{path}", status_code=404)

    results: list[ScanResult] = scan_targets([url], config={"timeout": 4})
    assert len(results) == 1
    r = results[0]
    assert r.php_version is None
    assert r.schema is not None
    assert "config" in r.schema.tables
    assert len(r.exposed_files) == 1
    assert r.exposed_files[0].file_type == "sql_dump"


def test_scan_targets_vuln_mapping(httpx_mock: HTTPXMock) -> None:
    """When a vulnerable version is detected, vulns list is populated."""
    url = "https://vulnerable.test"
    httpx_mock.add_response(
        url=url,
        headers={"X-Powered-By": "PHP/5.6.40"},
        text="old PHP",
    )
    for path in (
        "/phpinfo.php",
        "/info.php",
        "/php.php",
        "/dump.sql",
        "/backup.sql",
        "/db.sql",
        "/database.sql",
        "/schema.sql",
        "/nonexistent-404.php",
    ):
        httpx_mock.add_response(url=f"{url}{path}", status_code=404)

    results: list[ScanResult] = scan_targets([url])
    assert len(results) == 1
    r = results[0]
    assert r.php_version == "5.6.40"
    assert len(r.vulns) > 0
    assert any(v.cve.startswith("CVE-") for v in r.vulns)


def test_scan_targets_proxy_rotation(httpx_mock: HTTPXMock) -> None:
    """Smoke test that proxy config is accepted and rotated (no real proxy)."""
    urls = ["https://a.test", "https://b.test"]
    for u in urls:
        httpx_mock.add_response(url=u, text="proxied")
        for p in (
            "/phpinfo.php",
            "/info.php",
            "/php.php",
            "/dump.sql",
            "/backup.sql",
            "/db.sql",
            "/database.sql",
            "/schema.sql",
            "/nonexistent-404.php",
        ):
            httpx_mock.add_response(url=f"{u}{p}", status_code=404)

    config: dict[str, Any] = {
        "max_concurrency": 2,
        "timeout": 5,
        "proxies": ["http://proxy1:8080", "http://proxy2:8080"],
    }
    results = scan_targets(urls, config=config)
    assert len(results) == 2
    for r in results:
        assert len(r.errors) == 0
