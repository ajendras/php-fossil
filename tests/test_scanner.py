"""Tests for scanner, fingerprinting, schema parsing and mocks."""

import pytest
from pytest_httpx import HTTPXMock

from phpfossil.scanner import scan_targets
from phpfossil.schema import parse_sql_dump
from phpfossil.vulndb import get_vulns_for_version
from phpfossil.models import ScanResult, SchemaResult


def test_parse_sql_dump():
    sql = """CREATE TABLE `users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

CREATE TABLE `posts` (
  `id` int(11) NOT NULL,
  `title` varchar(100),
  `content` text
);

INSERT INTO `users` VALUES (1,'admin');
INSERT INTO `posts` VALUES (1,'hello','world');
"""
    result: SchemaResult = parse_sql_dump(sql)
    assert len(result.tables) == 2
    assert result.tables == ["users", "posts"]
    assert len(result.columns.get("users", [])) == 2
    assert len(result.columns.get("posts", [])) == 3
    assert result.row_counts.get("users", 0) == 1
    assert result.row_counts.get("posts", 0) == 1


def test_load_vulndb():
    vulns = get_vulns_for_version("5.6.40")
    assert len(vulns) > 5
    assert all(v.severity in ("critical", "high", "medium", "low") for v in vulns)


def test_scan_targets_with_mock(httpx_mock: HTTPXMock):
    # Mock the main target (triggers header + body detection)
    httpx_mock.add_response(
        url="https://example.com",
        headers={"X-Powered-By": "PHP/7.4.33"},
        text="PHP Version 7.4.33",
        status_code=200,
    )
    # Mock phpinfo probe (second in loop after /phpinfo.php 404)
    httpx_mock.add_response(
        url="https://example.com/info.php",
        text="<h1>PHP Version 7.4.33</h1><p>phpinfo()</p>",
        status_code=200,
    )
    # Mock sql dump probe
    httpx_mock.add_response(
        url="https://example.com/dump.sql",
        text="CREATE TABLE users (id int); INSERT INTO users VALUES (1); -- mysqldump",
        status_code=200,
    )
    # Mock remaining probes so we do not trigger "no mock found" errors
    for extra_path in (
        "/phpinfo.php",
        "/php.php",
        "/nonexistent-404.php",
        "/backup.sql",
        "/db.sql",
        "/database.sql",
        "/schema.sql",
    ):
        httpx_mock.add_response(
            url=f"https://example.com{extra_path}",
            status_code=404,
        )

    results = scan_targets(
        ["https://example.com"], config={"max_concurrency": 5, "timeout": 5}
    )
    assert len(results) == 1
    r = results[0]
    assert r.url == "https://example.com"
    assert r.php_version == "7.4.33"
    assert any(src in r.detected_from for src in ("headers", "body", "phpinfo"))
    assert len(r.exposed_files) >= 1
    assert any(f.file_type == "sql_dump" for f in r.exposed_files)
    assert len(r.vulns) > 0
