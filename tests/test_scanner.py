"""Test suite for scanner and fingerprinter."""

import pytest
from pytest_httpx import HTTPXMock

from phpfossil.fingerprinter import (
    detect_from_body,
    detect_from_error_page,
    detect_from_headers,
    detect_from_phpinfo,
    detect_php_version,
)
from phpfossil.models import ScanResult
from phpfossil.scanner import scan_targets


def test_detect_php_version_helpers():
    """Test all detection helpers, including the previously failing body case."""
    # Body detection for inline PHP echo (was returning None)
    assert detect_php_version(body='<?php echo "PHP Version 5.6.40"; ?>') == "5.6.40"
    assert detect_from_body('<?php echo "PHP Version 5.6.40"; ?>') == "5.6.40"

    # Headers
    assert detect_from_headers({"X-Powered-By": "PHP/7.4.33"}) == "7.4.33"
    assert detect_from_headers({}) is None
    assert detect_from_headers(None) is None

    # phpinfo
    assert detect_from_phpinfo("<title>phpinfo()</title><h1>PHP Version 8.0.1</h1>") == "8.0.1"

    # error page
    assert detect_from_error_page("PHP Version: 5.6.40") == "5.6.40"
    assert detect_from_error_page("some error PHP/7.2.5") == "7.2.5"
    assert detect_from_error_page("(PHP 7.1.33)") == "7.1.33"

    # priority order
    assert detect_php_version(
        headers={"Server": "PHP/8.2.0"},
        phpinfo_content="PHP Version 7.4",
        body="PHP 5.6"
    ) == "8.2.0"


def test_scan_targets_with_mock(httpx_mock: HTTPXMock):
    """Test async scan with mocked responses for all probe paths.

    All mocked URLs are now requested because we probe every location
    (no early breaks) and always probe the error page.
    """
    url = "https://example.com"

    # Main response triggers header and body detection
    httpx_mock.add_response(
        url=url,
        text='<?php echo "PHP Version 5.6.40"; ?>',
        headers={"X-Powered-By": "PHP/5.6.40"},
        status_code=200,
    )

    # phpinfo probes - multiple will succeed and be collected
    httpx_mock.add_response(
        url="https://example.com/phpinfo.php",
        text='<?php phpinfo(); ?> PHP Version 5.6.40',
        status_code=200,
    )
    httpx_mock.add_response(
        url="https://example.com/info.php",
        text="PHP Version 5.6.40 info page",
        status_code=200,
    )
    httpx_mock.add_response(
        url="https://example.com/php.php",
        text="plain php file",
        status_code=200,
    )

    # SQL dump probes - multiple will succeed and be collected
    httpx_mock.add_response(
        url="https://example.com/dump.sql",
        text="CREATE TABLE `users` (id int);\nINSERT INTO `users` VALUES (1);",
        status_code=200,
    )
    httpx_mock.add_response(
        url="https://example.com/backup.sql",
        text="/* mysqldump */\nCREATE TABLE config (setting TEXT);",
        status_code=200,
    )
    httpx_mock.add_response(
        url="https://example.com/db.sql",
        text="no sql here",
        status_code=200,
    )
    httpx_mock.add_response(
        url="https://example.com/database.sql",
        status_code=404,
    )
    httpx_mock.add_response(
        url="https://example.com/schema.sql",
        text="CREATE TABLE logs (id int, entry text);",
        status_code=200,
    )

    # Error page (now always probed)
    httpx_mock.add_response(
        url="https://example.com/nonexistent-404.php",
        text="Fatal error: ... PHP Version 5.6.40",
        status_code=404,
    )

    results: list[ScanResult] = scan_targets([url], config={"max_concurrency": 5, "timeout": 3})
    assert len(results) == 1
    r = results[0]
    assert r.url == url
    assert r.php_version == "5.6.40"
    assert "headers" in r.detected_from
    assert len(r.exposed_files) >= 4
    phpinfos = [f for f in r.exposed_files if f.file_type == "phpinfo"]
    sqldumps = [f for f in r.exposed_files if f.file_type == "sql_dump"]
    assert len(phpinfos) == 2
    assert len(sqldumps) == 3
    assert r.schema is not None
    assert len(r.schema.tables) >= 2
    assert "users" in r.schema.tables
    assert r.errors == []


def test_scan_targets_invalid():
    with pytest.raises(ValueError, match="targets must be a non-empty list"):
        scan_targets([])
    with pytest.raises(ValueError, match="All targets must be valid"):
        scan_targets(["ftp://bad.com"])


def test_scan_targets_with_error(httpx_mock: HTTPXMock):
    httpx_mock.add_response(url="https://bad.example.com", status_code=500)
    results = scan_targets(["https://bad.example.com"])
    assert len(results) == 1
    assert len(results[0].errors) > 0
    assert results[0].php_version is None


def test_schema_in_scan(httpx_mock: HTTPXMock):
    """Ensure schema parsing is invoked when a valid SQL dump is found."""
    url = "https://example.com"
    httpx_mock.add_response(
        url=url,
        text="ok",
        status_code=200,
    )
    httpx_mock.add_response(
        url="https://example.com/schema.sql",
        text="""CREATE TABLE test_table (
    id INT PRIMARY KEY,
    name VARCHAR(100)
);
INSERT INTO test_table VALUES (1, 'test');""",
        status_code=200,
    )
    # Remaining probes return 404 so only schema.sql is collected
    for p in [
        "/phpinfo.php",
        "/info.php",
        "/php.php",
        "/dump.sql",
        "/backup.sql",
        "/db.sql",
        "/database.sql",
        "/nonexistent-404.php",
    ]:
        httpx_mock.add_response(url=f"https://example.com{p}", status_code=404)

    results = scan_targets([url], config={"max_concurrency": 5, "timeout": 3})
    r = results[0]
    assert r.schema is not None
    assert "test_table" in r.schema.tables
    assert "id" in r.schema.columns.get("test_table", [])
    assert r.schema.row_counts.get("test_table", 0) > 0
