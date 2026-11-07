"""Tests for the PHP Fossil scanner.

Covers input validation, mock-based HTTP probing of version detection,
exposed files, schema extraction and the persistent Store. Uses
pytest-httpx to simulate responses without real network calls.
"""

import json
from pathlib import Path
from typing import Any

import pytest
from pytest_httpx import HTTPXMock

from phpfossil.models import ExposedFile, ScanResult, SchemaResult
from phpfossil.scanner import scan_targets
from phpfossil.store import Store


def test_scan_targets_invalid_input() -> None:
    """Validate that scan_targets rejects bad inputs."""
    with pytest.raises(ValueError, match="non-empty list"):
        scan_targets([])

    with pytest.raises(ValueError, match="valid http/https URLs"):
        scan_targets(["ftp://bad.example.com"])


@pytest.mark.httpx_mock(assert_all_responses_were_requested=False)
def test_scan_targets_with_mock(httpx_mock: HTTPXMock) -> None:
    """Test full scan flow with mocked responses for all probe paths.

    Some mocks (php.php, error page, later SQL files) are intentionally
    not hit because of early break/return when a valid response is found.
    The marker above disables the strict "all registered responses must
    be requested" check from pytest-httpx.
    """
    # Main target - provides version via header + body
    httpx_mock.add_response(
        url="https://example.com",
        text="<html><body>PHP powered site</body></html>",
        headers={"X-Powered-By": "PHP/7.4.33"},
        status_code=200,
    )

    # First phpinfo probe succeeds -> later php.php mock is not requested
    httpx_mock.add_response(
        url="https://example.com/phpinfo.php",
        text="<h1>PHP Version 7.4.33</h1>",
        status_code=200,
    )
    httpx_mock.add_response(url="https://example.com/info.php", status_code=404)
    httpx_mock.add_response(url="https://example.com/php.php", status_code=404)

    # First SQL dump succeeds -> later SQL mocks are not requested
    httpx_mock.add_response(
        url="https://example.com/dump.sql",
        text=(
            "CREATE TABLE users (id INT, name VARCHAR(50));\n"
            "INSERT INTO users VALUES (1, 'test');"
        ),
        status_code=200,
    )
    for extra_sql in (
        "https://example.com/backup.sql",
        "https://example.com/db.sql",
        "https://example.com/database.sql",
        "https://example.com/schema.sql",
    ):
        httpx_mock.add_response(url=extra_sql, status_code=404)

    # Error-page fallback is skipped because version was already detected
    httpx_mock.add_response(
        url="https://example.com/nonexistent-404.php",
        text="PHP Parse error: ... (PHP 7.4.33)",
        status_code=404,
    )

    results = scan_targets(
        ["https://example.com"], config={"max_concurrency": 5, "timeout": 5}
    )

    assert len(results) == 1
    r: ScanResult = results[0]

    assert r.url == "https://example.com"
    assert r.php_version == "7.4.33"
    assert "headers" in r.detected_from
    assert "phpinfo" in r.detected_from
    assert len(r.vulns) > 0
    assert any(e.file_type == "phpinfo" for e in r.exposed_files)
    assert any(e.file_type == "sql_dump" for e in r.exposed_files)

    # schema field works via alias + property
    assert r.schema_result is not None
    assert r.schema is not None  # property
    assert "users" in r.schema.tables
    assert r.schema.columns.get("users") == ["id", "name"]
    assert r.schema.row_counts.get("users") == 1

    assert len(r.errors) == 0


def test_scan_targets_error_handling(httpx_mock: HTTPXMock) -> None:
    """Ensure errors are captured when all requests fail."""
    httpx_mock.add_exception(Exception("Connection refused"), url="https://bad.example.com")

    results = scan_targets(["https://bad.example.com"], config={"timeout": 2})
    assert len(results) == 1
    assert len(results[0].errors) == 1
    assert "Connection refused" in results[0].errors[0]


def test_store_integration(tmp_path: Path) -> None:
    """Verify ScanResult objects with schema can be persisted and retrieved."""
    db_path = tmp_path / "test.db"
    store = Store(db_path)

    schema = SchemaResult(
        tables=["users", "posts"],
        columns={"users": ["id", "email"]},
        row_counts={"users": 42},
    )
    result = ScanResult(
        url="https://legacy.example.com",
        php_version="7.4.33",
        schema=schema,  # uses alias
        exposed_files=[
            ExposedFile(
                url="https://legacy.example.com/phpinfo.php",
                file_type="phpinfo",
                content_preview="PHP Version 7.4.33",
            )
        ],
    )

    store.store(result)
    assert store.count() == 1

    history = store.get_history(limit=5)
    assert len(history) == 1
    reloaded = history[0]
    assert reloaded.url == result.url
    assert reloaded.php_version == result.php_version
    assert reloaded.schema is not None
    assert reloaded.schema.tables == ["users", "posts"]


def test_scan_result_serialization() -> None:
    """Ensure JSON round-tripping preserves schema under the 'schema' key."""
    schema = SchemaResult(tables=["orders"])
    result = ScanResult(
        url="https://example.com",
        php_version="5.6.40",
        schema=schema,
        vulns=[],
    )

    data = json.loads(result.model_dump_json())
    assert data["schema"]["tables"] == ["orders"]
    assert "schema_result" not in data

    restored = ScanResult.model_validate(data)
    assert restored.schema.tables == ["orders"]
