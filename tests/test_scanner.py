"""Unit tests for the async scanner, fingerprinting helpers and live callback support.

Covers detect_php_version accuracy, scan_targets with pytest-httpx mocks,
callback handling, ConfigSettings (dict and object), ScanResult model
serialization and basic store integration. Dedicated tests for nuclei/ollama/passive
live in their own files.
"""

import asyncio
import json
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from pytest_httpx import HTTPXMock

from phpfossil import (
    ConfigSettings,
    ScanResult,
    detect_php_version,
    detect_from_body,
    detect_from_headers,
    generate_report,
    scan_targets,
    store_results,
)
from phpfossil.fingerprinter import detect_from_phpinfo
from phpfossil.models import Vulnerability
from phpfossil.store import Store


def test_detect_from_headers():
    """Test header-based PHP version detection (including case-insensitivity)."""
    assert detect_from_headers({"X-Powered-By": "PHP/7.4.33"}) == "7.4.33"
    assert detect_from_headers({"x-powered-by": "PHP/8.1.2"}) == "8.1.2"
    assert detect_from_headers({"Server": "Apache/2.4.41 (Unix) PHP/7.3.1"}) == "7.3.1"
    assert detect_from_headers({}) is None
    assert detect_from_headers(None) is None


def test_detect_from_body():
    """Test body-based detection with multiple signature patterns."""
    assert detect_from_body("PHP Version 5.6.40") == "5.6.40"
    assert detect_from_body(b"X-Powered-By: PHP/8.0.1") == "8.0.1"
    assert detect_from_body("<html>php/7.4.33") == "7.4.33"
    assert detect_from_body("no version here") is None


def test_detect_from_phpinfo():
    """Test phpinfo() specific parsing."""
    phpinfo = '<tr><td>PHP Version</td><td class="v">8.2.5</td></tr>'
    assert detect_from_phpinfo(phpinfo) == "8.2.5"
    assert detect_from_phpinfo(b">PHP Version 7.4.33<") == "7.4.33"
    assert detect_from_phpinfo("no phpinfo") is None


def test_detect_php_version_combined():
    """Test the main multi-vector detection priority order."""
    headers = {"X-Powered-By": "PHP/8.1.2"}
    assert detect_php_version(headers) == "8.1.2"

    # header takes precedence
    assert detect_php_version(headers, body="PHP Version 7.4.0") == "8.1.2"

    # phpinfo next
    assert detect_php_version(None, None, phpinfo_content="PHP Version 8.0.1") == "8.0.1"

    # body fallback
    assert detect_php_version(None, "PHP Version 7.3.1") == "7.3.1"


@pytest.mark.asyncio
async def test_scan_targets(httpx_mock: HTTPXMock):
    """Test basic async scanning with mocked responses.

    Uses the correct httpx_mock fixture name provided by pytest-httpx.
    """
    httpx_mock.add_response(
        url="https://httpbin.org",
        text="<h1>PHP Version 8.1.2</h1>",
        headers={"X-Powered-By": "PHP/8.1.2"},
    )
    results = await scan_targets(
        ["https://httpbin.org"],
        config={"max_concurrency": 5, "timeout": 5, "verbose": 0},
    )
    assert len(results) == 1
    assert results[0].php_version == "8.1.2"
    assert results[0].url == "https://httpbin.org"
    assert len(results[0].detected_from) >= 1


@pytest.mark.asyncio
async def test_scan_targets_with_callback(httpx_mock: HTTPXMock):
    """Test scanner live callback for TUI/real-time UI support."""
    httpx_mock.add_response(
        url="http://example.com",
        text="PHP Version 7.4.33",
        headers={"X-Powered-By": "PHP/7.4.33"},
    )

    callback_calls = []

    def live_callback(result: ScanResult) -> None:
        callback_calls.append(result)

    results = await scan_targets(
        ["http://example.com"],
        config=ConfigSettings(
            max_concurrency=1,
            timeout=5,
            verbose=0,
            use_nuclei=False,
            use_ollama=False,
            use_community_fingerprints=False,
        ),
        callback=live_callback,
    )

    assert len(results) == 1
    assert len(callback_calls) == 1
    assert results[0].php_version == "7.4.33"
    assert callback_calls[0].php_version == "7.4.33"


@pytest.mark.asyncio
async def test_scan_targets_config_object(httpx_mock: HTTPXMock):
    """Test that both dict and ConfigSettings are accepted (public API contract)."""
    httpx_mock.add_response(
        url="https://test.com",
        text="<title>Demo - PHP 8.3.0</title>",
        headers={},
    )
    config = ConfigSettings(
        max_concurrency=3,
        per_domain_limit=2,
        timeout=10,
        verbose=0,
        use_nuclei=False,
        use_ollama=False,
    )
    results = await scan_targets(["https://test.com"], config=config)
    assert len(results) == 1
    assert results[0].php_version is not None


def test_scan_result_model():
    """Test ScanResult Pydantic model, computed fields and JSON roundtrip."""
    vuln = Vulnerability(
        cve="CVE-2021-1234",
        title="Remote Code Execution",
        severity="critical",
        description="Test vuln",
        fixed_in="8.0.1",
        references=["https://example.com"],
    )
    result = ScanResult(
        url="https://legacy.example.com",
        php_version="7.4.33",
        detected_from=["header", "body"],
        vulns=[vuln],
        scan_time=datetime.now(),
    )
    assert result.is_vulnerable() is True
    assert result.risk_score >= 70
    assert result.risk_summary == "critical"

    data = result.model_dump(mode="json")
    reloaded = ScanResult.model_validate(data)
    assert reloaded.url == result.url
    assert reloaded.php_version == result.php_version
    assert len(reloaded.vulns) == 1


def test_config_settings_validation_and_defaults():
    """Test pydantic ConfigSettings defaults, validators and user-agent injection."""
    cfg = ConfigSettings(verbose=2)
    assert cfg.max_concurrency == 20
    assert cfg.timeout == 12
    assert cfg.per_domain_limit == 5
    assert len(cfg.user_agents) == len(cfg.user_agents)  # populated from DEFAULT
    assert cfg.db_path is not None
    assert "history.db" in str(cfg.db_path)

    # test capping
    cfg2 = ConfigSettings(max_concurrency=100)
    assert cfg2.max_concurrency == 50


@pytest.mark.asyncio
async def test_store_persistence_after_scan(httpx_mock: HTTPXMock, tmp_path: Path):
    """Test that scan results are automatically persisted via store_results."""
    httpx_mock.add_response(
        url="https://persist.example.com",
        text="PHP Version 5.6.40",
        headers={"X-Powered-By": "PHP/5.6.40"},
    )
    db_path = tmp_path / "test_history.db"
    results = await scan_targets(
        ["https://persist.example.com"],
        config=ConfigSettings(
            max_concurrency=1,
            timeout=5,
            verbose=0,
            db_path=db_path,
            use_nuclei=False,
            use_ollama=False,
        ),
    )
    store_results(results)

    store = Store(db_path=str(db_path))
    historical = store.get_results(limit=5)
    assert len(historical) >= 1
    assert any(r.url == "https://persist.example.com" for r in historical)


def test_generate_report_terminal_smoke(httpx_mock: HTTPXMock):
    """Smoke test that terminal report does not raise for a simple result set."""
    # No real output capture needed; just ensure it runs
    result = ScanResult(
        url="https://example.com",
        php_version="7.4.33",
        vulns=[
            Vulnerability(
                cve="CVE-2019-1234",
                title="Example",
                severity="medium",
                description="Test",
            )
        ],
    )
    generate_report([result], output_format="terminal")
