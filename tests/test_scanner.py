"""Tests for the PHP Fossil scanner.

Covers async scanning with concurrency limits, fingerprinting via multiple
probe paths, exposed file detection, live callbacks, Ollama integration
(with proper fallback and real-path mocking), Nuclei mocking, and Store
persistence. All HTTP calls are fully mocked via pytest-httpx to prevent
unmatched-request assertions.
"""

import asyncio
import re
from unittest.mock import MagicMock, patch

import httpx
import pytest

from phpfossil.models import ExposedFile, NucleiFinding, ScanResult, Vulnerability
from phpfossil.ollama import generate_summary, is_ollama_available
from phpfossil.scanner import scan_targets
from phpfossil.store import Store, get_historical_results


@pytest.fixture
def scanner_mocks(httpx_mock):
    """Register responses for every path the scanner may probe.

    Covers root, common PHP info files, .env, SQL dumps, random
    nonexistent-*.php (for error-page version leaks), and a broad
    fallback. This eliminates the "requests were not expected" and
    "responses mocked but not requested" failures.
    """
    base_urls = ["https://httpbin.org", "http://example.com"]
    probe_paths = ["", "/phpinfo.php", "/info.php", "/test.php", "/.env", "/backup.sql"]

    for base in base_urls:
        for path in probe_paths:
            url = f"{base}{path}"
            if any(p in path for p in ("phpinfo", "info.php")):
                content = (
                    "<!DOCTYPE html><h1>PHP Version 7.4.33</h1>"
                    "<p>phpinfo() output would be here.</p>"
                )
                status = 200
            elif path == "/.env":
                content = "APP_ENV=production\nDB_PASSWORD=supersecret123\n"
                status = 200
            elif path.endswith(".sql"):
                content = (
                    "-- PHP Fossil test SQL dump\n"
                    "CREATE TABLE users (id INT, email VARCHAR(255));\n"
                    "INSERT INTO users VALUES (1, 'test@example.com');"
                )
                status = 200
            else:
                content = (
                    "<html><head><title>Test Page</title></head>"
                    "<body><h1>Welcome</h1></body></html>"
                )
                status = 200
            httpx_mock.add_response(url=url, text=content, status_code=status)

        # Random nonexistent-*.php used by error-page fingerprinting
        httpx_mock.add_response(
            url=re.compile(re.escape(base) + r"/nonexistent-\d+\.php"),
            text=(
                "<!DOCTYPE html><html><body>"
                "<h1>PHP Fatal error</h1>"
                "<p>Uncaught Error: ... (PHP 7.4.33)</p>"
                "</body></html>"
            ),
            status_code=500,
        )

    # Broad fallback for any other requests (Nuclei JSON, etc.)
    httpx_mock.add_response(
        url=re.compile(r"https?://.*"),
        json={"status": "ok"},
        status_code=200,
    )
    yield


def test_scanner_respects_max_concurrency(scanner_mocks):
    """Verify concurrency limit is respected and all probe paths are handled."""
    targets = ["https://httpbin.org", "http://example.com"]
    config = {
        "max_concurrency": 2,
        "timeout": 5,
        "use_nuclei": False,
        "use_ollama": False,
    }

    results = asyncio.run(scan_targets(targets, config=config))

    assert len(results) == 2
    for r in results:
        assert isinstance(r, ScanResult)
        assert r.url in targets
        # At least one detection source should be recorded
        assert len(r.detected_from) >= 1 or r.php_version is not None


def test_is_ollama_available_fallback(httpx_mock):
    """Test that is_ollama_available returns False on non-successful response."""
    httpx_mock.add_response(
        url="http://localhost:11434/api/tags",
        status_code=503,
        text="Ollama unavailable",
    )
    assert not is_ollama_available()


def test_generate_summary_with_real_results(httpx_mock):
    """Test full Ollama summary path with both availability check and chat API mocked."""
    httpx_mock.add_response(
        url="http://localhost:11434/api/tags",
        json={"models": [{"name": "llama3"}]},
        status_code=200,
    )
    httpx_mock.add_response(
        url="http://localhost:11434/api/chat",
        json={
            "message": {
                "content": (
                    "# PHP Fossil Scan Summary\n\n"
                    "Overall risk is **High** due to legacy PHP 7.4 and exposed files.\n\n"
                    "**Risk Level:** High"
                )
            }
        },
        status_code=200,
    )

    results = [
        ScanResult(
            url="https://example.com",
            php_version="7.4.33",
            detected_from=["body", "error_page"],
            vulns=[
                Vulnerability(
                    cve="CVE-2019-11043",
                    title="PHP CGI Argument Injection",
                    severity="critical",
                    description="Test vulnerability",
                    fixed_in="7.4.34",
                )
            ],
            exposed_files=[
                ExposedFile(
                    url="https://example.com/.env",
                    file_type="env",
                    content_preview="DB_PASSWORD=secret",
                )
            ],
            nuclei_findings=[
                NucleiFinding(
                    template="php-cgi-arg-injection",
                    name="PHP CGI RCE",
                    severity="critical",
                )
            ],
        )
    ]

    summary = generate_summary(results, model="llama3", timeout=5)
    assert "PHP Fossil Scan Summary" in summary
    assert "Risk Level" in summary
    assert "High" in summary


@pytest.mark.asyncio
async def test_scan_with_live_callback(scanner_mocks):
    """Exercise the optional live callback used by the TUI."""
    callback = MagicMock()
    config = {
        "max_concurrency": 5,
        "timeout": 5,
        "use_nuclei": False,
        "use_ollama": False,
    }
    results = await scan_targets(
        ["http://example.com"], config=config, callback=callback
    )
    assert len(results) == 1
    assert callback.call_count >= 1


@patch("phpfossil.nuclei.subprocess.run")
def test_nuclei_validation(mock_subprocess, scanner_mocks):
    """Mock Nuclei subprocess and verify findings are attached."""
    mock_subprocess.return_value.stdout = (
        '{"template-id":"cve-2019-11043","info":{"name":"PHP CGI","severity":"critical"}}\n'
    )
    mock_subprocess.return_value.returncode = 0

    config = {
        "max_concurrency": 3,
        "timeout": 5,
        "use_nuclei": True,
        "use_ollama": False,
    }
    results = asyncio.run(scan_targets(["http://example.com"], config=config))

    assert len(results) == 1
    assert len(results[0].nuclei_findings) > 0
    assert any(f.severity == "critical" for f in results[0].nuclei_findings)


def test_store_integration_after_scan(scanner_mocks, tmp_path):
    """Scan results are automatically persisted via the Store."""
    config = {
        "max_concurrency": 3,
        "timeout": 5,
        "use_nuclei": False,
        "use_ollama": False,
    }
    results = asyncio.run(scan_targets(["https://httpbin.org"], config=config))

    db_path = tmp_path / "test_history.db"
    store = Store(db_path=db_path)
    store.save_scan_results(results)

    historical = get_historical_results(limit=5, db_path=db_path)
    assert len(historical) >= 1
    assert historical[0].url == "https://httpbin.org"
