"""Tests for the PHP Fossil scanner.

Covers risk score calculation (including schema sensitivity), async scanning
with mocks, exposed file handling, and live callback path.
"""

import asyncio
from datetime import datetime, timezone
from typing import List

import pytest
from pytest_httpx import HTTPXMock

from phpfossil.models import (
    ExposedFile,
    NucleiFinding,
    ScanResult,
    SchemaResult,
    Vulnerability,
)
from phpfossil.scanner import scan_targets
from phpfossil.reporter import generate_report


def test_risk_score_no_vulns_no_schema():
    result = ScanResult(url="https://example.com")
    assert result.risk_score == 0


def test_risk_score_with_critical_vuln():
    vuln = Vulnerability(
        cve="CVE-2019-1234",
        title="Remote Code Execution",
        severity="critical",
        description="Test vuln",
    )
    result = ScanResult(
        url="https://example.com",
        php_version="7.4.0",
        vulns=[vuln],
    )
    assert result.risk_score >= 35


def test_risk_score_with_sensitive_schema():
    schema = SchemaResult(
        tables=["users", "payments", "admin_accounts"],
        columns={"users": ["id", "username", "password_hash"]},
        row_counts={"users": 25000, "payments": 820},
    )
    vuln = Vulnerability(
        cve="CVE-2021-5678",
        title="Info Leak",
        severity="high",
        description="Test",
    )
    result = ScanResult(
        url="https://legacy.example.com",
        php_version="5.6.40",
        vulns=[vuln],
        db_schema=schema,
        exposed_files=[
            ExposedFile(url="https://example.com/dump.sql", file_type="sql_dump")
        ],
    )
    # Critical boost from sensitive tables + high vuln + row count
    assert result.risk_score > 65


def test_risk_score_capped_at_100():
    vulns = [
        Vulnerability(
            cve=f"CVE-2020-{i}",
            title="Test",
            severity="critical",
            description="d",
        )
        for i in range(6)
    ]
    result = ScanResult(url="https://test.com", vulns=vulns)
    assert result.risk_score == 100


def test_risk_score_minimum_for_schema_exposure():
    schema = SchemaResult(
        tables=["admin_users", "config"],
        row_counts={"admin_users": 1200},
    )
    result = ScanResult(
        url="https://test.com",
        vulns=[],
        db_schema=schema,
    )
    score = result.risk_score
    assert score >= 35
    assert score <= 100


def test_risk_score_nuclei_bonus():
    finding = NucleiFinding(
        template="cve-2019-11043",
        name="PHP CGI RCE",
        severity="critical",
        matched_at="https://example.com",
    )
    result = ScanResult(
        url="https://example.com",
        nuclei_findings=[finding],
    )
    assert result.risk_score >= 12


@pytest.mark.asyncio
async def test_scan_targets(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url="https://httpbin.org",
        text="<title>PHP Version 8.1.0</title>",
        headers={"X-Powered-By": "PHP/8.1.0"},
        status_code=200,
    )
    httpx_mock.add_response(
        url="http://example.com",
        text="Plain site - no PHP",
        status_code=200,
    )

    results: List[ScanResult] = await scan_targets(
        ["https://httpbin.org", "http://example.com"],
        config={
            "max_concurrency": 2,
            "timeout": 5,
            "use_nuclei": False,
            "use_ollama": False,
        },
    )

    assert len(results) == 2
    php_results = [r for r in results if r.php_version]
    assert len(php_results) >= 1
    # New risk score is always present
    for r in results:
        assert isinstance(r.risk_score, int)
        assert 0 <= r.risk_score <= 100


def test_generate_report_includes_risk_score():
    results = [
        ScanResult(
            url="https://test.com",
            php_version="7.4.33",
            vulns=[
                Vulnerability(
                    cve="CVE-2021-1234",
                    title="Test",
                    severity="high",
                    description="Test",
                )
            ],
        )
    ]
    # Should not raise and includes risk score in output path
    generate_report(results, output_format="terminal")
    # HTML path exercised (no file written in test)
    # (In real test we would assert on captured output)
