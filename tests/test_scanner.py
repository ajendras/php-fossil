"""Tests for the scanner module including async scanning, mocks, live callbacks and integration with other components."""

import asyncio
import httpx
import pytest
from unittest.mock import MagicMock

from phpfossil.models import ScanResult
from phpfossil.scanner import scan_targets


@pytest.mark.asyncio
async def test_scan_targets_basic():
    """Test that scan_targets returns list of ScanResult objects."""
    config = {
        "max_concurrency": 3,
        "timeout": 10,
        "use_nuclei": False,
        "use_ollama": False,
        "use_community_fingerprints": False,
        "verbose": 0,
    }
    results = await scan_targets(
        ["https://httpbin.org", "http://example.com"], config=config
    )
    assert isinstance(results, list)
    assert len(results) >= 1
    for r in results:
        assert isinstance(r, ScanResult)
        assert r.url in ["https://httpbin.org", "http://example.com"]


@pytest.mark.asyncio
async def test_scan_targets_with_callback():
    """Test live callback functionality during scanning."""
    callback = MagicMock()
    config = {
        "max_concurrency": 2,
        "timeout": 5,
        "use_nuclei": False,
        "use_ollama": False,
        "verbose": 0,
    }
    results = await scan_targets(
        ["https://httpbin.org"], config=config, callback=callback
    )
    assert len(results) > 0
    assert callback.called
