"""Tests for passive discovery with Shodan and Censys."""

from unittest.mock import MagicMock, patch

from phpfossil import (
    CensysSearcher,
    ShodanSearcher,
    passive_discover,
)


@patch("phpfossil.passive.httpx.get")
def test_shodan_searcher(mock_get: MagicMock) -> None:
    """Test ShodanSearcher parses host results into URLs."""
    mock_get.return_value.json.return_value = {
        "matches": [
            {"ip_str": "192.0.2.1", "port": 80, "http": {"host": "example.com"}}
        ]
    }
    searcher = ShodanSearcher(api_key="fake-key")
    results = searcher.search('php "Version 7.4"', limit=5)
    assert len(results) == 1
    assert "http://example.com" in results[0]


@patch("phpfossil.passive.httpx.get")
def test_censys_searcher(mock_get: MagicMock) -> None:
    """Test CensysSearcher parses results into target URLs."""
    mock_get.return_value.json.return_value = {
        "results": [
            {
                "services": [{"port": 80}],
                "location": {"registered_country": "US"},
                "dns": {"names": ["test.com"]},
            }
        ]
    }
    searcher = CensysSearcher(api_id="fake", api_secret="fake")
    results = searcher.search("php", limit=3)
    assert len(results) >= 1


@patch("phpfossil.passive.ShodanSearcher")
def test_passive_discover(mock_shodan: MagicMock) -> None:
    """Test passive_discover aggregates results from enabled providers."""
    mock_shodan.return_value.search.return_value = [
        "http://legacy.example.com"
    ]
    targets = passive_discover(
        query='php "Version"', shodan_key="fake", limit=10
    )
    assert "http://legacy.example.com" in targets
    mock_shodan.assert_called_once()
