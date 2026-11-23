"""Tests for passive discovery module."""

from unittest.mock import patch

from phpfossil import (
    CensysSearcher,
    PassiveResult,
    ShodanSearcher,
    passive_discover,
    search_censys,
    search_shodan,
)


@patch("phpfossil.passive.requests.get")
def test_search_shodan(mock_get):
    """Test Shodan search returns parsed URLs."""
    mock_get.return_value.json.return_value = {
        "matches": [
            {"ip_str": "192.0.2.1", "port": 80, "ssl": False},
            {"ip_str": "192.0.2.2", "port": 443, "ssl": True},
        ]
    }
    results = search_shodan('php "Version 7.4"', limit=10, api_key="testkey")
    assert len(results) == 2
    assert any("http://" in r for r in results)


@patch("phpfossil.passive.requests.get")
def test_search_censys(mock_get):
    """Test Censys search functionality."""
    mock_get.return_value.json.return_value = {
        "results": [
            {"services": [{"port": 80}], "ip": "192.0.2.3"},
        ]
    }
    results = search_censys('php "Version"', limit=5, api_id="id", api_secret="secret")
    assert len(results) >= 1


def test_passive_discover():
    """Test combined passive discovery."""
    with patch("phpfossil.passive.search_shodan") as mock_shodan, patch(
        "phpfossil.passive.search_censys"
    ) as mock_censys:
        mock_shodan.return_value = ["http://test1.com"]
        mock_censys.return_value = ["https://test2.com"]
        targets = passive_discover(
            query='php "Version 8"',
            shodan_key="key",
            censys_id="id",
            censys_secret="secret",
            limit=20,
        )
        assert len(targets) == 2
        assert "http://test1.com" in targets


def test_shodan_searcher_class():
    """Test the ShodanSearcher class."""
    searcher = ShodanSearcher(api_key="fake")
    assert searcher.api_key == "fake"


def test_censys_searcher_class():
    """Test the CensysSearcher class."""
    searcher = CensysSearcher(api_id="id", api_secret="secret")
    assert searcher.api_id == "id"
    assert searcher.api_secret == "secret"
