"""Tests for passive discovery module."""

import re
from unittest.mock import patch

import pytest

from phpfossil.passive import (
    search_shodan,
    search_censys,
    passive_discover,
    ShodanSearcher,
    CensysSearcher,
)


def test_shodan_searcher(httpx_mock):
    httpx_mock.add_response(
        url=re.compile(r"https://api\.shodan\.io.*"),
        json={"matches": [{"hostnames": ["example.com"]}]},
        status_code=200,
    )
    results = search_shodan('php "7.4"', "test-key")
    assert len(results) == 1


def test_censys_searcher(httpx_mock):
    httpx_mock.add_response(
        url=re.compile(r"https://search\.censys\.io.*"),
        json={"result": {"hits": [{"ip": "1.2.3.4"}]}},
        status_code=200,
    )
    results = search_censys('php "7.4"', "test-id", "test-secret")
    assert len(results) >= 1


def test_passive_discover(httpx_mock):
    httpx_mock.add_response(
        url=re.compile(r"https://api\.shodan\.io.*"),
        json={"matches": [{"hostnames": ["example.com"]}]},
    )
    results = passive_discover(
        query='php "Version"',
        shodan_key="fake-key",
        limit=5,
    )
    assert len(results) >= 1


def test_searcher_classes():
    with patch("phpfossil.passive.search_shodan", return_value=["https://example.com"]):
        searcher = ShodanSearcher()
        results = searcher.search("test query", "fake-key")
        assert len(results) == 1
    with patch("phpfossil.passive.search_censys", return_value=["https://example.com"]):
        searcher = CensysSearcher()
        results = searcher.search("test query", "id", "secret")
        assert len(results) == 1
