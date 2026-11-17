"""Tests for CMS version fingerprinting in fingerprinter.py."""

import pytest

from phpfossil.fingerprinter import (
    detect_wordpress_version,
    detect_joomla_version,
    detect_laravel_version,
    detect_drupal_version,
    detect_magento_version,
    detect_prestashop_version,
    detect_cms_version,
)


@pytest.mark.parametrize(
    "body,expected",
    [
        ('<meta name="generator" content="WordPress 6.4.2">', "6.4.2"),
        ("<!-- Powered by WordPress 6.3.1 -->", "6.3.1"),
        ("WordPress 5.8", "5.8"),
        ("", None),
        ("no cms here", None),
        ("<meta name=\"generator\" content=\"SomethingElse 1.2.3\">", None),
    ],
)
def test_detect_wordpress_version(body: str, expected: str | None) -> None:
    assert detect_wordpress_version(body) == expected


@pytest.mark.parametrize(
    "body,expected",
    [
        ('<meta name="generator" content="Joomla! - Open Source Content Management - Version 4.4.0">', "4.4.0"),
        ("Joomla! 3.9.24", "3.9.24"),
        ("", None),
        ("random html without version", None),
    ],
)
def test_detect_joomla_version(body: str, expected: str | None) -> None:
    assert detect_joomla_version(body) == expected


@pytest.mark.parametrize(
    "body,expected",
    [
        ('<meta name="generator" content="Drupal 10.2.3">', "10.2.3"),
        ("Drupal 9.5.11", "9.5.11"),
        ('<meta name="Generator" content="Drupal 11.0.1">', "11.0.1"),
        ("", None),
        ("no drupal mention", None),
    ],
)
def test_detect_drupal_version(body: str, expected: str | None) -> None:
    assert detect_drupal_version(body) == expected


@pytest.mark.parametrize(
    "body,expected",
    [
        ('<meta name="generator" content="Magento 2.4.6">', "2.4.6"),
        ("Magento 2.3.7-p1", "2.3.7"),
        ("<!-- Magento Framework 2.4.5 -->", "2.4.5"),
        ("Magento/2.4.6", "2.4.6"),
        ("", None),
        ("plain page", None),
    ],
)
def test_detect_magento_version(body: str, expected: str | None) -> None:
    assert detect_magento_version(body) == expected


@pytest.mark.parametrize(
    "body,expected",
    [
        ('Powered by PrestaShop 8.1.0', "8.1.0"),
        ('<meta name="generator" content="PrestaShop 1.7.8.11">', "1.7.8"),
        ("PrestaShop™ 1.7.7.2", "1.7.7"),
        ('prestashop.version = "8.0.4"', "8.0.4"),
        ("", None),
        ("no shop version", None),
    ],
)
def test_detect_prestashop_version(body: str, expected: str | None) -> None:
    assert detect_prestashop_version(body) == expected


@pytest.mark.parametrize(
    "body,expected",
    [
        ('<meta name="generator" content="WordPress 6.4.2">', ("wordpress", "6.4.2")),
        ('<meta name="generator" content="Joomla! - Open Source Content Management - Version 4.4.0">', ("joomla", "4.4.0")),
        ('<meta name="generator" content="Drupal 10.2.3">', ("drupal", "10.2.3")),
        ('<meta name="generator" content="Magento 2.4.6">', ("magento", "2.4.6")),
        ('Powered by PrestaShop 8.1.0', ("prestashop", "8.1.0")),
        ("<!-- Laravel Framework 10.0.1 -->", ("laravel", "10.0.1")),
        ("plain html with no cms", None),
        ("", None),
    ],
)
def test_detect_cms_version(body: str, expected: tuple[str, str] | None) -> None:
    assert detect_cms_version(body) == expected


def test_cms_version_priority() -> None:
    # Body that could theoretically match multiple - should return first match (WordPress)
    body = '<meta name="generator" content="WordPress 6.4.2"><meta name="generator" content="Drupal 10.0">'
    assert detect_cms_version(body) == ("wordpress", "6.4.2")
