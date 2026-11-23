"""Tests for CMS-specific version fingerprinting."""

from phpfossil.fingerprinter import (
    detect_drupal_version,
    detect_magento_version,
    detect_prestashop_version,
    detect_symfony_version,
    detect_codeigniter_version,
    detect_cms_version,
)


def test_detect_prestashop_version():
    body = '<meta name="generator" content="PrestaShop 1.7.8.0">'
    assert detect_prestashop_version(body) == "1.7.8.0"


def test_detect_magento_version():
    body = "Magento 2.4.6"
    assert detect_magento_version(body) == "2.4.6"


def test_detect_drupal_version():
    body = '<meta name="generator" content="Drupal 10.2.3">'
    assert detect_drupal_version(body) == "10.2.3"


def test_detect_symfony_version():
    body = '<meta name="generator" content="Symfony 6.4.3">'
    assert detect_symfony_version(body) == "6.4.3"


def test_detect_codeigniter_version():
    body = "CodeIgniter 4.5.2"
    assert detect_codeigniter_version(body) == "4.5.2"


def test_detect_cms_version():
    body = '<meta name="generator" content="Drupal 10.2.3">'
    cms, version = detect_cms_version(body)
    assert cms == "drupal"
    assert version == "10.2.3"

    body2 = "Magento 2.4.6"
    cms, version = detect_cms_version(body2)
    assert cms == "magento"
    assert version == "2.4.6"
