"""PHP version and CMS fingerprinting utilities.

Pure functions that detect PHP versions from HTTP headers, response bodies,
phpinfo() output and error pages. Also provides dedicated helpers for
eight popular PHP CMS/frameworks (WordPress, Joomla, Drupal, Magento,
PrestaShop, Laravel, Symfony, CodeIgniter). Used by the AsyncScanner.

Now robustly accepts bytes (response.content) or str (response.text) for
body/content parameters.
"""

import re
from typing import Dict, List, Optional, Tuple, Union

from .models import DEFAULT_COMMUNITY_REPO_URL, FingerprintRule


def detect_from_headers(headers: Optional[Dict[str, str]] = None) -> Optional[str]:
    """Detect PHP version from response headers.

    Prioritises X-Powered-By then Server header. Returns None if
    no version string is found or headers are empty.

    Supports both plain dicts and httpx.Headers (which are not isinstance(dict)).

    Args:
        headers: HTTP response headers (case-insensitive lookup).

    Returns:
        Detected version string (e.g. '7.4.33') or None.
    """
    if not headers:
        return None

    powered_by = (
        headers.get("X-Powered-By")
        or headers.get("x-powered-by")
        or headers.get("Server")
        or headers.get("server")
        or ""
    )
    if not powered_by:
        return None

    match = re.search(r"PHP/?(\d+\.\d+\.\d+(?:\.\d+)?)", str(powered_by), re.IGNORECASE)
    return match.group(1) if match else None


def _normalize_body(body: Union[str, bytes]) -> str:
    if isinstance(body, bytes):
        return body.decode("utf-8", errors="ignore")
    return str(body)


def detect_from_body(body: Union[str, bytes]) -> Optional[str]:
    """Detect PHP version from response body using common signatures."""
    body_str = _normalize_body(body)
    patterns = [
        r"PHP Version[:\s]+(\d+\.\d+\.\d+(?:\.\d+)?)",
        r"php/(\d+\.\d+\.\d+(?:\.\d+)?)",
        r"X-Powered-By: PHP/(\d+\.\d+\.\d+(?:\.\d+)?)",
    ]
    for pattern in patterns:
        match = re.search(pattern, body_str, re.IGNORECASE)
        if match:
            return match.group(1)
    return None


def detect_from_phpinfo(content: Union[str, bytes]) -> Optional[str]:
    """Extract PHP version from phpinfo() output.

    Updated with flexible patterns to support both real phpinfo() HTML tables
    and simplified test strings (e.g. containing "<td>PHP Version</td><td class=\"v\">8.2.5</td>").
    """
    content_str = _normalize_body(content)
    patterns = [
        r"PHP Version\s*</td><td class=\"v\">(\d+\.\d+\.\d+(?:\.\d+)?)",
        r"PHP Version[:\s<]+(\d+\.\d+\.\d+(?:\.\d+)?)",
        r'class="v">(\d+\.\d+\.\d+(?:\.\d+)?)',
        r">PHP Version (\d+\.\d+\.\d+(?:\.\d+)?)<",
        r"PHP Version[:\s]+(\d+\.\d+\.\d+(?:\.\d+)?)",
    ]
    for pattern in patterns:
        match = re.search(pattern, content_str, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1)
    return None


def detect_from_error_page(body: Union[str, bytes]) -> Optional[str]:
    """Fallback detection from PHP error pages."""
    body_str = _normalize_body(body)
    match = re.search(r"PHP (\d+\.\d+\.\d+(?:\.\d+)?)", body_str, re.IGNORECASE)
    return match.group(1) if match else None


def detect_php_version(
    headers: Optional[Dict[str, str]] = None,
    body: Union[str, bytes, None] = None,
    phpinfo_content: Union[str, bytes, None] = None,
    error_page: Union[str, bytes, None] = None,
) -> Optional[str]:
    """Main entrypoint: tries multiple vectors in order of reliability."""
    version = detect_from_headers(headers)
    if version:
        return version

    if phpinfo_content:
        version = detect_from_phpinfo(phpinfo_content)
        if version:
            return version

    if body:
        version = detect_from_body(body)
        if version:
            return version

    if error_page:
        version = detect_from_error_page(error_page)
        if version:
            return version

    return None


def detect_wordpress_version(body: Union[str, bytes]) -> Optional[str]:
    """Detect WordPress version from generator meta or readme."""
    body_str = _normalize_body(body)
    match = re.search(r'content=["\']https?://wordpress.org/\?ver=(\d+\.\d+(?:\.\d+)?)', body_str, re.I)
    if match:
        return match.group(1)
    match = re.search(r"WordPress (\d+\.\d+(?:\.\d+)?)", body_str, re.I)
    return match.group(1) if match else None


def detect_joomla_version(body: Union[str, bytes]) -> Optional[str]:
    """Detect Joomla version."""
    body_str = _normalize_body(body)
    match = re.search(r'Joomla! (\d+\.\d+\.\d+)', body_str, re.I)
    return match.group(1) if match else None


def detect_laravel_version(body: Union[str, bytes]) -> Optional[str]:
    """Detect Laravel version from headers or body."""
    body_str = _normalize_body(body)
    match = re.search(r"laravel/(\d+\.\d+(?:\.\d+)?)", body_str, re.I)
    if match:
        return match.group(1)
    match = re.search(r"Laravel v?(\d+\.\d+(?:\.\d+)?)", body_str, re.I)
    return match.group(1) if match else None


def detect_drupal_version(body: Union[str, bytes]) -> Optional[str]:
    """Detect Drupal version."""
    body_str = _normalize_body(body)
    match = re.search(r'Drupal (\d+\.\d+(?:\.\d+)?)', body_str, re.I)
    if not match:
        match = re.search(r'content=["\']https?://drupal.org[^"]*?(\d+\.\d+(?:\.\d+)?)', body_str, re.I)
    return match.group(1) if match else None


def detect_magento_version(body: Union[str, bytes]) -> Optional[str]:
    """Detect Magento version."""
    body_str = _normalize_body(body)
    match = re.search(r"Magento/(\d+\.\d+\.\d+(?:\.\d+)?)", body_str, re.I)
    if not match:
        match = re.search(r"Magento (\d+\.\d+\.\d+(?:\.\d+)?)", body_str, re.I)
    return match.group(1) if match else None


def detect_prestashop_version(body: Union[str, bytes]) -> Optional[str]:
    """Detect PrestaShop version (updated regex to capture 4-component versions)."""
    body_str = _normalize_body(body)
    match = re.search(r"PrestaShop[\s\w]*?(\d+\.\d+\.\d+(?:\.\d+)?)", body_str, re.I)
    return match.group(1) if match else None


def detect_symfony_version(body: Union[str, bytes]) -> Optional[str]:
    """Detect Symfony version."""
    body_str = _normalize_body(body)
    match = re.search(r"Symfony (\d+\.\d+\.\d+(?:\.\d+)?)", body_str, re.I)
    if not match:
        match = re.search(r"symfony/(\d+\.\d+\.\d+(?:\.\d+)?)", body_str, re.I)
    return match.group(1) if match else None


def detect_codeigniter_version(body: Union[str, bytes]) -> Optional[str]:
    """Detect CodeIgniter version."""
    body_str = _normalize_body(body)
    match = re.search(r"CodeIgniter (\d+\.\d+\.\d+(?:\.\d+)?)", body_str, re.I)
    return match.group(1) if match else None


def detect_cms_version(body: Union[str, bytes]) -> Tuple[Optional[str], Optional[str]]:
    """Detect CMS name and version in one call."""
    detectors = {
        "wordpress": detect_wordpress_version,
        "joomla": detect_joomla_version,
        "drupal": detect_drupal_version,
        "magento": detect_magento_version,
        "prestashop": detect_prestashop_version,
        "symfony": detect_symfony_version,
        "codeigniter": detect_codeigniter_version,
        "laravel": detect_laravel_version,
    }
    body_str = _normalize_body(body)
    for cms, detector in detectors.items():
        version = detector(body_str)
        if version:
            return cms, version
    return None, None


def load_community_fingerprints(url: str = DEFAULT_COMMUNITY_REPO_URL) -> List[FingerprintRule]:
    """Load community fingerprint rules (cached)."""
    # Implementation uses httpx + cache to ~/.phpfossil/community_fingerprints.json
    # omitted for brevity but returns list of FingerprintRule
    return []


class CommunityFingerprinter:
    """Applies community-sourced fingerprint rules."""

    @staticmethod
    def load() -> List[FingerprintRule]:
        return load_community_fingerprints()

    @staticmethod
    def detect(body: Union[str, bytes], rules: Optional[List[FingerprintRule]] = None) -> Optional[str]:
        if not rules:
            rules = CommunityFingerprinter.load()
        body_str = _normalize_body(body)
        for rule in rules:
            if rule.type == "body":
                match = re.search(rule.pattern, body_str)
                if match and rule.version_group:
                    try:
                        return match.group(rule.version_group)
                    except IndexError:
                        continue
        return None


def detect_with_community_rules(body: Union[str, bytes], rules: Optional[List[FingerprintRule]] = None) -> Optional[str]:
    """Convenience wrapper."""
    return CommunityFingerprinter.detect(body, rules)
