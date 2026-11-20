"""PHP Fossil — discovers legacy PHP sites via search dorks, fingerprints old versions,
maps vulns, extracts schemas and builds prioritized security lists.

Public API:
    scan_targets (async — wrap with asyncio.run() from sync code; now accepts ConfigSettings
    or dict for validated configuration with defaults),
    generate_dorks, generate_report (supports terminal/html/csv),
    validate_with_nuclei, generate_summary, ScanResult, Vulnerability,
    NucleiFinding, get_vulns_for_version, parse_sql_dump, store_results,
    get_historical_results, Store, run_tui,
    passive_discover, search_shodan, search_censys, PassiveResult,
    ConfigSettings (new: pydantic-based validated settings with defaults and DX improvements),
    is_version_eol, get_eol_date (new: EOL status for any PHP version).

The embedded VulnDB now contains 215+ CVEs (35+ new entries for PHP 8.0-8.3)
and automatically injects critical-severity EOL entries for unsupported releases.

CSV output (output_format="csv") produces one row per vulnerability with
columns suitable for direct import into bug-bounty platforms (HackerOne,
Bugcrowd, etc).

Community fingerprint repository:
    load_community_fingerprints(), CommunityFingerprinter, FingerprintRule
"""

__version__ = "0.1.0"

from .models import (
    ExposedFile,
    FingerprintRule,
    NucleiFinding,
    ScanResult,
    SchemaResult,
    Vulnerability,
    PassiveResult,
    ConfigSettings,
    DEFAULT_USER_AGENTS,
    DEFAULT_COMMUNITY_REPO_URL,
)
from .scanner import scan_targets
from .search import generate_dorks
from .reporter import generate_report
from .vulndb import (
    get_vulns_for_version,
    is_version_eol,
    get_eol_date,
)
from .schema import parse_sql_dump
from .store import Store, get_historical_results, store_results
from .fingerprinter import (
    detect_from_headers,
    detect_from_body,
    detect_from_phpinfo,
    detect_from_error_page,
    detect_php_version,
    detect_wordpress_version,
    detect_joomla_version,
    detect_laravel_version,
    detect_drupal_version,
    detect_magento_version,
    detect_prestashop_version,
    detect_cms_version,
    load_community_fingerprints,
    detect_with_community_rules,
    CommunityFingerprinter,
)
from .nuclei import validate_with_nuclei, NucleiValidator
from .ollama import generate_summary, is_ollama_available, OllamaSummarizer
from .tui import run_tui
from .passive import (
    passive_discover,
    search_shodan,
    search_censys,
    ShodanSearcher,
    CensysSearcher,
)

__all__ = [
    "__version__",
    "scan_targets",
    "generate_dorks",
    "generate_report",
    "validate_with_nuclei",
    "generate_summary",
    "ScanResult",
    "Vulnerability",
    "NucleiFinding",
    "ExposedFile",
    "SchemaResult",
    "get_vulns_for_version",
    "is_version_eol",
    "get_eol_date",
    "parse_sql_dump",
    "store_results",
    "get_historical_results",
    "Store",
    # Fingerprinter helpers
    "detect_from_headers",
    "detect_from_body",
    "detect_from_phpinfo",
    "detect_from_error_page",
    "detect_php_version",
    "detect_wordpress_version",
    "detect_joomla_version",
    "detect_laravel_version",
    "detect_drupal_version",
    "detect_magento_version",
    "detect_prestashop_version",
    "detect_cms_version",
    # Community fingerprint repository
    "load_community_fingerprints",
    "detect_with_community_rules",
    "CommunityFingerprinter",
    "FingerprintRule",
    # Nuclei helpers
    "NucleiValidator",
    # Ollama helpers
    "generate_summary",
    "is_ollama_available",
    "OllamaSummarizer",
    # TUI
    "run_tui",
    # Passive discovery
    "passive_discover",
    "search_shodan",
    "search_censys",
    "ShodanSearcher",
    "CensysSearcher",
    "PassiveResult",
    # New validated configuration
    "ConfigSettings",
    "DEFAULT_USER_AGENTS",
    "DEFAULT_COMMUNITY_REPO_URL",
]
