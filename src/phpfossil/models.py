"""Pydantic models for PHP Fossil.

Core data structures representing scan outcomes, vulnerabilities,
exposed files, parsed database schemas and Nuclei validation results.
All models include validation, rich docstrings and secure defaults.
"""

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    computed_field,
    field_validator,
    model_validator,
)


DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]

DEFAULT_COMMUNITY_REPO_URL = "https://raw.githubusercontent.com/ajendras/php-fossil/main/community-fingerprints.json"


class Vulnerability(BaseModel):
    """Represents a known vulnerability tied to a PHP version."""

    cve: str = Field(..., description="CVE identifier")
    title: str = Field(..., description="Short title of the vulnerability")
    severity: str = Field(..., description="Severity: critical, high, medium, low")
    description: str = Field(..., description="Detailed description")
    fixed_in: Optional[str] = Field(None, description="Version that fixes the issue")
    references: List[str] = Field(default_factory=list, description="Links to advisories")


class ExposedFile(BaseModel):
    """Represents an exposed sensitive file (e.g. SQL dump)."""

    url: str
    content_type: str = "text/plain"
    size: Optional[int] = None
    snippet: Optional[str] = None


class SchemaResult(BaseModel):
    """Parsed database schema from an SQL dump."""

    tables: List[Dict[str, Any]] = Field(default_factory=list)
    raw_tables: int = 0
    sensitive_columns: List[str] = Field(default_factory=list)


class NucleiFinding(BaseModel):
    """Result from a Nuclei template run."""

    template: str
    name: str
    severity: str
    description: Optional[str] = None
    reference: Optional[str] = None

    @field_validator("severity", mode="before")
    @classmethod
    def normalize_severity(cls, v: Any) -> str:
        if isinstance(v, str):
            sev = v.lower().strip()
            if sev not in {"critical", "high", "medium", "low", "info", "unknown"}:
                return "medium"
            return sev
        return "medium"


class PassiveResult(BaseModel):
    """Result from passive reconnaissance (Shodan/Censys)."""

    url: str
    source: str
    port: int = 80
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    raw: Dict[str, Any] = Field(default_factory=dict)


class ScanResult(BaseModel):
    """Complete scan outcome for a single target."""

    url: str
    php_version: Optional[str] = None
    detected_from: List[str] = Field(default_factory=list)
    vulns: List[Vulnerability] = Field(default_factory=list)
    exposed_files: List[ExposedFile] = Field(default_factory=list)
    db_schema: Optional[SchemaResult] = None
    nuclei_findings: List[NucleiFinding] = Field(default_factory=list)
    llm_summary: Optional[str] = None
    scan_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    risk_score: int = 0

    model_config = ConfigDict(arbitrary_types_allowed=True)

    def is_vulnerable(self) -> bool:
        """Return True if the target has known vulnerabilities or confirmed exploits."""
        return bool(self.vulns) or bool(self.nuclei_findings)

    @computed_field
    @property
    def risk_summary(self) -> str:
        if self.risk_score >= 70:
            return "critical"
        if self.risk_score >= 40:
            return "high"
        if self.risk_score >= 20:
            return "medium"
        return "low"

    @field_validator("php_version")
    @classmethod
    def validate_version(cls, v: Optional[str]) -> Optional[str]:
        if v and not re.match(r"^\d+\.\d+(\.\d+)?$", v):
            raise ValueError("Invalid PHP version format")
        return v


class ConfigSettings(BaseModel):
    """Validated configuration for scans with sensible defaults.

    The `verbose` field controls logging level for the CLI (and can be
    respected by scanner/tui components). 0=WARNING, 1=INFO, 2=DEBUG.
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    max_concurrency: int = Field(default=20, ge=1, le=50)
    timeout: int = Field(default=12, ge=5, le=60)
    proxies: List[str] = Field(default_factory=list)
    user_agents: List[str] = Field(default_factory=list)
    use_nuclei: bool = False
    use_ollama: bool = False
    ollama_model: str = "llama3"
    use_community_fingerprints: bool = False
    community_repo_url: str = DEFAULT_COMMUNITY_REPO_URL
    db_path: Optional[Path] = None
    shodan_api_key: Optional[str] = Field(default=None, alias="shodan_api_key")
    censys_api_id: Optional[str] = None
    censys_api_secret: Optional[str] = None
    verbose: int = Field(default=0, ge=0, le=3)

    @model_validator(mode="after")
    def set_default_user_agents(self) -> "ConfigSettings":
        if not self.user_agents:
            self.user_agents = DEFAULT_USER_AGENTS[:]
        return self

    @model_validator(mode="after")
    def set_default_db_path(self) -> "ConfigSettings":
        if self.db_path is None:
            self.db_path = Path.home() / ".phpfossil" / "history.db"
        return self

    @field_validator("max_concurrency")
    @classmethod
    def cap_concurrency(cls, v: int) -> int:
        return min(v, 50)


class FingerprintRule(BaseModel):
    """Rule for community-sourced fingerprint detection."""

    type: str = Field(..., pattern="^(header|body|phpinfo|error_page)$")
    pattern: str
    version_group: int = 1


__all__ = [
    "Vulnerability",
    "ExposedFile",
    "SchemaResult",
    "NucleiFinding",
    "PassiveResult",
    "ScanResult",
    "ConfigSettings",
    "FingerprintRule",
    "DEFAULT_USER_AGENTS",
    "DEFAULT_COMMUNITY_REPO_URL",
]
