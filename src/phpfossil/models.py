"""Pydantic models for PHP Fossil.

Core data structures representing scan outcomes, vulnerabilities,
exposed files and parsed database schemas. All models include
validation, rich docstrings and secure defaults.
"""

import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class Vulnerability(BaseModel):
    """Represents a known vulnerability tied to a PHP version."""

    cve: str = Field(..., description="CVE identifier")
    title: str = Field(..., description="Short title of the vulnerability")
    severity: str = Field(..., description="Severity: critical, high, medium, low")
    description: str = Field(..., description="Detailed description")
    fixed_in: Optional[str] = Field(
        None, description="Version in which the issue was fixed"
    )
    reference: Optional[str] = Field(None, description="External reference URL")

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        allowed = {"critical", "high", "medium", "low"}
        if v.lower() not in allowed:
            raise ValueError(f"severity must be one of {allowed}")
        return v.lower()


class ExposedFile(BaseModel):
    """Represents a sensitive file discovered on a target (phpinfo, SQL dump, etc)."""

    url: str = Field(..., description="Full URL to the exposed file")
    file_type: str = Field(..., description="Type: phpinfo, sql_dump, backup, etc.")
    content_preview: Optional[str] = Field(
        None, description="Truncated preview of file content"
    )


class SchemaResult(BaseModel):
    """Parsed information from an exposed SQL dump."""

    tables: List[str] = Field(default_factory=list)
    columns: Dict[str, List[str]] = Field(default_factory=dict)
    row_counts: Dict[str, int] = Field(default_factory=dict)


class ScanResult(BaseModel):
    """Result of scanning one target."""

    url: str = Field(..., description="The scanned URL")
    php_version: Optional[str] = Field(
        None, description="Detected PHP version string e.g. '7.4.33'"
    )
    detected_from: List[str] = Field(
        default_factory=list, description="Sources that contributed to detection"
    )
    vulns: List[Vulnerability] = Field(default_factory=list)
    exposed_files: List[ExposedFile] = Field(default_factory=list)
    schema: Optional[SchemaResult] = None
    errors: List[str] = Field(default_factory=list)
    scan_time: datetime = Field(default_factory=datetime.utcnow)

    def is_vulnerable(self) -> bool:
        """Return True if any vulnerabilities were found."""
        return len(self.vulns) > 0

    @field_validator("php_version")
    @classmethod
    def validate_php_version(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        if not re.match(r"^\d+\.\d+(\.\d+)?$", v.strip()):
            raise ValueError("PHP version must match pattern X.Y or X.Y.Z")
        return v.strip()

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v


__all__ = [
    "Vulnerability",
    "ExposedFile",
    "SchemaResult",
    "ScanResult",
]
