"""Nuclei integration for confirming exploitable vulnerabilities on discovered legacy PHP sites.

Uses subprocess to invoke the nuclei CLI tool and parses JSON output into Pydantic models.
"""

import json
import subprocess
from typing import List, Optional, Any

from .models import NucleiFinding


def validate_with_nuclei(
    targets: List[str],
    templates: Optional[List[str]] = None,
    templates_dir: Optional[str] = None,
    timeout: int = 45,
) -> List[NucleiFinding]:
    """Execute Nuclei against one or more targets.

    Returns list of NucleiFinding objects. If the nuclei binary is not found
    or any error occurs, returns empty list (graceful degradation).
    Supports templates_dir for backwards compatibility with tests.
    """
    if templates_dir and not templates:
        templates = [templates_dir]
    if not templates:
        templates = ["cves/php", "vulnerabilities/php", "http/technologies/php"]

    findings: List[NucleiFinding] = []

    for target in targets:
        cmd = [
            "nuclei",
            "-target", target,
            "-json",
            "-silent",
            "-timeout", "10",
        ]
        if templates:
            cmd.extend(["-t"] + templates)

        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )

            if completed.stdout:
                for line in completed.stdout.splitlines():
                    line = line.strip()
                    if line:
                        try:
                            raw: dict[str, Any] = json.loads(line)
                            finding = NucleiFinding.model_validate(raw)
                            findings.append(finding)
                        except (json.JSONDecodeError, ValueError):
                            continue
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            # nuclei not installed or timed out - common in CI without go install
            continue
        except Exception:
            continue

    return findings


class NucleiValidator:
    """Encapsulates Nuclei usage, mirroring OllamaSummarizer style."""

    def __init__(self, templates: Optional[List[str]] = None, templates_dir: Optional[str] = None):
        self.templates = templates or []
        self.templates_dir = templates_dir

    def validate(self, targets: List[str], timeout: int = 45) -> List[NucleiFinding]:
        templates = self.templates
        if self.templates_dir:
            templates = templates + [self.templates_dir] if templates else [self.templates_dir]
        return validate_with_nuclei(
            targets, templates=templates, templates_dir=self.templates_dir, timeout=timeout
        )

    @staticmethod
    def is_available() -> bool:
        """Test if the nuclei binary can be executed."""
        try:
            subprocess.run(
                ["nuclei", "-version"],
                capture_output=True,
                timeout=5,
                check=False,
            )
            return True
        except FileNotFoundError:
            return False
        except Exception:
            return False


__all__ = ["validate_with_nuclei", "NucleiValidator"]
