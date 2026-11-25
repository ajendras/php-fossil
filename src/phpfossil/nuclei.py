"""Nuclei integration for exploit validation.

Uses subprocess to call the nuclei binary. Supports custom template directories via
the ConfigSettings.nuclei_templates_dir option. Falls back gracefully if nuclei is not
available or templates fail to load.
"""

import json
import subprocess
from pathlib import Path
from typing import List, Optional

from .models import ConfigSettings, NucleiFinding


def validate_with_nuclei(
    url: str, config: Optional[ConfigSettings] = None
) -> List[NucleiFinding]:
    """Validate a target with Nuclei templates.

    If config.nuclei_templates_dir is provided and exists, it is passed with -t to limit
    to that directory's templates. Otherwise uses Nuclei's default template set.

    Returns list of NucleiFinding objects.
    """
    if config is None or not getattr(config, "use_nuclei", False):
        return []

    cmd = [
        "nuclei",
        "-u",
        url,
        "-json",
        "-silent",
        "-timeout",
        str(getattr(config, "timeout", 10)),
    ]

    nuclei_dir = getattr(config, "nuclei_templates_dir", None)
    if nuclei_dir:
        dir_path = Path(str(nuclei_dir))
        if dir_path.exists():
            cmd.extend(["-t", str(dir_path)])

    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=45,
            check=False,
        )
        findings: List[NucleiFinding] = []
        for line in completed.stdout.split("\n"):
            line = line.strip()
            if line:
                try:
                    raw = json.loads(line)
                    findings.append(NucleiFinding.model_validate(raw))
                except (json.JSONDecodeError, ValueError):
                    continue
        return findings
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        # Graceful degradation - nuclei not in PATH or other issues
        return []


class NucleiValidator:
    """Wrapper for batch validation with a fixed config."""

    def __init__(self, config: ConfigSettings):
        self.config = config

    def scan(self, url: str) -> List[NucleiFinding]:
        return validate_with_nuclei(url, self.config)


__all__ = ["validate_with_nuclei", "NucleiValidator"]
