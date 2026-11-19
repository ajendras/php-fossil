"""Local Ollama LLM integration for generating executive summaries and remediation advice.

No additional dependencies; uses direct HTTP calls to the Ollama REST API running on localhost:11434.
"""

import httpx
from typing import List, Optional

from .models import ScanResult


def is_ollama_available(timeout: int = 3) -> bool:
    """Quick check if Ollama service is reachable.

    Used by CLI, TUI and scanner to decide whether to attempt summarization.
    """
    try:
        with httpx.Client(timeout=timeout) as client:
            response = client.get("http://localhost:11434/api/tags")
            return response.is_success
    except Exception:
        return False


def generate_summary(
    results: List[ScanResult], model: str = "llama3"
) -> str:
    """Generate a natural-language executive summary using Ollama.

    Constructs a prompt from the top risk findings and returns the model response.
    Falls back gracefully on any error (Ollama not running, network issue, etc).
    """
    if not results:
        return "No scan results to summarize."

    # Build compact prompt (limit input size)
    prompt_lines = [
        "You are a senior security engineer specializing in legacy PHP applications.",
        "Provide a concise executive summary (3-5 sentences) for the following scan results.",
        "Highlight the highest risk items, any exposed database schemas or credentials,",
        "and prioritized remediation steps.\n",
    ]

    for result in sorted(results, key=lambda r: r.risk_score, reverse=True)[:4]:
        vuln_count = len(result.vulns)
        nuclei_count = len(result.nuclei_findings)
        exposed = len(result.exposed_files)
        summary_line = (
            f"- {result.url} | PHP {result.php_version or 'unknown'} | "
            f"Risk Score: {result.risk_score} | Vulns: {vuln_count}"
        )
        if nuclei_count:
            summary_line += f" | Nuclei: {nuclei_count}"
        if exposed:
            summary_line += f" | Exposed files: {exposed}"
        prompt_lines.append(summary_line)

    prompt = "\n".join(prompt_lines)

    try:
        with httpx.Client(timeout=45.0) as client:
            resp = client.post(
                "http://localhost:11434/api/generate",
                json={
                    "model": model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": 0.7},
                },
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("response", "").strip()
    except httpx.RequestError as exc:
        return f"Could not connect to Ollama: {exc}"
    except Exception as exc:
        return f"Summary generation failed: {exc}"


class OllamaSummarizer:
    """Ollama wrapper following the same pattern as NucleiValidator and CommunityFingerprinter."""

    def __init__(self, model: str = "llama3"):
        self.model = model

    def summarize(self, results: List[ScanResult]) -> str:
        """Generate summary using the configured model."""
        return generate_summary(results, self.model)

    @staticmethod
    def is_available() -> bool:
        """Check availability without instantiating."""
        return is_ollama_available()


__all__ = ["generate_summary", "is_ollama_available", "OllamaSummarizer"]
