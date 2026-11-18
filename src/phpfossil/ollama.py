"""Local Ollama integration for generating summaries of scan results.

Uses the Ollama REST API (/api/tags and /api/chat). No extra dependencies.
Graceful fallback when Ollama is not running.
"""

import json
from typing import List, Optional

import httpx

from .models import ScanResult


def is_ollama_available() -> bool:
    """Quick check if Ollama service is reachable on localhost:11434."""
    try:
        with httpx.Client(timeout=2.0) as client:
            resp = client.get("http://localhost:11434/api/tags")
            return resp.status_code == 200
    except Exception:  # noqa: BLE001
        return False


def generate_summary(
    results: List[ScanResult], model: str = "llama3"
) -> str:
    """Generate an executive summary using local Ollama.

    Hits /api/chat with a crafted prompt based on vulnerable results.
    """
    if not results:
        return "No results to summarize."

    vulnerable = [r for r in results if r.is_vulnerable() or r.exposed_files]
    if not vulnerable:
        return (
            "All scanned targets appear to be using modern PHP versions "
            "with no immediate issues detected."
        )

    prompt = (
        f"You are a security expert. Summarize the following PHP legacy scan "
        f"in 3-4 sentences.\n\n"
        f"Found {len(vulnerable)} at-risk target(s).\n"
        f"PHP versions: {sorted({r.php_version for r in vulnerable if r.php_version})}\n"
        f"Risk scores: {sorted({r.risk_score for r in vulnerable})}\n"
        f"Key findings: exposed schemas, old CVEs, possible RCE/LFI.\n\n"
        f"Provide prioritized recommendations."
    )

    try:
        with httpx.Client(timeout=30.0) as client:
            resp = client.post(
                "http://localhost:11434/api/chat",
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": False,
                },
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("message", {}).get(
                "content", "Summary generation returned no content."
            )
    except Exception as exc:  # noqa: BLE001
        return (
            f"Ollama summary unavailable: {str(exc)}. "
            "Ensure Ollama is running and a model is pulled."
        )


class OllamaSummarizer:
    """Wrapper for Ollama functionality (consistent with other modules)."""

    @staticmethod
    def summarize(results: List[ScanResult], model: str = "llama3") -> str:
        return generate_summary(results, model)

    @staticmethod
    def is_available() -> bool:
        return is_ollama_available()


__all__ = ["generate_summary", "is_ollama_available", "OllamaSummarizer"]
