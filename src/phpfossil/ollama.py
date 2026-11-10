"""Ollama integration for PHP Fossil.

Provides functions to generate natural-language executive summaries of
scan results using a locally running Ollama instance (http://localhost:11434).
No additional Python dependencies — uses existing httpx client.
Consistent style with nuclei.py.
"""

import json
from typing import List, Optional

import httpx

from .models import ScanResult


def is_ollama_available() -> bool:
    """Check if an Ollama service is reachable on the default localhost port.

    Returns:
        True if Ollama responds to /api/tags, False otherwise.
    """
    try:
        resp = httpx.get("http://localhost:11434/api/tags", timeout=2.0)
        return resp.status_code == 200
    except Exception:  # noqa: BLE001
        return False


def generate_summary(
    results: List[ScanResult],
    model: str = "llama3",
    timeout: int = 30,
) -> str:
    """Generate an LLM-powered natural language summary of discovered issues.

    Builds a compact context from all ScanResult objects and sends a
    structured prompt to Ollama's /api/chat endpoint. Returns a Markdown
    executive summary with risk level and remediation steps.

    Falls back gracefully when Ollama is unavailable or returns an error.

    Args:
        results: List of ScanResult objects (usually from scan_targets).
        model: Name of the Ollama model (must be pulled locally).
        timeout: Timeout for the Ollama HTTP request in seconds.

    Returns:
        Markdown summary text or a helpful fallback message.
    """
    if not results:
        return "No scan results to summarize."

    if not is_ollama_available():
        return (
            "# LLM Summary Unavailable\n\n"
            "Ollama does not appear to be running.\n\n"
            "Start the service and pull a model:\n"
            "```bash\n"
            "ollama serve\n"
            "ollama pull llama3\n"
            "```\n\n"
            "Then re-run the scan with `--ollama` (or `use_ollama=True`)."
        )

    # Build compact context (limit to first 4 targets to keep prompt reasonable)
    findings: List[str] = []
    for r in results[:4]:
        entry = f"Target: {r.url}\n"
        if r.php_version:
            entry += f"PHP Version: {r.php_version}\n"
        if r.vulns:
            cves = ", ".join(v.cve for v in r.vulns[:3])
            entry += f"Vulnerabilities: {len(r.vulns)} ({cves})\n"
        if r.exposed_files:
            types = ", ".join(f.file_type for f in r.exposed_files)
            entry += f"Exposed files: {len(r.exposed_files)} ({types})\n"
        if r.nuclei_findings:
            confirmed = len([f for f in r.nuclei_findings if f.template != "error"])
            entry += f"Nuclei confirmations: {confirmed}\n"
        findings.append(entry.strip())

    context = "\n\n".join(findings)

    prompt = f"""You are a senior application security engineer specializing in legacy PHP.

Analyze the PHP Fossil scan results below and write a concise executive summary (maximum 320 words).

Include:
- Overall risk posture and why it matters
- The 2-3 most critical issues with CVE references
- Prioritized remediation steps (include target PHP versions)
- Any risks from exposed schemas or debug endpoints
- A final "Risk Level" line (Critical / High / Medium / Low)

Scan results:
{context}

Answer in clear Markdown using headings and bullet points. Never mention Ollama, the tool name, or that this is AI-generated."""

    try:
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": "You are an expert cybersecurity analyst."},
                {"role": "user", "content": prompt},
            ],
            "stream": False,
            "options": {"temperature": 0.6, "num_ctx": 4096},
        }

        response = httpx.post(
            "http://localhost:11434/api/chat",
            json=payload,
            timeout=timeout,
        )
        response.raise_for_status()
        data = response.json()
        content = data.get("message", {}).get("content", "")
        if not content:
            return "Ollama returned an empty response."
        return content.strip()

    except httpx.HTTPError as exc:
        return (
            f"# Summary Error\n\n"
            f"Could not reach Ollama: {exc}\n\n"
            f"Ensure `ollama serve` is running and the model '{model}' has been pulled."
        )
    except Exception as exc:  # noqa: BLE001
        return f"# Summary Generation Failed\n\nUnexpected error: {exc}"


class OllamaSummarizer:
    """Object-oriented wrapper for Ollama summary generation (mirrors NucleiValidator)."""

    @staticmethod
    def summarize(
        results: List[ScanResult], model: str = "llama3"
    ) -> str:
        """Run summarization and return the generated text."""
        return generate_summary(results, model=model)


__all__ = [
    "generate_summary",
    "is_ollama_available",
    "OllamaSummarizer",
]
