"""Module 10: Local/Remote LLM call helpers for suggestion generation.

This module previously implemented "Threat Chain Knowledge Acquisition &
Human Curation" (MITRE ATLAS fetch -> LLM candidate synthesis -> human
review -> attack_patterns). That feature has been replaced by the
Ontology & Description Suggestions tab (tabs/threat_curation_chain.py),
which uses Ollama to compare a tool's declared description/classification
against its real implementation source, as an advisory-only suggestion.

What remains here is just the generic LLM call plumbing that tab depends
on. It has no opinion on capabilities, ontology, or attack patterns:
- It never writes to the database.
- It never decides a tool's C1-C6 classification.
- Its output is always raw text/JSON handed back to the caller to
  interpret and present to a human.
"""

from __future__ import annotations

import json
import os
from typing import Any, Optional, Tuple

MODULE_NAME = "Module 10: LLM Call Helpers"

DEFAULT_OPENAI_MODEL = "gpt-4o-mini"
DEFAULT_OLLAMA_MODEL = "qwen3:14b"
DEFAULT_OLLAMA_URL = "http://localhost:11434"

OLLAMA_CONNECT_TIMEOUT = 10    # connect to Ollama
OLLAMA_READ_TIMEOUT = 300      # local generation can be slow


def generate_with_openai(
    prompt: str, model: Optional[str] = None
) -> Tuple[str, str]:
    try:
        from openai import OpenAI
    except ImportError as exc:
        raise RuntimeError("Install openai: pip install openai") from exc

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is not configured.")

    selected_model = model or os.getenv("OPENAI_MODEL", DEFAULT_OPENAI_MODEL)

    response = OpenAI(api_key=api_key).chat.completions.create(
        model=selected_model,
        temperature=0,
        response_format={"type": "json_object"},
        messages=[
            {
                "role": "system",
                "content": (
                    "You produce strictly structured JSON for a defensive "
                    "security research system."
                ),
            },
            {"role": "user", "content": prompt},
        ],
    )
    content = response.choices[0].message.content
    if not content:
        raise RuntimeError("OpenAI returned an empty response.")
    return content, selected_model


def generate_with_ollama(
    prompt: str,
    model: Optional[str] = None,
    base_url: Optional[str] = None,
) -> Tuple[str, str]:
    import requests

    selected_model = model or os.getenv("OLLAMA_MODEL", DEFAULT_OLLAMA_MODEL)
    selected_url = base_url or os.getenv("OLLAMA_BASE_URL", DEFAULT_OLLAMA_URL)
    endpoint = selected_url.rstrip("/") + "/api/generate"

    try:
        response = requests.post(
            endpoint,
            json={
                "model": selected_model,
                "prompt": prompt,
                "stream": False,
                "format": "json",
                "think": False,  # qwen3 thinking eats num_predict
                "keep_alive": "10m",
                "options": {"temperature": 0, "num_predict": 4096},
            },
            timeout=(OLLAMA_CONNECT_TIMEOUT, OLLAMA_READ_TIMEOUT),
        )
    except requests.exceptions.ReadTimeout as exc:
        raise RuntimeError(
            f"Ollama model '{selected_model}' did not finish within "
            f"{OLLAMA_READ_TIMEOUT}s. Try a smaller/faster model or check "
            "system memory."
        ) from exc
    except requests.exceptions.ConnectionError as exc:
        raise RuntimeError(
            f"Could not reach Ollama at {endpoint}. Make sure Ollama "
            "is running."
        ) from exc

    response.raise_for_status()
    content = response.json().get("response")
    if not content:
        raise RuntimeError("Ollama returned an empty response.")
    return content, selected_model


def parse_llm_json(raw: str) -> Any:
    """Parse an LLM's JSON reply, tolerating stray markdown code fences.

    Some local models wrap JSON in ```...``` even when asked not to.
    This strips a single leading/trailing fence line before parsing.
    Raises json.JSONDecodeError (not silently swallowed) if the result
    still isn't valid JSON, so callers can show the raw text to a human
    instead of guessing at a fallback value.
    """
    text = raw.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    return json.loads(text)
