"""Module 10: AI Tool Description & Metadata Generator (Ollama or ChatGPT).

This module used to be plain "LLM call helpers" for the Ontology &
Description Suggestions tab, which itself replaced the earlier Threat
Curation Chain feature. It now owns the full pipeline behind the AI Tool
Description & Metadata Generator tab (tabs/tool_desc_generator.py):

- reading the project's fixed C1-C6 capability lexicon straight from the
  JSON rule files in capability_lexicon/ (not a hand-written summary of
  them),
- building the prompt that grounds an LLM in that lexicon plus whatever
  is actually known about one tool (its declared name/description, its
  current Module 3 classification, and its real implementation source
  when one is found), and
- calling either a local Ollama model or OpenAI's ChatGPT API to draft a
  corrected description and capability metadata.

Hard rules, matching the rest of this project:
- The capability set this module offers the LLM is exactly whatever is
  defined in the lexicon JSON files at the configured path, read fresh
  every call. Nothing here hardcodes C1-C6 - if the project's lexicon
  changes, so does what the LLM is allowed to suggest.
- This module never writes to capability_lexicon/*.json, the ontology
  database, or a tool's declared metadata. Everything it returns is a
  plain dict for a human to review and apply elsewhere (Edit Database
  tab).
- This module never re-runs or overrides the Module 3 lexical
  classifier and has no opinion of its own on a tool's capabilities
  beyond what it asks the LLM to derive from real material.
- If a tool's source is not available, callers should pass source=None;
  this module tells the LLM plainly that no source was found rather
  than fabricating or reconstructing one.
- Any error talking to Ollama/OpenAI, or parsing its reply, is returned
  to the caller instead of being swallowed or silently defaulted.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Optional, Tuple

MODULE_NAME = "Module 10: AI Tool Description & Metadata Generator"

DEFAULT_OPENAI_MODEL = "gpt-4o-mini"
DEFAULT_OLLAMA_MODEL = "qwen3:14b"
DEFAULT_OLLAMA_URL = "http://localhost:11434"
DEFAULT_LEXICON_DIR = r"C:\Users\amal4\PycharmProjects\ToolAssist\capability_lexicon"

OLLAMA_CONNECT_TIMEOUT = 10    # connect to Ollama
OLLAMA_READ_TIMEOUT = 300      # local generation can be slow


# ============================================================
# CAPABILITY LEXICON (read straight from capability_lexicon/*.json)
# ============================================================

def load_capability_lexicon(lexicon_dir: str) -> Tuple[list, list]:
    """Read every capability rule file in lexicon_dir.

    Returns (capabilities, warnings):
      - capabilities: one dict per file that parsed successfully, with
        whatever fields that file actually has (capability_id,
        capability_name, schema_version, notes, confidence_values,
        rules, ...) plus "_source_file" pointing at the file it came
        from. Sorted by capability_id.
      - warnings: human-readable strings for any file that was missing,
        unreadable, or missing a capability_id - these are surfaced to
        the user, never silently dropped.
    """
    capabilities = []
    warnings = []

    directory = Path(lexicon_dir)

    if not directory.is_dir():
        warnings.append(f"Capability lexicon directory not found: {lexicon_dir}")
        return capabilities, warnings

    json_files = sorted(directory.glob("*.json"))

    if not json_files:
        warnings.append(f"No .json files found in {lexicon_dir}")
        return capabilities, warnings

    for path in json_files:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError) as error:
            warnings.append(f"Could not read {path.name}: {error}")
            continue

        if "capability_id" not in data:
            warnings.append(f"{path.name} has no 'capability_id' field - skipped")
            continue

        data["_source_file"] = str(path)
        capabilities.append(data)

    capabilities.sort(key=lambda cap: cap.get("capability_id", ""))
    return capabilities, warnings


def format_lexicon_reference(capabilities: list) -> str:
    """Render the loaded lexicon as plain text for the LLM prompt.

    This lists every enabled regex rule and the reason it was written,
    exactly as authored in the JSON files, so the LLM is grounded in the
    real matching logic the automated classifier uses - not someone's
    paraphrase of it.
    """
    if not capabilities:
        return "(No capability lexicon files were loaded.)"

    blocks = []

    for cap in capabilities:
        lines = [f"{cap.get('capability_id')} - {cap.get('capability_name')}"]

        if cap.get("notes"):
            lines.append(f"  Notes: {cap['notes']}")

        rules = cap.get("rules", []) or []
        enabled_rules = [rule for rule in rules if rule.get("enabled", True)]

        if enabled_rules:
            lines.append("  Regex signals used by the automated classifier:")
            for rule in enabled_rules:
                lines.append(
                    "    - pattern {!r} ({} confidence): {}".format(
                        rule.get("pattern", ""),
                        rule.get("confidence", "?"),
                        rule.get("reason", ""),
                    )
                )
        else:
            lines.append("  (No enabled rules found for this capability.)")

        blocks.append("\n".join(lines))

    return "\n\n".join(blocks)


# ============================================================
# TOOL STATE (what the pipeline already knows about one tool)
# ============================================================

def describe_current_classification(tool: dict) -> str:
    """Render a tool's current Module 3 classification as text."""
    mapping = tool.get("mapping", {}) or {}
    mappings_list = mapping.get("mappings", [])

    if not mappings_list:
        return mapping.get("mapping_reason", "No normalized capabilities found - UNMAPPED")

    lines = []
    for entry in mappings_list:
        lines.append(
            "{} (confidence {}): matched \"{}\" - {}".format(
                entry.get("capability_id"),
                entry.get("confidence"),
                entry.get("normalized_match"),
                entry.get("reason"),
            )
        )
    return "\n".join(lines)


# ============================================================
# PROMPT CONSTRUCTION
# ============================================================

def build_tool_description_prompt(tool: dict, lexicon_text: str, source: Optional[dict] = None) -> str:
    """Build the exact prompt sent to the LLM. Grounded only in real inputs."""

    tool_name = tool.get("tool") or tool.get("tool_name") or "unknown_tool"
    description = tool.get("description") or "No description provided."
    classification_text = describe_current_classification(tool)

    if source:
        source_block = (
            "REAL IMPLEMENTATION SOURCE (found in this project at "
            f"{source.get('file')}, line {source.get('line')}, match kind: "
            f"{source.get('match_kind')}):\n```\n{source.get('snippet', '')}\n```"
        )
    else:
        source_block = (
            "No implementation source was found in this project's "
            "src_server_code/ for this tool. Base the suggestion only on "
            "the declared description and the lexicon below - do not "
            "invent behavior you have not been shown."
        )

    return f"""You are helping a defensive security research project write an
accurate declared description and capability metadata for one MCP tool.
You do not execute any tool. You only work from the text already given
to you below.

FIXED CAPABILITY LEXICON (the ONLY capabilities you may choose from -
this is the exact rule set the project's automated lexical classifier
uses, not a summary of it):
{lexicon_text}

DECLARED TOOL NAME: {tool_name}

CURRENT DECLARED DESCRIPTION:
{description}

CURRENT AUTOMATED CLASSIFICATION (produced by a separate lexical rule
engine, not by you):
{classification_text}

{source_block}

Task: write a corrected, accurate one-paragraph description for this
tool, and say which of the fixed capabilities above genuinely apply,
grounded only in the material given to you. If nothing above supports a
capability, do not suggest it. If none of the fixed capabilities fit,
return an empty list and explain why in "notes". Do not invent a new
capability id, and do not describe behavior that isn't shown to you.

Respond with strictly valid JSON only, matching this exact schema:

{{
  "matches_current_description": true or false,
  "matches_current_classification": true or false,
  "suggested_description": "a corrected, accurate one-paragraph description, or empty string if matches_current_description is true",
  "suggested_capabilities": ["C_", ...] or [],
  "capability_justification": "one or two sentences citing specific lexicon rules or source lines that support the suggested capabilities, or empty string if matches_current_classification is true",
  "suggested_metadata": {{
    "short_summary": "one plain sentence describing what the tool does",
    "tags": ["short", "keyword", "tags"]
  }},
  "notes": "anything else worth flagging for a human reviewer, or empty string"
}}

Do not include any text outside the JSON object."""


# ============================================================
# LLM CALL HELPERS
# ============================================================

def generate_with_openai(prompt: str, model: Optional[str] = None) -> Tuple[str, str]:
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

    Some models wrap JSON in ```...``` even when asked not to. This
    strips a single leading/trailing fence line before parsing. Raises
    json.JSONDecodeError (not silently swallowed) if the result still
    isn't valid JSON, so callers can show the raw text to a human
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


# ============================================================
# TOP-LEVEL ORCHESTRATOR
# ============================================================

def generate_tool_description(
    tool: dict,
    lexicon_dir: str,
    backend: str,
    model: Optional[str] = None,
    base_url: Optional[str] = None,
    source: Optional[dict] = None,
) -> dict:
    """Load the lexicon, build the prompt, call the chosen backend, and
    parse its JSON reply.

    backend must be "ollama" or "openai". Always returns a dict: either
    the parsed suggestion (plus "_model", "_backend", and
    "lexicon_warnings") or an "error" key describing what went wrong.
    Nothing is silently swallowed or defaulted.
    """
    capabilities, warnings = load_capability_lexicon(lexicon_dir)
    lexicon_text = format_lexicon_reference(capabilities)

    prompt = build_tool_description_prompt(tool, lexicon_text, source=source)

    try:
        if backend == "ollama":
            raw, selected_model = generate_with_ollama(prompt, model=model, base_url=base_url)
        elif backend == "openai":
            raw, selected_model = generate_with_openai(prompt, model=model)
        else:
            return {"error": f"Unknown backend: {backend!r}", "lexicon_warnings": warnings}
    except Exception as error:
        return {"error": str(error), "lexicon_warnings": warnings}

    try:
        parsed = parse_llm_json(raw)
    except json.JSONDecodeError as error:
        return {
            "error": (
                f"{backend} did not return valid JSON. Showing the raw "
                f"response instead. Parse error: {error}"
            ),
            "raw": raw,
            "model": selected_model,
            "lexicon_warnings": warnings,
        }

    parsed["_model"] = selected_model
    parsed["_backend"] = backend
    parsed["lexicon_warnings"] = warnings
    return parsed