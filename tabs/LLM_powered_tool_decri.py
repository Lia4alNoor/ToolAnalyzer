"""AI Tool Description & Metadata Generator — ontology + lexicon aware.

Combines the Streamlit UI and Module 10 backend.
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
DEFAULT_LEXICON_DIR = (
    r"C:\Users\amal4\PycharmProjects\ToolAssist\capability_lexicon"
)

OLLAMA_CONNECT_TIMEOUT = 10
OLLAMA_READ_TIMEOUT = 300

# Capability ontology: the authoritative semantic boundaries behind each
# lexicon category. The regex lexicon is a heuristic signal for these
# boundaries, not a substitute for them.
ONTOLOGY = [
    {
        "id": "C1",
        "name": "External Data Ingestion",
        "inclusion": "Tools fetching public or untrusted external data into context (web scrapers, search, social fetchers).",
        "exclusion": "Reading private/local user assets (maps to C2).",
    },
    {
        "id": "C2",
        "name": "Sensitive Data Access",
        "inclusion": "Tools reading local private files, credentials, health/financial records, or personal logs.",
        "exclusion": "Transmitting retrieved records across a network endpoint (maps to C3).",
    },
    {
        "id": "C3",
        "name": "External Communication",
        "inclusion": "Tools performing outbound network messaging, data transmission, emails, webhooks, or social posts.",
        "exclusion": "Modifying local files or local system state without network egress (maps to C4).",
    },
    {
        "id": "C4",
        "name": "State Modification",
        "inclusion": "Tools creating, modifying, appending to, or deleting local files, databases, or configs.",
        "exclusion": "Executing arbitrary OS terminal commands or dynamic scripts (maps to C5).",
    },
    {
        "id": "C5",
        "name": "System Execution",
        "inclusion": "Tools spawning OS shell commands, running Python/JS code scripts, binaries, or reverse shells.",
        "exclusion": "Actuating physical hardware or IoT devices (maps to C6).",
    },
    {
        "id": "C6",
        "name": "Physical Actuation",
        "inclusion": "Tools controlling physical hardware, IoT smart home appliances, smart locks, or actuators.",
        "exclusion": "Pure compute/digital OS execution without hardware actuation (maps to C5).",
    },
]


def format_ontology_reference(ontology: list) -> str:
    """Render the ontology boundaries as plain text for the prompt."""
    blocks = []
    for cat in ontology:
        blocks.append(
            f"{cat['id']} - {cat['name']}\n"
            f"  Included: {cat['inclusion']}\n"
            f"  Excluded: {cat['exclusion']}"
        )
    return "\n\n".join(blocks)


# ============================================================
# SOURCE LOOKUP
# ============================================================

def _find_source(tool: dict) -> Optional[dict]:
    """Best-effort lookup of a tool's implementation in src_server_code/."""
    root = Path("src_server_code")
    if not root.is_dir():
        return None

    name = tool.get("tool") or tool.get("tool_name") or ""

    for p in root.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in {
            ".py", ".js", ".ts", ".tsx", ".java", ".go", ".rs"
        }:
            continue
        try:
            txt = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if name and name in txt:
            lines = txt.splitlines()
            for i, line in enumerate(lines, 1):
                if name in line:
                    lo, hi = max(1, i - 5), min(len(lines), i + 10)
                    return {
                        "file": str(p),
                        "match_kind": "tool-name",
                        "line": i,
                        "snippet": "\n".join(lines[lo - 1:hi]),
                        "language": p.suffix.lstrip("."),
                    }
    return None


def describe_availability(tool: dict) -> dict:
    source = _find_source(tool)
    if source:
        return {"source": source, "message": "Implementation source found."}
    return {"source": None, "message": "No matching implementation source found."}


# ============================================================
# CAPABILITY LEXICON
# ============================================================

def load_capability_lexicon(lexicon_dir: str) -> Tuple[list, list]:
    """Load every capability rule JSON file in lexicon_dir."""
    capabilities: list = []
    warnings: list = []

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
    """Render the loaded lexicon rules as plain text for the prompt."""
    if not capabilities:
        return "(No capability lexicon files were loaded.)"

    blocks = []
    for cap in capabilities:
        lines = [f"{cap.get('capability_id')} - {cap.get('capability_name')}"]
        if cap.get("notes"):
            lines.append(f"  Notes: {cap['notes']}")

        enabled_rules = [r for r in cap.get("rules", []) or [] if r.get("enabled", True)]
        if enabled_rules:
            lines.append("  Regex signals used by the automated classifier:")
            for rule in enabled_rules:
                lines.append(
                    "    - pattern {!r} ({} confidence): {}".format(
                        rule.get("pattern", ""), rule.get("confidence", "?"), rule.get("reason", "")
                    )
                )
        else:
            lines.append("  (No enabled rules found for this capability.)")

        blocks.append("\n".join(lines))

    return "\n\n".join(blocks)


# ============================================================
# TOOL STATE
# ============================================================

def describe_current_classification(tool: dict) -> str:
    """Render a tool's current Module 3 classification as text."""
    mapping = tool.get("mapping", {}) or {}
    mappings_list = mapping.get("mappings", [])

    if not mappings_list:
        return mapping.get("mapping_reason", "No normalized capabilities found - UNMAPPED")

    return "\n".join(
        "{} (confidence {}): matched \"{}\" - {}".format(
            e.get("capability_id"), e.get("confidence"), e.get("normalized_match"), e.get("reason")
        )
        for e in mappings_list
    )


# ============================================================
# PROMPT CONSTRUCTION
# ============================================================

def build_tool_description_prompt(
    tool: dict,
    ontology_text: str,
    lexicon_text: str,
    source: Optional[dict] = None,
) -> str:
    """Build the exact prompt sent to the LLM."""
    tool_name = tool.get("tool") or tool.get("tool_name") or "unknown_tool"
    description = tool.get("description") or "No description provided."
    classification_text = describe_current_classification(tool)

    if source:
        source_block = (
            "REAL IMPLEMENTATION SOURCE (found in this project at "
            f"{source.get('file')}, line {source.get('line')}, match kind: {source.get('match_kind')}):\n"
            f"```\n{source.get('snippet', '')}\n```"
        )
    else:
        source_block = (
            "No implementation source was found in this project's src_server_code/ "
            "for this tool. Base the suggestion only on the declared description and "
            "the material below - do not invent behavior you have not been shown."
        )

    return f"""You are helping a defensive security research project write an
accurate declared description and capability metadata for one MCP tool.
You do not execute any tool. You only work from the text already given
to you below.

CAPABILITY ONTOLOGY (authoritative boundary definitions - use these to
resolve edge cases; place the tool in a category only if it satisfies
that category's inclusion boundary AND does not fall under its
exclusion boundary):
{ontology_text}

FIXED CAPABILITY LEXICON (the exact regex rule set the project's
automated lexical classifier uses - a heuristic signal, not a
definition; where a regex hit conflicts with the ontology boundaries
above, the ontology wins):
{lexicon_text}

DECLARED TOOL NAME: {tool_name}

CURRENT DECLARED DESCRIPTION:
{description}

CURRENT AUTOMATED CLASSIFICATION (produced by a separate lexical rule
engine, not by you):
{classification_text}

{source_block}

Task: write a corrected, accurate one-paragraph description for this
tool, and say which of the fixed capabilities (C1-C6) genuinely apply,
grounded only in the material given to you and consistent with the
ontology's inclusion/exclusion boundaries. If nothing above supports a
capability, do not suggest it. If none of the fixed capabilities fit,
return an empty list and explain why in "notes". Do not invent a new
capability id, and do not describe behavior that isn't shown to you.

Respond with strictly valid JSON only, matching this exact schema:

{{
  "matches_current_description": true or false,
  "matches_current_classification": true or false,
  "suggested_description": "a corrected, accurate one-paragraph description, or empty string if matches_current_description is true",
  "suggested_capabilities": ["C_", ...] or [],
  "capability_justification": "one or two sentences citing the specific ontology boundary and/or lexicon rule behind each suggested capability, or empty string if matches_current_classification is true",
  "suggested_metadata": {{
    "short_summary": "one plain sentence describing what the tool does",
    "metadata": ["Read-only", "Destructive", "Idempotent", "Open-world"]
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
                "content": "You produce strictly structured JSON for a defensive security research system.",
            },
            {"role": "user", "content": prompt},
        ],
    )

    content = response.choices[0].message.content
    if not content:
        raise RuntimeError("OpenAI returned an empty response.")
    return content, selected_model


def generate_with_ollama(
    prompt: str, model: Optional[str] = None, base_url: Optional[str] = None
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
                "think": False,
                "keep_alive": "10m",
                "options": {"temperature": 0, "num_predict": 4096},
            },
            timeout=(OLLAMA_CONNECT_TIMEOUT, OLLAMA_READ_TIMEOUT),
        )
    except requests.exceptions.ReadTimeout as exc:
        raise RuntimeError(
            f"Ollama model '{selected_model}' did not finish within {OLLAMA_READ_TIMEOUT}s. "
            "Try a smaller/faster model or check system memory."
        ) from exc
    except requests.exceptions.ConnectionError as exc:
        raise RuntimeError(f"Could not reach Ollama at {endpoint}. Make sure Ollama is running.") from exc

    response.raise_for_status()
    content = response.json().get("response")
    if not content:
        raise RuntimeError("Ollama returned an empty response.")
    return content, selected_model


def parse_llm_json(raw: str) -> Any:
    """Parse an LLM JSON reply, tolerating markdown code fences."""
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
    prompt_override: Optional[str] = None,
) -> dict:
    """Load ontology + lexicon, build prompt, call backend, parse JSON reply."""
    capabilities, warnings = load_capability_lexicon(lexicon_dir)
    lexicon_text = format_lexicon_reference(capabilities)
    ontology_text = format_ontology_reference(ONTOLOGY)

    prompt = prompt_override or build_tool_description_prompt(
        tool, ontology_text, lexicon_text, source=source
    )

    try:
        if backend == "ollama":
            raw, selected_model = generate_with_ollama(prompt, model=model, base_url=base_url)
        elif backend == "openai":
            raw, selected_model = generate_with_openai(prompt, model=model)
        else:
            return {"error": f"Unknown backend: {backend!r}", "lexicon_warnings": warnings, "_prompt_used": prompt}
    except Exception as error:
        return {"error": str(error), "lexicon_warnings": warnings, "_prompt_used": prompt}

    try:
        parsed = parse_llm_json(raw)
    except json.JSONDecodeError as error:
        return {
            "error": f"{backend} did not return valid JSON. Showing the raw response instead. Parse error: {error}",
            "raw": raw,
            "model": selected_model,
            "lexicon_warnings": warnings,
            "_prompt_used": prompt,
        }

    parsed["_model"] = selected_model
    parsed["_backend"] = backend
    parsed["lexicon_warnings"] = warnings
    parsed["_prompt_used"] = prompt
    return parsed


# ============================================================
# STREAMLIT UI
# ============================================================

import streamlit as st


def _tool_label(tool: dict) -> str:
    return tool.get("tool") or tool.get("tool_name") or "unknown_tool"


def _render_tool_details(tool: dict) -> None:
    st.markdown("**Declared name & description**")
    st.write(_tool_label(tool))
    st.caption(tool.get("description") or "No description provided.")

    st.markdown("**Current classification (Module 3, unchanged by this tab)**")
    st.caption(describe_current_classification(tool))

    other_keys = {k: v for k, v in tool.items() if k not in ("tool", "tool_name", "description", "mapping")}
    if other_keys:
        st.markdown("**Other fields on this tool**")
        st.json(other_keys)


def _render_ontology_reference() -> None:
    with st.expander("Capability ontology (C1-C6 boundaries)"):
        for cat in ONTOLOGY:
            st.markdown(f"**{cat['id']} - {cat['name']}**")
            st.caption(f"Included: {cat['inclusion']}")
            st.caption(f"Excluded: {cat['exclusion']}")


def render() -> None:
    st.header("AI Tool Description & Metadata Generator")
    st.caption(
        "Pick a tool, review what the pipeline already knows about it, then optionally "
        "ask an LLM to draft a corrected description and capability metadata grounded "
        "in the project's capability ontology and lexicon. Suggestions are for human "
        "review only and are never written back automatically."
    )

    analysis_result = st.session_state.get("analysis_result")
    if analysis_result is None:
        st.info("Run the security analysis in the Capability Risk Analyzer tab first, then come back here.")
        return

    all_tools = analysis_result.get("tools", [])
    if not all_tools:
        st.info("No analyzed tools found in the current session.")
        return

    tool_names = [_tool_label(t) for t in all_tools]
    selected_name = st.selectbox("Select a tool", tool_names, key="desc_gen_tool_select")
    tool = all_tools[tool_names.index(selected_name)]

    st.divider()
    _render_tool_details(tool)

    st.divider()
    _render_ontology_reference()

    st.divider()

    availability = describe_availability(tool)
    source = availability.get("source")

    if source:
        st.markdown("**Implementation source found**")
        st.caption(f"`{source.get('file')}` (match: {source.get('match_kind')}, line {source.get('line')}).")
        st.code(source.get("snippet", ""), language=source.get("language", "text"))
    else:
        st.warning(
            "No implementation source found in this project's src_server_code/ for "
            "this tool. The suggestion will be based only on the declared "
            "description, the ontology, and the lexicon."
        )
        st.caption(availability.get("message", ""))

    st.divider()
    st.markdown("**Model settings**")

    backend_choice = st.radio(
        "Generate with", ["Ollama (local)", "ChatGPT (OpenAI)"], key="desc_gen_backend", horizontal=True
    )
    backend = "ollama" if backend_choice.startswith("Ollama") else "openai"

    col_model, col_extra = st.columns(2)
    if backend == "ollama":
        with col_model:
            model = st.text_input("Ollama model", value=DEFAULT_OLLAMA_MODEL, key="desc_gen_ollama_model")
        with col_extra:
            base_url = st.text_input("Ollama base URL", value=DEFAULT_OLLAMA_URL, key="desc_gen_ollama_url")
    else:
        with col_model:
            model = st.text_input("OpenAI model", value=DEFAULT_OPENAI_MODEL, key="desc_gen_openai_model")
        base_url = None
        with col_extra:
            st.caption("Reads the API key from the OPENAI_API_KEY environment variable.")

    lexicon_dir = st.text_input(
        "Capability lexicon directory",
        value=DEFAULT_LEXICON_DIR,
        key="desc_gen_lexicon_dir",
        help="Folder containing the six C1-C6 capability rule JSON files.",
    )

    st.divider()

    result_key = f"desc_gen_result_{selected_name}"
    prompt_key = f"desc_gen_prompt_{selected_name}"

    if prompt_key in st.session_state:
        st.markdown("**Prompt to send (editable)**")
        st.text_area(
            "Prompt",
            value=st.session_state[prompt_key],
            height=420,
            key=f"desc_gen_prompt_editor_{selected_name}",
        )

    if st.button("Generate description + metadata with AI", key="desc_gen_button"):
        try:
            with st.spinner("Reading the ontology, lexicon, and generating a suggestion..."):
                capabilities, lexicon_warnings = load_capability_lexicon(lexicon_dir)
                lexicon_text = format_lexicon_reference(capabilities)
                ontology_text = format_ontology_reference(ONTOLOGY)

                prompt = st.session_state.get(
                    f"desc_gen_prompt_editor_{selected_name}",
                    build_tool_description_prompt(tool, ontology_text, lexicon_text, source=source),
                )
                st.session_state[prompt_key] = prompt

                st.session_state[result_key] = generate_tool_description(
                    tool, lexicon_dir, backend, model=model, base_url=base_url, source=source, prompt_override=prompt,
                )
        except Exception as error:
            st.session_state[result_key] = {"error": str(error)}

    stored = st.session_state.get(result_key)
    if not stored:
        return

    st.divider()
    st.markdown("**Suggestion — not applied**")
    st.caption(
        "Generated by an LLM reading the material above, for human review only. This "
        "does not change the lexical classification, the ontology, or the tool's "
        "declared metadata. Apply it yourself in the Edit Database tab if you agree with it."
    )

    for warning in stored.get("lexicon_warnings", []) or []:
        st.warning(warning)

    if stored.get("error"):
        st.error(stored["error"])
        if stored.get("raw"):
            st.code(stored["raw"])
        if stored.get("_prompt_used"):
            st.markdown("**Prompt Used**")
            st.code(stored["_prompt_used"], language="text")
        return

    st.write(f"Backend: `{stored.get('_backend', backend)}` · Model: `{stored.get('_model', 'unknown')}`")

    if stored.get("matches_current_classification") is False:
        st.warning("Suggests the current classification may be inaccurate.")
        suggested = stored.get("suggested_capabilities") or []
        if suggested:
            st.write("Suggested capabilities: " + ", ".join(suggested))
        else:
            st.write("Suggests none of the fixed capabilities fit this tool's real behavior.")
        if stored.get("capability_justification"):
            st.caption(stored["capability_justification"])
    else:
        st.success("Suggests the current classification matches the ontology/lexicon.")

    if stored.get("matches_current_description") is False:
        st.warning("Suggests the declared description may be inaccurate.")
        if stored.get("suggested_description"):
            st.text_area(
                "Suggested description",
                value=stored["suggested_description"],
                key=f"desc_gen_desc_{selected_name}",
            )
    else:
        st.success("Suggests the declared description matches the ontology/lexicon.")

    suggested_metadata = stored.get("suggested_metadata") or {}
    if suggested_metadata:
        st.markdown("**Suggested metadata**")
        st.json(suggested_metadata)

    if stored.get("notes"):
        st.caption(f"Notes: {stored['notes']}")

    if stored.get("_prompt_used"):
        st.markdown("**Prompt Used**")
        st.code(stored["_prompt_used"], language="text")


if __name__ == "__main__":
    render()