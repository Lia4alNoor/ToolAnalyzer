"""Ontology & Description Suggestions (Ollama).

Replaces the previous Threat Curation Chain tab.

For tools whose real implementation source is available in this project
(src_server_code/), this tab asks a local Ollama model to compare the
tool's DECLARED name/description and its CURRENT C1-C6 classification
against what the source code actually does, and to suggest a correction
if they disagree.

Hard rules, matching the rest of this project:
- The C1-C6 ontology is fixed. Ollama is given the six existing
  capabilities and must choose among them (or say "none fit"). It is
  never allowed to invent a new capability.
- Ollama's output is advisory only. It is displayed as a suggestion for
  a human to review. Nothing here writes to capability_lexicon/*.json,
  the ontology database, or the tool's declared metadata. To apply a
  suggestion, use the Edit Database tab yourself.
- This tab never re-runs or overrides the Module 3 lexical classifier.
  The measured pipeline results are unaffected by anything on this tab.
- If a tool's source is not present in this project's src_server_code/,
  this tab says so. It never fabricates or reconstructs source code.
"""

import json

import streamlit as st

from modules import tool_source_locator
from modules.modules import module_5_ontology_database, module_10


# ============================================================
# PROMPT CONSTRUCTION
# ============================================================

def _ontology_reference_text():
    """Render the fixed C1-C6 ontology as reference text for the prompt."""

    lines = []

    for cap_id, name, definition, example_risk in module_5_ontology_database.CAPABILITY_SEED:
        lines.append(f"{cap_id} - {name}: {definition} (Example risk: {example_risk})")

    return "\n".join(lines)


def _current_classification_text(tool):
    """Render the tool's current Module 3 classification for the prompt."""

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


def build_suggestion_prompt(tool, source):
    """Build the exact prompt sent to Ollama. Grounded only in real inputs."""

    tool_name = tool.get("tool") or tool.get("tool_name") or "unknown_tool"
    description = tool.get("description") or "No description provided."

    return f"""You are reviewing one MCP tool declaration against its real implementation
source code for a defensive security research project. You do not execute
any tool. You only compare declared text against source text already
provided to you below.

FIXED CAPABILITY ONTOLOGY (you may only choose from these six; if none
genuinely fit, say so explicitly instead of forcing a label):
{_ontology_reference_text()}

DECLARED TOOL NAME: {tool_name}

DECLARED DESCRIPTION:
{description}

CURRENT AUTOMATED CLASSIFICATION (produced by a separate lexical rule
engine, not by you):
{_current_classification_text(tool)}

REAL IMPLEMENTATION SOURCE (found in this project at {source.get('file')},
line {source.get('line')}, match kind: {source.get('match_kind')}):
```
{source.get('snippet', '')}
```

Task: decide whether the declared description and the current
classification are an accurate, complete account of what this source code
actually does. Respond with strictly valid JSON only, matching this exact
schema:

{{
  "matches_description": true or false,
  "matches_classification": true or false,
  "suggested_capabilities": ["C_" , ...] or [],
  "capability_justification": "one or two sentences citing specific lines/behavior in the source, or empty string if matches_classification is true",
  "suggested_description": "a corrected, accurate one-paragraph description, or empty string if matches_description is true",
  "notes": "anything else worth flagging for a human reviewer, or empty string"
}}

If no capability in the fixed ontology fits the source's real behavior,
return an empty list for suggested_capabilities and explain why in notes.
Do not invent a new capability ID. Do not include any text outside the
JSON object."""


# ============================================================
# OLLAMA CALL + PARSING
# ============================================================

def request_suggestion(tool, source, model, base_url):
    """Call Ollama and parse its JSON response. Never falls back silently."""

    prompt = build_suggestion_prompt(tool, source)

    raw, selected_model = module_10.generate_with_ollama(
        prompt,
        model=model,
        base_url=base_url,
    )

    try:
        parsed = module_10.parse_llm_json(raw)
    except json.JSONDecodeError as error:
        return {
            "error": (
                "Ollama did not return valid JSON. Showing the raw "
                f"response instead. Parse error: {error}"
            ),
            "raw": raw,
            "model": selected_model,
        }

    parsed["_model"] = selected_model
    return parsed


# ============================================================
# UI
# ============================================================

def render_tool_suggestion_panel(tool, model, base_url):
    """Render the per-tool source check + on-demand Ollama suggestion."""

    tool_name = tool.get("tool") or tool.get("tool_name") or "unknown_tool"

    availability = tool_source_locator.describe_availability(tool)
    source = availability.get("source")

    with st.expander(tool_name):

        st.caption(tool.get("description") or "No description provided.")

        st.markdown("**Current classification (Module 3, unchanged by this tab)**")
        st.caption(_current_classification_text(tool))

        st.divider()

        if not source:
            st.warning(
                "No suggestion available: implementation source was not "
                "found in this project's src_server_code/."
            )
            st.caption(availability.get("message", ""))
            return

        st.markdown("**Implementation source found**")
        st.caption(
            f"`{source.get('file')}` (match: {source.get('match_kind')}, "
            f"line {source.get('line')})."
        )
        st.code(source.get("snippet", ""), language=source.get("language", "text"))

        result_key = f"ollama_suggestion_{tool_name}"

        if st.button("Get Ollama suggestion", key=f"ollama_button_{tool_name}"):

            try:
                with st.spinner("Reading source and generating a suggestion..."):
                    st.session_state[result_key] = request_suggestion(
                        tool, source, model, base_url
                    )
            except Exception as error:
                st.session_state[result_key] = {"error": str(error)}

        stored = st.session_state.get(result_key)

        if not stored:
            return

        st.divider()
        st.markdown("**Suggestion — not applied**")
        st.caption(
            "Generated by a local LLM reading the source above, for human "
            "review only. This does not change the lexical classification, "
            "the capability lexicon, or the ontology database. Apply it "
            "yourself in the Edit Database tab if you agree with it."
        )

        if stored.get("error"):
            st.error(stored["error"])
            if stored.get("raw"):
                st.code(stored["raw"])
            return

        st.write(f"Model: `{stored.get('_model', 'unknown')}`")

        if stored.get("matches_classification") is False:
            st.warning("Suggests the current classification may be inaccurate.")
            suggested = stored.get("suggested_capabilities") or []
            if suggested:
                st.write("Suggested capabilities: " + ", ".join(suggested))
            else:
                st.write("Suggests none of C1-C6 fit this tool's real behavior.")
            if stored.get("capability_justification"):
                st.caption(stored["capability_justification"])
        else:
            st.success("Suggests the current classification matches the source.")

        if stored.get("matches_description") is False:
            st.warning("Suggests the declared description may be inaccurate.")
            if stored.get("suggested_description"):
                st.text_area(
                    "Suggested description",
                    value=stored["suggested_description"],
                    key=f"ollama_desc_{tool_name}",
                )
        else:
            st.success("Suggests the declared description matches the source.")

        if stored.get("notes"):
            st.caption(f"Notes: {stored['notes']}")


def render():

    st.header("Ontology & Description Suggestions (Ollama)")

    st.caption(
        "For tools whose real implementation source is available in this "
        "project, ask a local Ollama model to compare the declared "
        "description and current C1-C6 classification against the actual "
        "source code, and suggest a correction if they disagree. The C1-C6 "
        "ontology stays fixed - Ollama can only choose among the existing "
        "six capabilities, or say none fit. Suggestions are for human "
        "review only and are never written back automatically."
    )

    analysis_result = st.session_state.get("analysis_result")

    if analysis_result is None:
        st.info(
            "Run the security analysis in the Capability Risk Analyzer tab "
            "first, then come back here."
        )
        return

    all_tools = analysis_result.get("tools", [])

    if not all_tools:
        st.info("No analyzed tools found in the current session.")
        return

    col_model, col_url = st.columns(2)

    with col_model:
        model = st.text_input(
            "Ollama model",
            value=module_10.DEFAULT_OLLAMA_MODEL,
            key="suggestion_ollama_model",
        )

    with col_url:
        base_url = st.text_input(
            "Ollama base URL",
            value=module_10.DEFAULT_OLLAMA_URL,
            key="suggestion_ollama_url",
        )

    st.divider()

    for tool in all_tools:
        render_tool_suggestion_panel(tool, model, base_url)
