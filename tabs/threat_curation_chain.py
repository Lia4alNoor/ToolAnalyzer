"""AI Tool Description & Metadata Generator.

Replaces the previous Ontology & Description Suggestions (Ollama) tab,
which itself replaced the original Threat Curation Chain tab.

This tab lets a human pick one analyzed MCP tool, review everything the
pipeline currently knows about it, and - on request - ask an LLM
(Ollama, running locally, or OpenAI/ChatGPT) to draft a corrected
description and capability metadata for it.

The LLM is grounded only in:
- the tool's own declared name/description,
- its current Module 3 lexical classification,
- the project's fixed C1-C6 capability lexicon, read directly from the
  JSON rule files in capability_lexicon/ (not a paraphrase of them), and
- the tool's real implementation source, when one is found in this
  project's src_server_code/.

Hard rules, matching the rest of this project:
- The capability set is whatever is actually defined in the lexicon
  JSON files at the configured path - never invented. If a file is
  missing or malformed, that is surfaced as a warning, not papered over.
- The LLM's output is advisory only. Nothing on this tab writes to
  capability_lexicon/*.json, the ontology database, or a tool's declared
  metadata. To apply a suggestion, use the Edit Database tab yourself.
- This tab never re-runs or overrides the Module 3 lexical classifier.
  The measured pipeline results are unaffected by anything here.
- If a tool's source is not present in src_server_code/, this tab says
  so and asks the LLM to work from the declared description and lexicon
  alone - it never fabricates or reconstructs source code.
"""

import streamlit as st

from modules import tool_source_locator
from modules.modules import module10_tool_desc_generator as desc_gen


def _tool_label(tool):
    return tool.get("tool") or tool.get("tool_name") or "unknown_tool"


def _render_tool_details(tool):
    """Show everything the pipeline currently has on this tool."""

    st.markdown("**Declared name & description**")
    st.write(_tool_label(tool))
    st.caption(tool.get("description") or "No description provided.")

    st.markdown("**Current classification (Module 3, unchanged by this tab)**")
    st.caption(desc_gen.describe_current_classification(tool))

    other_keys = {
        key: value
        for key, value in tool.items()
        if key not in ("tool", "tool_name", "description", "mapping")
    }
    if other_keys:
        st.markdown("**Other fields on this tool**")
        st.json(other_keys)


def render():

    st.header("AI Tool Description & Metadata Generator")

    st.caption(
        "Pick a tool, review what the pipeline already knows about it, then "
        "optionally ask an LLM to draft a corrected description and "
        "capability metadata grounded in the project's fixed capability "
        "lexicon. Suggestions are for human review only and are never "
        "written back automatically."
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

    tool_names = [_tool_label(tool) for tool in all_tools]
    selected_name = st.selectbox("Select a tool", tool_names, key="desc_gen_tool_select")
    tool = all_tools[tool_names.index(selected_name)]

    st.divider()
    _render_tool_details(tool)
    st.divider()

    availability = tool_source_locator.describe_availability(tool)
    source = availability.get("source")

    if source:
        st.markdown("**Implementation source found**")
        st.caption(
            f"`{source.get('file')}` (match: {source.get('match_kind')}, "
            f"line {source.get('line')})."
        )
        st.code(source.get("snippet", ""), language=source.get("language", "text"))
    else:
        st.warning(
            "No implementation source found in this project's "
            "src_server_code/ for this tool. The suggestion will be based "
            "only on the declared description and the capability lexicon."
        )
        st.caption(availability.get("message", ""))

    st.divider()
    st.markdown("**Model settings**")

    backend_choice = st.radio(
        "Generate with",
        ["Ollama (local)", "ChatGPT (OpenAI)"],
        key="desc_gen_backend",
        horizontal=True,
    )
    backend = "ollama" if backend_choice.startswith("Ollama") else "openai"

    col_model, col_extra = st.columns(2)

    if backend == "ollama":
        with col_model:
            model = st.text_input(
                "Ollama model",
                value=desc_gen.DEFAULT_OLLAMA_MODEL,
                key="desc_gen_ollama_model",
            )
        with col_extra:
            base_url = st.text_input(
                "Ollama base URL",
                value=desc_gen.DEFAULT_OLLAMA_URL,
                key="desc_gen_ollama_url",
            )
    else:
        with col_model:
            model = st.text_input(
                "OpenAI model",
                value=desc_gen.DEFAULT_OPENAI_MODEL,
                key="desc_gen_openai_model",
            )
        base_url = None
        with col_extra:
            st.caption("Reads the API key from the OPENAI_API_KEY environment variable.")

    lexicon_dir = st.text_input(
        "Capability lexicon directory",
        value=desc_gen.DEFAULT_LEXICON_DIR,
        key="desc_gen_lexicon_dir",
        help="Folder containing the six C1-C6 capability rule JSON files.",
    )

    st.divider()

    result_key = f"desc_gen_result_{selected_name}"

    if st.button("Generate description + metadata with AI", key="desc_gen_button"):
        try:
            with st.spinner("Reading the capability lexicon and generating a suggestion..."):
                st.session_state[result_key] = desc_gen.generate_tool_description(
                    tool,
                    lexicon_dir,
                    backend,
                    model=model,
                    base_url=base_url,
                    source=source,
                )
        except Exception as error:
            st.session_state[result_key] = {"error": str(error)}

    stored = st.session_state.get(result_key)

    if not stored:
        return

    st.divider()
    st.markdown("**Suggestion — not applied**")
    st.caption(
        "Generated by an LLM reading the material above, for human review "
        "only. This does not change the lexical classification, the "
        "capability lexicon, or the tool's declared metadata. Apply it "
        "yourself in the Edit Database tab if you agree with it."
    )

    for warning in stored.get("lexicon_warnings", []) or []:
        st.warning(warning)

    if stored.get("error"):
        st.error(stored["error"])
        if stored.get("raw"):
            st.code(stored["raw"])
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
        st.success("Suggests the current classification matches the source/lexicon.")

    if stored.get("matches_current_description") is False:
        st.warning("Suggests the declared description may be inaccurate.")
        if stored.get("suggested_description"):
            st.text_area(
                "Suggested description",
                value=stored["suggested_description"],
                key=f"desc_gen_desc_{selected_name}",
            )
    else:
        st.success("Suggests the declared description matches the source/lexicon.")

    suggested_metadata = stored.get("suggested_metadata") or {}
    if suggested_metadata:
        st.markdown("**Suggested metadata**")
        st.json(suggested_metadata)

    if stored.get("notes"):
        st.caption(f"Notes: {stored['notes']}")