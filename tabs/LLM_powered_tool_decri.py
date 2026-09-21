from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Optional, Tuple

import streamlit as st


MODULE_NAME = "Module 10: AI Tool Description & Metadata Generator"

DEFAULT_OPENAI_MODEL = "gpt-4o-mini"
DEFAULT_OLLAMA_MODEL = "qwen3:14b"
DEFAULT_OLLAMA_URL = "http://localhost:11434"

DEFAULT_LEXICON_DIR = (
    r"C:\Users\amal4\PycharmProjects\ToolAssist\capability_lexicon"
)

DEFAULT_PROMPT_FILE = (
    r"C:\Users\amal4\PycharmProjects\ToolAssist\tool_description_prompt.txt"
)

OLLAMA_CONNECT_TIMEOUT = 10
OLLAMA_READ_TIMEOUT = 300


ONTOLOGY = [
    {
        "id": "C1",
        "name": "External Data Ingestion",
        "inclusion": "Tools fetching public or untrusted external data into context, such as web scrapers, search, and social fetchers.",
        "exclusion": "Reading private or local user assets.",
    },
    {
        "id": "C2",
        "name": "Sensitive Data Access",
        "inclusion": "Tools reading local private files, credentials, health or financial records, personal logs, or private user data.",
        "exclusion": "Transmitting retrieved records across a network endpoint.",
    },
    {
        "id": "C3",
        "name": "External Communication",
        "inclusion": "Tools performing outbound network messaging, data transmission, emails, webhooks, or social posts.",
        "exclusion": "Modifying local files or local system state without network egress.",
    },
    {
        "id": "C4",
        "name": "State Modification",
        "inclusion": "Tools creating, modifying, appending to, or deleting local files, databases, or configuration state.",
        "exclusion": "Executing arbitrary OS terminal commands or dynamic scripts.",
    },
    {
        "id": "C5",
        "name": "System Execution",
        "inclusion": "Tools spawning OS shell commands, running Python or JavaScript scripts, binaries, or reverse shells.",
        "exclusion": "Actuating physical hardware or IoT devices.",
    },
    {
        "id": "C6",
        "name": "Physical Actuation",
        "inclusion": "Tools controlling physical hardware, IoT devices, smart home appliances, smart locks, or other actuators.",
        "exclusion": "Pure compute or digital OS execution without physical hardware actuation.",
    },
]


def format_ontology_reference(ontology: list) -> str:
    blocks = []

    for category in ontology:
        blocks.append(
            f"{category['id']} - {category['name']}\n"
            f"Included: {category['inclusion']}\n"
            f"Excluded: {category['exclusion']}"
        )

    return "\n\n".join(blocks)


def load_capability_lexicon(lexicon_dir: str) -> Tuple[list, list]:
    capabilities = []
    warnings = []

    directory = Path(lexicon_dir)

    if not directory.is_dir():
        warnings.append(
            f"Capability lexicon directory not found: {lexicon_dir}"
        )
        return capabilities, warnings

    json_files = sorted(directory.glob("*.json"))

    if not json_files:
        warnings.append(
            f"No .json files found in {lexicon_dir}"
        )
        return capabilities, warnings

    for path in json_files:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError) as error:
            warnings.append(
                f"Could not read {path.name}: {error}"
            )
            continue

        if "capability_id" not in data:
            warnings.append(
                f"{path.name} has no 'capability_id' field - skipped"
            )
            continue

        data["_source_file"] = str(path)
        capabilities.append(data)

    capabilities.sort(
        key=lambda capability: capability.get("capability_id", "")
    )

    return capabilities, warnings


def format_lexicon_reference(capabilities: list) -> str:
    if not capabilities:
        return "(No capability lexicon files were loaded.)"

    blocks = []

    for capability in capabilities:
        lines = [
            f"{capability.get('capability_id')} - "
            f"{capability.get('capability_name')}"
        ]

        if capability.get("notes"):
            lines.append(
                f"Notes: {capability['notes']}"
            )

        enabled_rules = [
            rule
            for rule in capability.get("rules", []) or []
            if rule.get("enabled", True)
        ]

        if enabled_rules:
            lines.append(
                "Regex signals used by the automated classifier:"
            )

            for rule in enabled_rules:
                lines.append(
                    "  - pattern {!r} ({} confidence): {}".format(
                        rule.get("pattern", ""),
                        rule.get("confidence", "?"),
                        rule.get("reason", ""),
                    )
                )
        else:
            lines.append(
                "(No enabled rules found for this capability.)"
            )

        blocks.append("\n".join(lines))

    return "\n\n".join(blocks)


def load_prompt_template(prompt_file: str) -> str:
    path = Path(prompt_file)

    if not path.is_file():
        raise FileNotFoundError(
            f"Prompt template not found: {prompt_file}"
        )

    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError as error:
        raise RuntimeError(
            f"Could not read prompt template: {error}"
        ) from error


def build_tool_description_prompt(
    code: str,
    ontology_text: str,
    lexicon_text: str,
    prompt_file: str,
) -> str:
    template = load_prompt_template(prompt_file)

    return (
        f"{template}\n\n"
        f"CAPABILITY ONTOLOGY\n"
        f"===================\n\n"
        f"{ontology_text}\n\n"
        f"CAPABILITY LEXICON\n"
        f"==================\n\n"
        f"{lexicon_text}\n\n"
        f"MCP TOOL IMPLEMENTATION CODE\n"
        f"============================\n\n"
        f"```python\n"
        f"{code}\n"
        f"```\n"
    )


def generate_with_openai(
    prompt: str,
    model: Optional[str] = None,
) -> Tuple[str, str]:
    try:
        from openai import OpenAI
    except ImportError as exc:
        raise RuntimeError(
            "Install openai: pip install openai"
        ) from exc

    api_key = os.getenv("OPENAI_API_KEY")

    if not api_key:
        raise RuntimeError(
            "OPENAI_API_KEY is not configured."
        )

    selected_model = (
        model
        or os.getenv("OPENAI_MODEL", DEFAULT_OPENAI_MODEL)
    )

    client = OpenAI(api_key=api_key)

    response = client.chat.completions.create(
        model=selected_model,
        temperature=0,
        response_format={"type": "json_object"},
        messages=[
            {
                "role": "system",
                "content": (
                    "You produce strictly structured JSON for a "
                    "defensive cybersecurity research system."
                ),
            },
            {
                "role": "user",
                "content": prompt,
            },
        ],
    )

    content = response.choices[0].message.content

    if not content:
        raise RuntimeError(
            "OpenAI returned an empty response."
        )

    return content, selected_model


def generate_with_ollama(
    prompt: str,
    model: Optional[str] = None,
    base_url: Optional[str] = None,
) -> Tuple[str, str]:
    import requests

    selected_model = (
        model
        or os.getenv("OLLAMA_MODEL", DEFAULT_OLLAMA_MODEL)
    )

    selected_url = (
        base_url
        or os.getenv("OLLAMA_BASE_URL", DEFAULT_OLLAMA_URL)
    )

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
                "options": {
                    "temperature": 0,
                    "num_predict": 4096,
                },
            },
            timeout=(
                OLLAMA_CONNECT_TIMEOUT,
                OLLAMA_READ_TIMEOUT,
            ),
        )
    except requests.exceptions.ReadTimeout as exc:
        raise RuntimeError(
            f"Ollama model '{selected_model}' did not finish within "
            f"{OLLAMA_READ_TIMEOUT}s. Try a smaller or faster model "
            "or check system memory."
        ) from exc
    except requests.exceptions.ConnectionError as exc:
        raise RuntimeError(
            f"Could not reach Ollama at {endpoint}. "
            "Make sure Ollama is running."
        ) from exc

    response.raise_for_status()

    content = response.json().get("response")

    if not content:
        raise RuntimeError(
            "Ollama returned an empty response."
        )

    return content, selected_model


def parse_llm_json(raw: str) -> Any:
    text = raw.strip()

    if text.startswith("```"):
        lines = text.splitlines()

        if lines and lines[0].startswith("```"):
            lines = lines[1:]

        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]

        text = "\n".join(lines).strip()

    return json.loads(text)


def generate_tool_description(
    code: str,
    lexicon_dir: str,
    backend: str,
    prompt_file: str,
    model: Optional[str] = None,
    base_url: Optional[str] = None,
) -> dict:
    capabilities, warnings = load_capability_lexicon(
        lexicon_dir
    )

    lexicon_text = format_lexicon_reference(
        capabilities
    )

    ontology_text = format_ontology_reference(
        ONTOLOGY
    )

    try:
        prompt = build_tool_description_prompt(
            code=code,
            ontology_text=ontology_text,
            lexicon_text=lexicon_text,
            prompt_file=prompt_file,
        )
    except Exception as error:
        return {
            "error": str(error),
            "lexicon_warnings": warnings,
        }

    try:
        if backend == "ollama":
            raw, selected_model = generate_with_ollama(
                prompt,
                model=model,
                base_url=base_url,
            )

        elif backend == "openai":
            raw, selected_model = generate_with_openai(
                prompt,
                model=model,
            )

        else:
            return {
                "error": f"Unknown backend: {backend!r}",
                "lexicon_warnings": warnings,
                "_prompt_used": prompt,
            }

    except Exception as error:
        return {
            "error": str(error),
            "lexicon_warnings": warnings,
            "_prompt_used": prompt,
        }

    try:
        parsed = parse_llm_json(raw)

    except json.JSONDecodeError as error:
        return {
            "error": (
                f"{backend} did not return valid JSON. "
                f"Parse error: {error}"
            ),
            "raw": raw,
            "model": selected_model,
            "lexicon_warnings": warnings,
            "_prompt_used": prompt,
        }

    if not isinstance(parsed, dict):
        return {
            "error": (
                "The LLM response was valid JSON but "
                "was not an object."
            ),
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


def render_ontology_used() -> None:
    st.markdown("### Ontology Used")

    for category in ONTOLOGY:
        with st.expander(
            f"{category['id']} — {category['name']}"
        ):
            st.markdown(
                f"**Included:** {category['inclusion']}"
            )

            st.markdown(
                f"**Excluded:** {category['exclusion']}"
            )

def render() -> None:
    st.header(
        "AI Tool Description & Metadata Generator"
    )

    st.caption(
        "Paste an MCP tool implementation below. The LLM analyses the "
        "code using the project's C1-C6 capability ontology and lexical "
        "rules, then produces editable suggestions for human review."
    )

    st.divider()

    st.markdown("### Tool Implementation Code")

    code = st.text_area(
        "Code",
        height=420,
        key="desc_gen_code_input",
        placeholder=(
            "Paste the MCP tool implementation code here..."
        ),
        label_visibility="collapsed",
    )

    st.divider()

    st.markdown("### Model Settings")

    backend_choice = st.radio(
        "Generate with",
        ["Ollama (local)", "ChatGPT (OpenAI)"],
        key="desc_gen_backend",
        horizontal=True,
    )

    backend = (
        "ollama"
        if backend_choice.startswith("Ollama")
        else "openai"
    )

    col_model, col_extra = st.columns(2)

    if backend == "ollama":
        with col_model:
            model = st.text_input(
                "Ollama model",
                value=DEFAULT_OLLAMA_MODEL,
                key="desc_gen_ollama_model",
            )

        with col_extra:
            base_url = st.text_input(
                "Ollama base URL",
                value=DEFAULT_OLLAMA_URL,
                key="desc_gen_ollama_url",
            )
    else:
        with col_model:
            model = st.text_input(
                "OpenAI model",
                value=DEFAULT_OPENAI_MODEL,
                key="desc_gen_openai_model",
            )

        base_url = None

        with col_extra:
            st.caption(
                "Reads the API key from the "
                "OPENAI_API_KEY environment variable."
            )

    lexicon_dir = st.text_input(
        "Capability lexicon directory",
        value=DEFAULT_LEXICON_DIR,
        key="desc_gen_lexicon_dir",
        help=(
            "Folder containing the C1-C6 capability rule JSON files."
        ),
    )

    prompt_file = st.text_input(
        "Prompt template file",
        value=DEFAULT_PROMPT_FILE,
        key="desc_gen_prompt_file",
        help=(
            "Text file containing the fixed LLM instructions."
        ),
    )

    st.divider()

    if st.button(
        "Create description using LLM",
        type="primary",
        key="desc_gen_button",
        use_container_width=True,
    ):
        if not code.strip():
            st.warning(
                "Please enter the MCP tool implementation code first."
            )
        else:
            with st.spinner(
                "Analysing the implementation and generating the description..."
            ):
                result = generate_tool_description(
                    code=code,
                    lexicon_dir=lexicon_dir,
                    backend=backend,
                    prompt_file=prompt_file,
                    model=model,
                    base_url=base_url,
                )

            st.session_state["desc_gen_result"] = result

    result = st.session_state.get("desc_gen_result")

    if not result:
        return

    st.divider()

    for warning in result.get(
        "lexicon_warnings",
        [],
    ) or []:
        st.warning(warning)

    if result.get("error"):
        st.error(result["error"])

        if result.get("raw"):
            st.markdown("### Raw LLM Response")

            st.code(
                result["raw"],
                language="text",
            )

        if result.get("_prompt_used"):
            with st.expander("Prompt Used"):
                st.code(
                    result["_prompt_used"],
                    language="text",
                )

        return

    st.markdown("### Generated Description")

    description = st.text_area(
        "Description",
        value=result.get(
            "suggested_description",
            "",
        ),
        height=160,
        key="desc_gen_editable_description",
    )

    st.markdown("### Generated Metadata")

    suggested_metadata = result.get(
        "suggested_metadata",
        {},
    )

    if not isinstance(suggested_metadata, dict):
        suggested_metadata = {}

    short_summary = st.text_input(
        "Short Summary",
        value=suggested_metadata.get(
            "short_summary",
            "",
        ),
        key="desc_gen_editable_summary",
    )

    metadata_options = [
        "Read-only",
        "Destructive",
        "Idempotent",
        "Open-world",
    ]

    selected_metadata = st.multiselect(
        "Metadata",
        options=metadata_options,
        default=[
            item
            for item in suggested_metadata.get(
                "metadata",
                [],
            )
            if item in metadata_options
        ],
        key="desc_gen_editable_metadata",
    )

    st.markdown("### Suggested Capabilities")

    capability_options = [
        category["id"]
        for category in ONTOLOGY
    ]

    selected_capabilities = st.multiselect(
        "Capabilities",
        options=capability_options,
        default=[
            capability
            for capability in result.get(
                "suggested_capabilities",
                [],
            )
            if capability in capability_options
        ],
        key="desc_gen_editable_capabilities",
    )

    capability_justification = st.text_area(
        "Capability Justification",
        value=result.get(
            "capability_justification",
            "",
        ),
        height=120,
        key="desc_gen_editable_justification",
    )

    notes = st.text_area(
        "Notes",
        value=result.get(
            "notes",
            "",
        ),
        height=120,
        key="desc_gen_editable_notes",
    )

    st.divider()

    if st.button(
        "Save Generated Result",
        type="primary",
        key="desc_gen_save_button",
        use_container_width=True,
    ):
        saved_result = dict(result)

        saved_result["suggested_description"] = description
        saved_result["suggested_capabilities"] = selected_capabilities
        saved_result["capability_justification"] = (
            capability_justification
        )

        saved_result["suggested_metadata"] = {
            "short_summary": short_summary,
            "metadata": selected_metadata,
        }

        saved_result["notes"] = notes

        st.session_state["desc_gen_result"] = saved_result
        st.session_state["desc_gen_saved_result"] = saved_result

        st.success(
            "Generated result saved successfully."
        )

    if st.session_state.get("desc_gen_saved_result"):
        st.caption(
            "The edited description, metadata, capabilities, and notes "
            "are saved in the current Streamlit session."
        )

    st.divider()

    render_ontology_used()

    st.divider()

    with st.expander("Prompt Used"):
        st.code(
            result.get("_prompt_used", ""),
            language="text",
        )

    st.caption(
        f"Backend: {result.get('_backend', backend)} · "
        f"Model: {result.get('_model', model)}"
    )