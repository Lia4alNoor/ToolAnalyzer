"""
Test 4 - AI Tool Description and Metadata Generator
Reprocessing harness for test_4_generator_12.json

Purpose
-------
Evaluate what Module 10 produces when the published tool description and
annotation hints are withheld.

The generator receives:
    - tool name
    - argument schema
    - real implementation source, when available
    - capability ontology
    - capability lexicon

The published description and published annotation hints are retained only
as reference values for comparison.

The output JSON stores only:
    - tool name
    - arguments
    - ingested implementation source code
    - published/reference description, classification and metadata
    - generated description, classification and metadata
    - generation status
"""

from datetime import datetime, timezone
from pathlib import Path
import importlib.util
import json
import sys
import traceback


# ============================================================
# PATHS
# ============================================================

PROJECT_ROOT = Path(
    r"C:\Users\amal4\PycharmProjects\ToolAssist"
)

GENERATOR_FILE = (
    PROJECT_ROOT
    / "tabs"
    / "LLM_powered_tool_decri.py"
)

SOURCE_LOCATOR_FILE = (
    PROJECT_ROOT
    / "modules"
    / "tool_source_locator.py"
)

INPUT_FILE = (
    PROJECT_ROOT
    / "data"
    / "test_4_generator_12.json"
)

OUTPUT_FILE = (
    PROJECT_ROOT
    / "data"
    / "test_4_generator_12_reprocessed.json"
)

LEXICON_DIR = (
    PROJECT_ROOT
    / "capability_lexicon"
)


# ============================================================
# RUN SETTINGS
# ============================================================

BACKEND = "ollama"

# Information deliberately withheld from Module 10.
BLANK_DESCRIPTION = True
STRIP_HINTS = True

# Maximum implementation source supplied/stored.
MAX_SOURCE_CHARS = 20000


# ============================================================
# ANNOTATION / HINT KEYS
# ============================================================

HINT_KEYS = (
    "readOnlyHint",
    "destructiveHint",
    "idempotentHint",
    "openWorldHint",
    "read_only_hint",
    "destructive_hint",
    "idempotent_hint",
    "open_world_hint",
    "annotations",
    "hints",
)


# ============================================================
# SOURCE RECORD KEYS
# ============================================================

SOURCE_CODE_KEYS = (
    "code",
    "source",
    "source_code",
    "snippet",
    "body",
    "text",
    "content",
)

SOURCE_PATH_KEYS = (
    "path",
    "file",
    "file_path",
    "filepath",
    "source_file",
    "location",
    "url",
)


# ============================================================
# LOAD PYTHON MODULE FROM FILE
# ============================================================

def load_module(path, module_name):
    """Load a Python module directly from a file."""

    if not path.exists():
        raise FileNotFoundError(
            f"Module not found: {path}"
        )

    spec = importlib.util.spec_from_file_location(
        module_name,
        path,
    )

    if spec is None or spec.loader is None:
        raise RuntimeError(
            f"Could not load module: {path}"
        )

    module = importlib.util.module_from_spec(spec)

    sys.modules[module_name] = module

    spec.loader.exec_module(module)

    return module


# ============================================================
# LOAD INPUT
# ============================================================

def load_input_file(path):
    """
    Load the test input.

    Supports:
        - list of tool records
        - {"records": [...]}
        - {"tools": [...]}
        - {"results": [...]}
        - single tool object
    """

    if not path.exists():
        raise FileNotFoundError(
            f"Input file not found: {path}"
        )

    with path.open(
        "r",
        encoding="utf-8",
    ) as f:
        data = json.load(f)

    if isinstance(data, list):
        return data

    if isinstance(data, dict):

        for key in (
            "records",
            "tools",
            "results",
        ):
            if isinstance(data.get(key), list):
                return data[key]

        if any(
            key in data
            for key in (
                "name",
                "tool",
                "tool_name",
                "toolName",
            )
        ):
            return [data]

    raise ValueError(
        "Could not find a list of tools/records in the input JSON."
    )


# ============================================================
# NORMALIZATION HELPERS
# ============================================================

def extract_name(tool):
    """Extract the MCP tool name."""

    name = (
        tool.get("tool")
        or tool.get("tool_name")
        or tool.get("toolName")
        or tool.get("name")
    )

    if name:
        return str(name).strip()

    return "Unnamed tool"


def extract_description(tool):
    """
    Extract the original published description.

    This is retained only as reference data and is not passed
    to Module 10.
    """

    description = (
        tool.get("description")
        or tool.get("declared_description")
    )

    if description:
        return str(description)

    evaluation = tool.get("evaluation")

    if isinstance(evaluation, dict):

        description = evaluation.get(
            "published_description",
            "",
        )

        if description:
            return str(description)

    test_input = tool.get("_test_input")

    if isinstance(test_input, dict):

        return str(
            test_input.get(
                "description",
                "",
            )
        )

    return ""


def extract_published_hints(tool):
    """
    Extract the original published annotation metadata.

    These values are retained only for comparison.
    """

    found = {}

    evaluation = tool.get("evaluation")

    if isinstance(evaluation, dict):

        mapping = {
            "published_readOnlyHint": "readOnlyHint",
            "published_destructiveHint": "destructiveHint",
            "published_idempotentHint": "idempotentHint",
            "published_openWorldHint": "openWorldHint",
            "published_read_only_hint": "read_only_hint",
            "published_destructive_hint": "destructive_hint",
            "published_idempotent_hint": "idempotent_hint",
            "published_open_world_hint": "open_world_hint",
        }

        for source_key, output_key in mapping.items():

            if source_key in evaluation:

                found[output_key] = (
                    evaluation[source_key]
                )

    containers = [tool]

    test_input = tool.get("_test_input")

    if isinstance(test_input, dict):
        containers.append(test_input)

    for container in containers:

        for key in HINT_KEYS:

            if key in container:

                found.setdefault(
                    key,
                    container[key],
                )

    return found


def extract_published_classification(tool):
    """
    Extract the original published/hand-labelled capability
    classification for reference.

    This is never passed to Module 10.
    """

    evaluation = tool.get("evaluation")

    if isinstance(evaluation, dict):

        for key in (
            "hand_labelled_capabilities",
            "hand_labeled_capabilities",
            "published_capabilities",
            "capabilities",
        ):

            value = evaluation.get(key)

            if value is not None:
                return value

    for key in (
        "hand_labelled_capabilities",
        "hand_labeled_capabilities",
        "published_capabilities",
        "capabilities",
    ):

        value = tool.get(key)

        if value is not None:
            return value

    return []


def extract_arguments(tool):
    """
    Extract only the argument/input schema.
    """

    for key in (
        "input_schema",
        "inputSchema",
        "arguments",
        "parameters",
        "signature",
    ):

        value = tool.get(key)

        if value is not None:
            return value

    test_input = tool.get("_test_input")

    if isinstance(test_input, dict):

        for key in (
            "input_schema",
            "inputSchema",
            "arguments",
            "parameters",
            "signature",
        ):

            value = test_input.get(key)

            if value is not None:
                return value

        excluded = set(HINT_KEYS) | {
            "description",
            "declared_description",
            "name",
            "tool",
            "tool_name",
            "toolName",
        }

        filtered = {
            key: value
            for key, value in test_input.items()
            if key not in excluded
        }

        if filtered:
            return filtered

    if (
        test_input is not None
        and not isinstance(test_input, dict)
    ):
        return test_input

    return {}


def normalize_tool(
    tool,
    arguments,
):
    """
    Build the exact minimal tool record handed to Module 10.

    Only intended generator evidence is retained:
        - tool name
        - argument schema
        - blank description

    Published descriptions, hints, classifications,
    evaluation labels, provenance and source identifiers
    are excluded.
    """

    name = extract_name(tool)

    normalized = {
        "tool": name,
        "tool_name": name,
        "arguments": arguments,
        "description": "",
    }

    return normalized, name


# ============================================================
# IMPLEMENTATION SOURCE
# ============================================================

def read_code_from_path(raw_path):
    """
    Read an implementation file.

    Supports:
        C:\\project\\file.py
        C:\\project\\file.py:120
        relative/path/file.py
    """

    candidates = [
        str(raw_path)
    ]

    text = str(raw_path)

    # Remove trailing :line or :line:column while preserving
    # the Windows drive-letter colon.
    parts = text.rsplit(
        ":",
        1,
    )

    if (
        len(parts) == 2
        and parts[1].strip().isdigit()
    ):
        candidates.append(
            parts[0]
        )

    for candidate in candidates:

        path = Path(candidate)

        if not path.is_absolute():
            path = PROJECT_ROOT / path

        try:

            if path.is_file():

                return (
                    path.read_text(
                        encoding="utf-8",
                        errors="replace",
                    ),
                    str(path),
                    None,
                )

        except Exception as error:

            return (
                None,
                str(path),
                f"{type(error).__name__}: {error}",
            )

    return (
        None,
        None,
        "path did not resolve to a readable file",
    )


def capture_implementation_source(
    located_source,
):
    """
    Extract implementation source code from the source locator.

    Only the actual ingested code is retained for the final JSON.
    """

    if located_source is None:

        return None

    code = None
    path = None

    # --------------------------------------------------------
    # LOCATOR RETURNED DICT
    # --------------------------------------------------------

    if isinstance(
        located_source,
        dict,
    ):

        for key in SOURCE_CODE_KEYS:

            value = located_source.get(key)

            if (
                isinstance(value, str)
                and value.strip()
            ):
                code = value
                break

        for key in SOURCE_PATH_KEYS:

            value = located_source.get(key)

            if (
                isinstance(value, str)
                and value.strip()
            ):
                path = value
                break

        # If only a path was returned, read the source file.
        if (
            code is None
            and path is not None
        ):

            (
                code,
                resolved_path,
                _,
            ) = read_code_from_path(path)

            if resolved_path:
                path = resolved_path

    # --------------------------------------------------------
    # LOCATOR RETURNED STRING
    # --------------------------------------------------------

    elif isinstance(
        located_source,
        str,
    ):

        if (
            "\n" in located_source
            and len(located_source) > 200
        ):
            code = located_source

        else:

            (
                code,
                resolved_path,
                _,
            ) = read_code_from_path(
                located_source
            )

            path = (
                resolved_path
                or located_source
            )

    # --------------------------------------------------------
    # STORE ONLY CODE AND PATH
    # --------------------------------------------------------

    if (
        not isinstance(code, str)
        or not code.strip()
    ):
        return None

    if len(code) > MAX_SOURCE_CHARS:

        code = code[:MAX_SOURCE_CHARS]

    return {
        "path": path,
        "code": code,
    }


# ============================================================
# BUILD SOURCE EVIDENCE FOR MODULE 10
# ============================================================

def build_generator_source(
    implementation_source,
):
    """
    Convert captured implementation source into the structure
    expected by Module 10.
    """

    if not implementation_source:
        return None

    path = implementation_source.get(
        "path"
    )

    return {
        "file": path,
        "line": None,
        "match_kind": "tool-source-locator",
        "snippet": implementation_source.get(
            "code",
            "",
        ),
        "language": (
            Path(path).suffix.lstrip(".")
            if path
            else "text"
        ),
    }


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "Test 4 generator reprocessing is running...",
        flush=True,
    )

    # ========================================================
    # LOAD REAL GENERATOR
    # ========================================================

    generator = load_module(
        GENERATOR_FILE,
        "real_generator_chain",
    )

    required_generator_functions = [
        "load_capability_lexicon",
        "format_lexicon_reference",
        "format_ontology_reference",
        "build_tool_description_prompt",
        "generate_tool_description",
    ]

    missing = [
        name
        for name in required_generator_functions
        if not hasattr(generator, name)
    ]

    if missing:

        raise RuntimeError(
            "The generator is missing required functions: "
            + ", ".join(missing)
        )

    # ========================================================
    # LOAD REAL SOURCE LOCATOR
    # ========================================================

    source_locator = load_module(
        SOURCE_LOCATOR_FILE,
        "real_tool_source_locator",
    )

    if not hasattr(
        source_locator,
        "find_tool_source",
    ):

        raise RuntimeError(
            "tool_source_locator.py does not contain "
            "find_tool_source()."
        )

    # ========================================================
    # LOAD REAL ONTOLOGY
    # ========================================================

    if not hasattr(
        generator,
        "ONTOLOGY",
    ):

        raise RuntimeError(
            "The real generator does not expose ONTOLOGY."
        )

    ontology_text = (
        generator.format_ontology_reference(
            generator.ONTOLOGY
        )
    )

    # ========================================================
    # LOAD REAL LEXICON
    # ========================================================

    (
        capabilities,
        lexicon_warnings,
    ) = generator.load_capability_lexicon(
        str(LEXICON_DIR)
    )

    lexicon_text = (
        generator.format_lexicon_reference(
            capabilities
        )
    )

    # ========================================================
    # LOAD TEST DATA
    # ========================================================

    tools = load_input_file(
        INPUT_FILE
    )

    results = []

    # ========================================================
    # PROCESS EACH TOOL
    # ========================================================

    for index, original_tool in enumerate(
        tools,
        start=1,
    ):

        print(
            f"Processing tool {index}/{len(tools)}...",
            flush=True,
        )

        # ----------------------------------------------------
        # REFERENCE DATA
        # ----------------------------------------------------

        published_description = (
            extract_description(
                original_tool
            )
        )

        published_hints = (
            extract_published_hints(
                original_tool
            )
        )

        published_classification = (
            extract_published_classification(
                original_tool
            )
        )

        arguments = extract_arguments(
            original_tool
        )

        # ----------------------------------------------------
        # MINIMAL GENERATOR INPUT
        # ----------------------------------------------------

        tool, name = normalize_tool(
            original_tool,
            arguments,
        )

        # ====================================================
        # FIND IMPLEMENTATION SOURCE
        # ====================================================

        located_source = None

        try:

            located_source = (
                source_locator.find_tool_source(
                    name
                )
            )

        except Exception:
            located_source = None

        implementation_source = (
            capture_implementation_source(
                located_source
            )
        )

        generator_source = (
            build_generator_source(
                implementation_source
            )
        )

        # ====================================================
        # BUILD MODULE 10 PROMPT
        # ====================================================

        try:

            prompt = (
                generator.build_tool_description_prompt(
                    tool,
                    ontology_text,
                    lexicon_text,
                    source=generator_source,
                )
            )

        except Exception as error:

            results.append(
                {
                    "test_case": index,
                    "tool": name,

                    "input": {
                        "arguments": arguments,
                        "implementation_source": (
                            implementation_source.get(
                                "code"
                            )
                            if implementation_source
                            else None
                        ),
                    },

                    "reference": {
                        "description": (
                            published_description
                        ),
                        "classification": (
                            published_classification
                        ),
                        "metadata": (
                            published_hints
                        ),
                    },

                    "output": {
                        "error": (
                            f"{type(error).__name__}: "
                            f"{error}"
                        )
                    },

                    "status": "error",
                }
            )

            continue

        # ====================================================
        # RUN REAL MODULE 10
        # ====================================================

        try:

            output = (
                generator.generate_tool_description(
                    tool=tool,
                    lexicon_dir=str(
                        LEXICON_DIR
                    ),
                    backend=BACKEND,
                    source=generator_source,
                    prompt_override=prompt,
                )
            )

            status = "success"

        except Exception as error:

            output = {
                "error": (
                    f"{type(error).__name__}: "
                    f"{error}"
                ),
                "traceback": (
                    traceback.format_exc()
                ),
            }

            status = "error"

        # ====================================================
        # SAVE CLEAN RESULT
        # ====================================================

        results.append(
            {
                "test_case": index,

                "tool": name,

                # ------------------------------------------------
                # INPUT / EVIDENCE GIVEN TO GENERATOR
                # ------------------------------------------------

                "input": {
                    "arguments": arguments,

                    "implementation_source": (
                        implementation_source.get(
                            "code"
                        )
                        if implementation_source
                        else None
                    ),
                },

                # ------------------------------------------------
                # ORIGINAL PUBLISHED DATA
                # ------------------------------------------------

                "reference": {
                    "description": (
                        published_description
                    ),

                    "classification": (
                        published_classification
                    ),

                    "metadata": (
                        published_hints
                    ),
                },

                # ------------------------------------------------
                # MODULE 10 OUTPUT
                # ------------------------------------------------

                "output": output,

                "status": status,
            }
        )

    # ========================================================
    # SAVE CLEAN JSON
    # ========================================================

    output_data = {
        "run_timestamp_utc": (
            datetime.now(
                timezone.utc
            ).isoformat()
        ),

        "test": "Test 4 - Implementation-Grounded "
                "Metadata Reconstruction",

        "generator": str(
            GENERATOR_FILE
        ),

        "backend": BACKEND,

        "settings": {
            "published_description_withheld": (
                BLANK_DESCRIPTION
            ),

            "published_hints_withheld": (
                STRIP_HINTS
            ),
        },

        "results": results,
    }

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with OUTPUT_FILE.open(
        "w",
        encoding="utf-8",
    ) as f:

        json.dump(
            output_data,
            f,
            indent=2,
            ensure_ascii=False,
        )

    print(
        f"Test 4 completed. Results saved to: {OUTPUT_FILE}",
        flush=True,
    )


if __name__ == "__main__":
    main()