"""Locate a tool's implementation source in the supplied project files.

Scope and honesty rules
-----------------------
* Source code is only ever READ from files that already exist in this
  project (src_server_code/ by default). Nothing is generated, inferred,
  reconstructed, or guessed.
* MCP metadata retrieval does NOT return implementation code. If a tool's
  source is not present in the project files, this module reports that it
  is unavailable rather than producing a plausible-looking body.
* A match is a best-effort textual lookup of a tool registration/definition
  in server source. The caller must present it as "source found in this
  project file", never as "the code the live server is running".
"""
import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Directories that may contain vendored MCP server source code.
SOURCE_DIRS = [
    PROJECT_ROOT / "src_server_code",
]

SOURCE_SUFFIXES = (".py", ".ts", ".js", ".tsx", ".mjs")

UNAVAILABLE_MESSAGE = "Implementation source not available."

# How many lines of context to show around a match.
CONTEXT_BEFORE = 2
CONTEXT_AFTER = 60


def _candidate_files():
    files = []
    for directory in SOURCE_DIRS:
        if not directory.exists():
            continue
        for path in sorted(directory.rglob("*")):
            if path.is_file() and path.suffix in SOURCE_SUFFIXES:
                files.append(path)
    return files


def _name_variants(tool_name):
    """Return plausible spellings of the same declared tool name.

    Only mechanical case/separator variants of the *declared* name are used;
    no semantic guessing about what the tool might be called.
    """
    name = (tool_name or "").strip()
    if not name:
        return []

    variants = {name}
    variants.add(name.replace("-", "_"))
    variants.add(name.replace("_", "-"))

    # snake_case -> camelCase / PascalCase
    parts = re.split(r"[-_]+", name)
    if len(parts) > 1:
        variants.add(parts[0] + "".join(p.capitalize() for p in parts[1:]))
        variants.add("".join(p.capitalize() for p in parts))

    return [v for v in variants if v]


def _match_patterns(variant):
    """Patterns that indicate a definition/registration of this tool."""
    escaped = re.escape(variant)
    return [
        # "name": "tool" / name: "tool" / name = "tool"
        (r"[\"']name[\"']?\s*[:=]\s*[\"']{}[\"']".format(escaped),
         "tool registration (name field)"),
        # registerTool("tool", ...) / tool("tool", ...)
        (r"(registerTool|addTool|tool|setRequestHandler)\s*\(\s*[\"']{}[\"']".format(escaped),
         "tool registration call"),
        # Python: def tool(...) / TOOL = "tool"
        (r"^\s*(async\s+)?def\s+{}\s*\(".format(escaped),
         "function definition"),
        (r"^\s*(export\s+)?(async\s+)?function\s+{}\s*\(".format(escaped),
         "function definition"),
        (r"^\s*(export\s+)?const\s+{}\s*=".format(escaped),
         "exported handler"),
        # Enum/constant listing e.g. GitTools.STATUS = "git_status"
        (r"=\s*[\"']{}[\"']".format(escaped),
         "tool name constant"),
    ]


def find_tool_source(tool_name):
    """Find implementation source for one declared tool name.

    Returns:
        dict | None: None when nothing was found. Otherwise:
            {
              "available": True,
              "file": "src_server_code/git/server.py",
              "line": 214,
              "match_kind": "tool registration (name field)",
              "snippet": "...",
              "language": "python",
              "provenance": "project file",
            }
    """
    variants = _name_variants(tool_name)
    if not variants:
        return None

    for path in _candidate_files():
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        lines = text.splitlines()

        for variant in variants:
            for pattern, kind in _match_patterns(variant):
                match = re.search(pattern, text, re.MULTILINE)
                if not match:
                    continue

                line_number = text[: match.start()].count("\n") + 1
                start = max(0, line_number - 1 - CONTEXT_BEFORE)
                end = min(len(lines), line_number + CONTEXT_AFTER)

                return {
                    "available": True,
                    "file": str(path.relative_to(PROJECT_ROOT)),
                    "line": line_number,
                    "match_kind": kind,
                    "matched_name": variant,
                    "snippet": "\n".join(lines[start:end]),
                    "snippet_start_line": start + 1,
                    "language": "python" if path.suffix == ".py" else "typescript",
                    "provenance": "project file",
                    "truncated": end < len(lines),
                }

    return None


def describe_availability(tool):
    """Explain where implementation source could (not) be obtained.

    Args:
        tool (dict): Normalized tool record.

    Returns:
        dict: {"source": dict | None, "message": str}
    """
    tool_name = tool.get("tool") or tool.get("tool_name") or ""

    # A retriever/loader may already have attached real source text.
    embedded = tool.get("implementation_source")
    if isinstance(embedded, dict) and embedded.get("snippet"):
        return {"source": embedded, "message": ""}

    found = find_tool_source(tool_name)

    if found:
        return {"source": found, "message": ""}

    searched = ", ".join(
        str(d.relative_to(PROJECT_ROOT))
        for d in SOURCE_DIRS
        if d.exists()
    ) or "no source directories present"

    return {
        "source": None,
        "message": (
            "{} MCP metadata retrieval does not expose implementation code, "
            "and no matching source file was found in this project "
            "(searched: {}).".format(UNAVAILABLE_MESSAGE, searched)
        ),
    }
