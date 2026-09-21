"""
Module 1: Server Selection / Discovery

Supports two input modes:

1. JSON file input
   - Reads an existing MCP tool JSON file.
   - Normalizes the tools for the downstream pipeline.

2. MCP server probing
   - Discovers publicly advertised remote MCP servers from the MCP Registry.
   - Attempts passive MCP connections.
   - Retrieves only tools/list metadata.
   - Does NOT execute MCP tools.
   - Displays server probing results.
   - Converts successfully retrieved tools into the normalized pipeline format.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from modules import collector


# ============================================================
# CONFIGURATION
# ============================================================

DEFAULT_PROBE_LIMIT = 20


# ============================================================
# MAIN ENTRY POINT
# ============================================================

def run(input_file: str):
    """
    Main entry point for Module 1 when using a JSON input file.

    Args:
        input_file: Path to JSON file containing tools.

    Returns:
        dict containing normalized tools and metadata.
    """

    print("=" * 70)
    print("Module 1: Server Selection / Discovery")
    print("=" * 70)

    result = process(input_file)
    return result


# ============================================================
# JSON INPUT
# ============================================================

def process(input_file: str) -> dict[str, Any]:
    """
    Read and normalize tools from a JSON file.

    Supported formats:

    1. Normalized MCP tool JSON
    2. MCPTox pure_tool.json
    3. Module 1 MCP collector output
    """

    try:

        with open(
            input_file,
            "r",
            encoding="utf-8",
        ) as f:

            data = json.load(f)

        # ----------------------------------------------------
        # Collector corpus format
        # ----------------------------------------------------

        if isinstance(data, dict) and "servers" in data:

            tools = flatten_collector_corpus(data)

            print(
                f"\nLoaded MCP collector corpus from: "
                f"{input_file}"
            )

            print(
                f"Servers found in corpus: "
                f"{len(data.get('servers', []))}"
            )

            print(
                f"Tools found: {len(tools)}\n"
            )

        else:

            tools = data

            print(
                f"\nLoaded tools from: {input_file}"
            )

            print(
                f"Total tools found: "
                f"{len(tools) if isinstance(tools, list) else 0}\n"
            )

        tools = normalize_tools(tools)

        display_tools(tools)

        return {
            "tools": tools,
            "tool_count": len(tools),
            "source_file": str(input_file),
            "input_mode": "json",
        }

    except FileNotFoundError:

        raise FileNotFoundError(
            f"Input file not found: {input_file}"
        )

    except json.JSONDecodeError:

        raise ValueError(
            f"Invalid JSON file: {input_file}"
        )

    except Exception as e:

        raise Exception(
            f"Error processing input file: {str(e)}"
        )


# ============================================================
# MCP SERVER PROBING
# ============================================================

def probe_mcp_servers(
    limit: int = DEFAULT_PROBE_LIMIT,
) -> dict[str, Any]:
    """
    Discover and passively probe MCP servers from the MCP Registry.

    The collector performs:

        Registry discovery
        ->
        MCP initialization
        ->
        tools/list
        ->
        metadata collection

    No MCP tool is executed.
    """

    print("=" * 70)
    print("Module 1: MCP Server Discovery / Probing")
    print("=" * 70)

    print(
        f"\n[*] Discovering up to {limit} MCP servers..."
    )

    servers = collector.discover_registry_servers(
        limit=limit
    )

    results = []

    for index, server in enumerate(
        servers,
        start=1,
    ):

        server_name = collector.server_name(
            server
        )

        print(
            f"\n[{index}/{len(servers)}] "
            f"Probing: {server_name}"
        )

        try:

            result = asyncio.run(
                collector.collect_server(
                    server
                )
            )

        except RuntimeError:
            """
            Handles environments where an asyncio event
            loop is already running.
            """

            result = _run_async_in_existing_loop(
                collector.collect_server(
                    server
                )
            )

        results.append(result)

    summary = collector.aggregate(
        results
    )

    corpus = {
        "corpus_version": "module1-probed",
        "source": {
            "name": "MCP Registry",
            "url": collector.REGISTRY_URL,
        },
        "collection_method": {
            "operation": "MCP tools/list",
            "tool_execution": False,
            "authentication_bypass": False,
            "source_code_analysis": False,
        },
        "summary": summary,
        "servers": results,
    }

    return corpus


def _run_async_in_existing_loop(coro):
    """
    Fallback for environments where an asyncio event loop
    already exists.
    """

    import threading

    result_container = []
    error_container = []

    def runner():

        try:

            result_container.append(
                asyncio.run(coro)
            )

        except Exception as exc:

            error_container.append(exc)

    thread = threading.Thread(
        target=runner
    )

    thread.start()
    thread.join()

    if error_container:

        raise error_container[0]

    return result_container[0]


# ============================================================
# SAVE PROBED MCP DATA
# ============================================================

def save_probe_results(
    corpus: dict[str, Any],
    output_file: str | Path,
) -> dict[str, Any]:
    """
    Save the complete MCP probing corpus.

    Returns the normalized Module 1 result as well.
    """

    output_file = Path(
        output_file
    )

    output_file.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output_file.open(
        "w",
        encoding="utf-8",
    ) as f:

        json.dump(
            corpus,
            f,
            indent=2,
            ensure_ascii=False,
        )

    tools = flatten_collector_corpus(
        corpus
    )

    tools = normalize_tools(
        tools
    )

    return {
        "tools": tools,
        "tool_count": len(tools),
        "source_file": str(output_file),
        "input_mode": "mcp_probe",
        "servers": corpus.get(
            "servers",
            [],
        ),
        "summary": corpus.get(
            "summary",
            {},
        ),
    }


# ============================================================
# COLLECTOR CORPUS -> PIPELINE FORMAT
# ============================================================

def flatten_collector_corpus(
    corpus: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Convert collector.py server/tool records into the
    normalized input expected by the downstream pipeline.

    Collector format:

        server
            -> tools
                -> tool_name
                -> desc
                -> metadata

    Module 1 format:

        tool
        description
        readOnlyHint
        destructiveHint
        idempotentHint
        openWorldHint
        input_schema
        source
    """

    flattened = []

    servers = corpus.get(
        "servers",
        [],
    )

    for server in servers:

        server_name = server.get(
            "server_name",
            "unknown_server",
        )

        endpoint = server.get(
            "endpoint"
        )

        connection_status = server.get(
            "connection_status"
        )

        for tool_record in server.get(
            "tools",
            [],
        ):

            metadata = (
                tool_record.get(
                    "metadata"
                )
                or {}
            )

            flattened.append(
                {
                    "tool": (
                        metadata.get(
                            "tool"
                        )
                        or tool_record.get(
                            "tool_name"
                        )
                    ),

                    "description": (
                        metadata.get(
                            "description"
                        )
                        or tool_record.get(
                            "desc"
                        )
                    ),

                    "readOnlyHint": metadata.get(
                        "readOnlyHint"
                    ),

                    "destructiveHint": metadata.get(
                        "destructiveHint"
                    ),

                    "idempotentHint": metadata.get(
                        "idempotentHint"
                    ),

                    "openWorldHint": metadata.get(
                        "openWorldHint"
                    ),

                    "input_schema": metadata.get(
                        "input_schema"
                    ),

                    "source": (
                        f"MCP:"
                        f"{server_name}"
                    ),

                    "server_name": server_name,

                    "server_endpoint": endpoint,

                    "server_connection_status": (
                        connection_status
                    ),

                    "metadata_source": (
                        "declared_by_server"
                    ),
                }
            )

    return flattened


# ============================================================
# NORMALIZATION
# ============================================================

def normalize_tools(
    tools: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Normalize all supported tool formats.

    Supported formats:

    1. Normalized MCP format
    2. MCPTox pure_tool.json
    3. MCP collector flattened format
    """

    if not tools:

        return tools

    normalized_tools = []

    for tool in tools:

        # ----------------------------------------------------
        # Format 1:
        # Already normalized MCP format
        # ----------------------------------------------------

        if (
            "tool" in tool
            and "description" in tool
        ):

            normalized_tools.append(
                tool
            )

            continue

        # ----------------------------------------------------
        # Format 2:
        # MCPTox pure_tool.json
        # ----------------------------------------------------

        if (
            "tool_name" in tool
            and "tool_content" in tool
        ):

            normalized_tool = {
                "tool": tool.get(
                    "tool_name",
                    "N/A",
                ),

                "description": tool.get(
                    "tool_content",
                    "N/A",
                ),

                "readOnlyHint": None,
                "destructiveHint": None,
                "idempotentHint": None,
                "openWorldHint": None,

                "source": (
                    f"MCPTox:"
                    f"{tool.get('tool_address', 'N/A')}"
                ),
            }

            normalized_tools.append(
                normalized_tool
            )

            continue

        # ----------------------------------------------------
        # Unknown format
        # ----------------------------------------------------

        raise ValueError(
            "Unsupported tool format. Expected either "
            "normalized MCP format, MCPTox pure_tool format, "
            "or MCP collector format."
        )

    return normalized_tools


# ============================================================
# DISPLAY TOOLS
# ============================================================

def display_tools(
    tools: list[dict[str, Any]],
) -> None:
    """
    Display normalized tools.
    """

    if not tools:

        print(
            "No tools found."
        )

        return

    print(
        "-" * 90
    )

    print(
        f"{'Tool Name':<30} | "
        f"{'ReadOnly':<10} | "
        f"{'Destructive':<12} | "
        f"{'Source':<25}"
    )

    print(
        "-" * 90
    )

    for tool in tools:

        tool_name = tool.get(
            "tool",
            "N/A",
        )

        readonly = str(
            tool.get(
                "readOnlyHint",
                "N/A",
            )
        )

        destructive = str(
            tool.get(
                "destructiveHint",
                "N/A",
            )
        )

        source = tool.get(
            "source",
            "N/A",
        )

        print(
            f"{tool_name:<30} | "
            f"{readonly:<10} | "
            f"{destructive:<12} | "
            f"{source:<25}"
        )

    print(
        "-" * 90
    )

    print(
        "\n[DETAILED TOOL INFORMATION]\n"
    )

    for index, tool in enumerate(
        tools,
        1,
    ):

        print(
            f"{index}. "
            f"{tool.get('tool', 'Unknown')}"
        )

        print(
            f"   Description: "
            f"{tool.get('description', 'N/A')}"
        )

        print(
            f"   ReadOnly Hint: "
            f"{tool.get('readOnlyHint', 'N/A')}"
        )

        print(
            f"   Destructive Hint: "
            f"{tool.get('destructiveHint', 'N/A')}"
        )

        print(
            f"   Idempotent Hint: "
            f"{tool.get('idempotentHint', 'N/A')}"
        )

        print(
            f"   Open World Hint: "
            f"{tool.get('openWorldHint', 'N/A')}"
        )

        print(
            f"   Source: "
            f"{tool.get('source', 'N/A')}"
        )

        print()