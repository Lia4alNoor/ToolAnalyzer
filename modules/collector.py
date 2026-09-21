"""
MCP Passive Corpus Collector
============================

Purpose:
    Discover MCP servers from a supplied corpus/registry export,
    connect to publicly accessible remote MCP servers, retrieve
    tools/list, and save the observed tool metadata.

SAFETY:
    - Does NOT call MCP tools.
    - Does NOT execute arbitrary code.
    - Does NOT bypass authentication.
    - Does NOT attempt credential discovery.
    - Only performs MCP initialization + tools/list.
    - Public source-code inspection is optional and separate.

Output:
    output/S1_mcp_registry.json
    output/corpus.json
"""

from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests
from mcp import Client


# ============================================================
# CONFIGURATION
# ============================================================

OUTPUT_DIR = Path("output")

# Maximum number of servers to investigate in one run.
# Start small. Increase after the collector works.
MAX_SERVERS = 20

# Connection timeout in seconds.
CONNECTION_TIMEOUT = 15

# Registry API.
REGISTRY_URL = "https://registry.modelcontextprotocol.io/v0.1/servers"

# Optional search query.
# Leave as None to retrieve registry results without a search filter.
REGISTRY_SEARCH = None


# ============================================================
# BASIC HELPERS
# ============================================================

def safe_json(value: Any) -> Any:
    """
    Convert SDK/Pydantic objects into JSON-compatible values.
    """
    if value is None:
        return None

    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")

    if hasattr(value, "dict"):
        return value.dict()

    if isinstance(value, dict):
        return {
            str(k): safe_json(v)
            for k, v in value.items()
        }

    if isinstance(value, list):
        return [safe_json(v) for v in value]

    if isinstance(value, tuple):
        return [safe_json(v) for v in value]

    if isinstance(value, (str, int, float, bool)):
        return value

    return str(value)


def annotation_value(annotations: Any, name: str) -> Any:
    """
    Safely obtain a ToolAnnotations field.

    Different MCP SDK/server versions may expose annotations
    slightly differently, so this deliberately avoids assuming
    one internal representation.
    """

    if annotations is None:
        return None

    if isinstance(annotations, dict):
        return annotations.get(name)

    return getattr(annotations, name, None)


def count_metadata(tool: Any) -> int:
    """
    Count metadata fields actually exposed by the live MCP server.

    Minimum:
        tool name
        description

    Optional:
        readOnlyHint
        destructiveHint
        idempotentHint
        openWorldHint
        input_schema

    The count is based ONLY on fields actually returned.
    """

    count = 0

    # Name
    if getattr(tool, "name", None) is not None:
        count += 1

    # Description
    if getattr(tool, "description", None) is not None:
        count += 1

    annotations = getattr(tool, "annotations", None)

    optional_annotations = [
        "readOnlyHint",
        "destructiveHint",
        "idempotentHint",
        "openWorldHint",
    ]

    for field in optional_annotations:
        value = annotation_value(annotations, field)

        if value is not None:
            count += 1

    # Input schema
    input_schema = getattr(tool, "input_schema", None)

    if input_schema is not None:
        count += 1

    return count


def metadata_record(tool: Any) -> dict[str, Any]:
    """
    Extract exactly the metadata required by the corpus.
    """

    annotations = getattr(tool, "annotations", None)

    return {
        "tool": getattr(tool, "name", None),
        "description": getattr(tool, "description", None),

        "readOnlyHint": annotation_value(
            annotations,
            "readOnlyHint"
        ),

        "destructiveHint": annotation_value(
            annotations,
            "destructiveHint"
        ),

        "idempotentHint": annotation_value(
            annotations,
            "idempotentHint"
        ),

        "openWorldHint": annotation_value(
            annotations,
            "openWorldHint"
        ),

        "input_schema": safe_json(
            getattr(tool, "input_schema", None)
        ),
    }


# ============================================================
# REGISTRY DISCOVERY
# ============================================================

def discover_registry_servers(
    limit: int = MAX_SERVERS,
) -> list[dict[str, Any]]:
    """
    Retrieve server entries from the official MCP Registry.

    NOTE:
        Registry records describe published servers. They do NOT
        guarantee that the server is anonymously accessible.

        The collector subsequently attempts only a normal MCP
        connection. Authentication failures are recorded rather
        than bypassed.
    """

    params = {
        "limit": limit
    }

    if REGISTRY_SEARCH:
        params["search"] = REGISTRY_SEARCH

    print("[*] Querying MCP Registry...")

    response = requests.get(
        REGISTRY_URL,
        params=params,
        timeout=20,
    )

    response.raise_for_status()

    data = response.json()

    # Registry API responses can evolve. Handle common structures.
    if isinstance(data, list):
        entries = data

    elif isinstance(data, dict):
        entries = (
            data.get("servers")
            or data.get("items")
            or data.get("results")
            or []
        )

    else:
        entries = []

    print(f"[+] Registry returned {len(entries)} server entries")

    return entries[:limit]


# ============================================================
# EXTRACT REMOTE URLS
# ============================================================

def extract_remote_urls(server: dict[str, Any]) -> list[str]:
    """
    Extract Streamable HTTP / SSE-style URLs from a registry entry.

    We intentionally do not infer URLs from package names.
    """

    urls: list[str] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):

            for key, item in value.items():

                key_lower = str(key).lower()

                if key_lower in {
                    "url",
                    "endpoint",
                    "endpointurl",
                    "server_url",
                    "serverurl",
                    "remote_url",
                    "remoteurl",
                }:

                    if isinstance(item, str):
                        if item.startswith(("http://", "https://")):
                            urls.append(item)

                walk(item)

        elif isinstance(value, list):

            for item in value:
                walk(item)

    walk(server)

    # Preserve order but remove duplicates.
    return list(dict.fromkeys(urls))


# ============================================================
# SERVER NAME / SOURCE INFORMATION
# ============================================================

def server_name(server: dict[str, Any]) -> str:
    """
    Obtain a human-readable registry identifier.
    """

    for key in [
        "name",
        "server_name",
        "serverName",
        "id",
    ]:
        value = server.get(key)

        if value:
            return str(value)

    return "unknown_server"


def repository_url(server: dict[str, Any]) -> str | None:
    """
    Try to retrieve a publicly advertised repository URL.

    This does NOT search GitHub automatically yet.
    That should be a separate source-code module so the evidence
    remains auditable.
    """

    candidates: list[str] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):

            for key, item in value.items():

                key_lower = str(key).lower()

                if (
                    "repository" in key_lower
                    or key_lower in {"repo", "source", "sourcecode"}
                ):
                    if isinstance(item, str):
                        candidates.append(item)

                    elif isinstance(item, dict):
                        for subkey in [
                            "url",
                            "repositoryUrl",
                            "repository_url",
                        ]:
                            subvalue = item.get(subkey)

                            if isinstance(subvalue, str):
                                candidates.append(subvalue)

                walk(item)

        elif isinstance(value, list):

            for item in value:
                walk(item)

    walk(server)

    for candidate in candidates:

        if candidate.startswith(("http://", "https://")):
            return candidate

    return None


# ============================================================
# MCP COLLECTION
# ============================================================

async def collect_server(
    server: dict[str, Any]
) -> dict[str, Any]:

    name = server_name(server)

    urls = extract_remote_urls(server)

    result: dict[str, Any] = {
        "server_name": name,
        "registry_record": safe_json(server),
        "repository_url": repository_url(server),
        "connection_attempted": False,
        "connection_status": "no_remote_url_found",
        "endpoint": None,
        "tools_found": 0,
        "tools_with_metadata": 0,
        "tools": [],
        "error": None,
    }

    if not urls:
        return result

    # Try advertised remote endpoints only.
    for url in urls:

        print(f"    [>] Connecting: {url}")

        result["connection_attempted"] = True
        result["endpoint"] = url

        try:

            # Official SDK lifecycle.
            #
            # Entering Client performs the MCP connection/handshake.
            # list_tools() retrieves the advertised tool catalogue.
            #
            # NO call_tool() is made.
            async with Client(url) as client:

                listed = await asyncio.wait_for(
                    client.list_tools(),
                    timeout=CONNECTION_TIMEOUT,
                )

                tools = listed.tools

                result["connection_status"] = "success"
                result["tools_found"] = len(tools)

                for tool in tools:

                    metadata = metadata_record(tool)
                    num_metadata = count_metadata(tool)

                    if num_metadata > 0:
                        result["tools_with_metadata"] += 1

                    tool_record = {
                        "tool_name": getattr(
                            tool,
                            "name",
                            None,
                        ),

                        "desc": getattr(
                            tool,
                            "description",
                            None,
                        ),

                        # Source code is deliberately not guessed.
                        # It will be populated by the separate source
                        # inspection stage.
                        "code_implementation": None,

                        "metadata": metadata,

                        "num_metadata": num_metadata,

                        # Do not classify consistency during collection.
                        # This is evidence collection, not interpretation.
                        "metadata_consistency": "not_assessed",
                    }

                    result["tools"].append(tool_record)

                print(
                    f"    [+] SUCCESS: {len(tools)} tools"
                )

                return result

        except asyncio.TimeoutError:

            result["connection_status"] = "timeout"
            result["error"] = (
                f"Connection/list_tools timeout after "
                f"{CONNECTION_TIMEOUT}s"
            )

            print("    [!] TIMEOUT")

        except Exception as exc:

            result["connection_status"] = "failed"

            # Store a concise error rather than a full traceback.
            result["error"] = (
                f"{type(exc).__name__}: {str(exc)[:500]}"
            )

            print(
                f"    [!] FAILED: "
                f"{type(exc).__name__}"
            )

    return result


# ============================================================
# AGGREGATION
# ============================================================

def aggregate(results: list[dict[str, Any]]) -> dict[str, Any]:

    servers_investigated = len(results)

    tools = []

    for server in results:
        tools.extend(server.get("tools", []))

    tools_found = len(tools)

    tools_with_metadata = sum(
        1
        for tool in tools
        if tool.get("num_metadata", 0) > 0
    )

    basic_metadata = sum(
        1
        for tool in tools
        if tool.get("num_metadata", 0) == 2
    )

    extended_metadata = sum(
        1
        for tool in tools
        if tool.get("num_metadata", 0) > 2
    )

    successful_servers = sum(
        1
        for server in results
        if server.get("connection_status") == "success"
    )

    failed_servers = servers_investigated - successful_servers

    return {
        "servers_investigated": servers_investigated,
        "servers_successfully_connected": successful_servers,
        "servers_failed": failed_servers,

        "tools_found": tools_found,

        "tools_with_metadata": tools_with_metadata,

        "tools_with_only_basic_metadata": basic_metadata,

        "tools_with_extended_metadata": extended_metadata,

        # These are intentionally not calculated here.
        #
        # Consistency requires source-code evidence and therefore
        # belongs to the analysis stage.
        "metadata_consistent": None,
        "metadata_inconsistent": None,
        "metadata_not_verifiable": None,

        "tools_with_source_code": None,
        "tools_without_source_code": None,
    }


# ============================================================
# SAVE
# ============================================================

def save_json(
    path: Path,
    data: dict[str, Any],
) -> None:

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with path.open(
        "w",
        encoding="utf-8",
    ) as f:

        json.dump(
            data,
            f,
            indent=2,
            ensure_ascii=False,
        )


# ============================================================
# MAIN
# ============================================================

async def main() -> None:

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    print("=" * 60)
    print("MCP PASSIVE CORPUS COLLECTOR")
    print("=" * 60)

    # --------------------------------------------------------
    # 1. DISCOVER
    # --------------------------------------------------------

    servers = discover_registry_servers(
        limit=MAX_SERVERS
    )

    # --------------------------------------------------------
    # 2. COLLECT
    # --------------------------------------------------------

    results: list[dict[str, Any]] = []

    for index, server in enumerate(
        servers,
        start=1,
    ):

        print(
            f"\n[{index}/{len(servers)}] "
            f"{server_name(server)}"
        )

        result = await collect_server(server)

        results.append(result)

    # --------------------------------------------------------
    # 3. AGGREGATE
    # --------------------------------------------------------

    summary = aggregate(results)

    # --------------------------------------------------------
    # 4. SAVE SOURCE-SPECIFIC CORPUS
    # --------------------------------------------------------

    corpus = {
        "corpus_version": "1.0",

        "source": {
            "name": "MCP Registry",
            "url": REGISTRY_URL,
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

    output_file = (
        OUTPUT_DIR /
        "S1_mcp_registry.json"
    )

    save_json(
        output_file,
        corpus,
    )

    # --------------------------------------------------------
    # 5. SAVE SUMMARY
    # --------------------------------------------------------

    save_json(
        OUTPUT_DIR /
        "corpus.json",
        summary,
    )

    # --------------------------------------------------------
    # 6. TERMINAL SUMMARY
    # --------------------------------------------------------

    print("\n" + "=" * 60)
    print("COLLECTION COMPLETE")
    print("=" * 60)

    print(
        f"Servers investigated: "
        f"{summary['servers_investigated']}"
    )

    print(
        f"Servers successfully connected: "
        f"{summary['servers_successfully_connected']}"
    )

    print(
        f"Tools found: "
        f"{summary['tools_found']}"
    )

    print(
        f"Tools with metadata: "
        f"{summary['tools_with_metadata']}"
    )

    print(
        f"Only name + description: "
        f"{summary['tools_with_only_basic_metadata']}"
    )

    print(
        f"Extended metadata: "
        f"{summary['tools_with_extended_metadata']}"
    )

    print(
        f"\nSaved: {output_file}"
    )


if __name__ == "__main__":
    asyncio.run(main())
