"""
Module 1: Server Selection / Discovery

Reads MCP server tools from JSON file and displays them.
"""

import json
from pathlib import Path


def run(input_file):
    """
    Main entry point for Module 1: Server Selection / Discovery

    Args:
        input_file (str): Path to JSON file containing tools

    Returns:
        dict: Parsed and normalized tools data
    """
    print("=" * 70)
    print("Module 1: Server Selection / Discovery")
    print("=" * 70)

    result = process(input_file)
    return result


def process(input_file):
    """
    Read and display tools from JSON file.

    Supports both:
    - Normalized MCP tool JSON
    - MCPTox pure_tool.json format

    Args:
        input_file (str): Path to JSON file

    Returns:
        dict: Contains 'tools' list and metadata
    """
    try:
        # Read the JSON file
        with open(input_file, 'r', encoding='utf-8') as f:
            tools = json.load(f)

        # Display header
        print(f"\nLoaded tools from: {input_file}")
        print(f"Total tools found: {len(tools)}\n")

        # Normalize input format if it is MCPTox
        tools = normalize_tools(tools)

        # Display each tool
        display_tools(tools)

        # Return structured result
        return {
            'tools': tools,
            'tool_count': len(tools),
            'source_file': input_file
        }

    except FileNotFoundError:
        raise FileNotFoundError(f"Input file not found: {input_file}")

    except json.JSONDecodeError:
        raise ValueError(f"Invalid JSON file: {input_file}")

    except Exception as e:
        raise Exception(f"Error processing input file: {str(e)}")


def normalize_tools(tools):
    """
    Detect the input format and normalize tools into the format
    expected by the rest of the pipeline.

    Supported formats:

    Normalized format:
        tool
        description
        readOnlyHint
        destructiveHint
        idempotentHint
        openWorldHint
        source

    MCPTox format:
        server_name
        tool_name
        query
        tool_content
        security risk
        paradigm
        tool_address

    Args:
        tools (list): Raw tool dictionaries

    Returns:
        list: Normalized tool dictionaries
    """

    if not tools:
        return tools

    normalized_tools = []

    for tool in tools:

        # ---------------------------------------------------------
        # Format 1: Already normalized MCP tool format
        # ---------------------------------------------------------
        if "tool" in tool and "description" in tool:

            normalized_tools.append(tool)

        # ---------------------------------------------------------
        # Format 2: MCPTox pure_tool.json format
        # ---------------------------------------------------------
        elif "tool_name" in tool and "tool_content" in tool:

            normalized_tool = {
                "tool": tool.get("tool_name", "N/A"),
                "description": tool.get("tool_content", "N/A"),

                # MCPTox does not provide these MCP annotations.
                # Keep them as None rather than assuming False.
                "readOnlyHint": None,
                "destructiveHint": None,
                "idempotentHint": None,
                "openWorldHint": None,

                # Preserve the original source information.
                "source": f"MCPTox:{tool.get('tool_address', 'N/A')}"
            }

            normalized_tools.append(normalized_tool)

        # ---------------------------------------------------------
        # Unknown format
        # ---------------------------------------------------------
        else:
            raise ValueError(
                "Unsupported tool format. Expected either the "
                "normalized MCP format or the MCPTox pure_tool.json format."
            )

    return normalized_tools


def display_tools(tools):
    """
    Display tools in formatted table.

    Args:
        tools (list): List of normalized tool dictionaries
    """
    if not tools:
        print("No tools found.")
        return

    # Print table header
    print("-" * 70)
    print(
        f"{'Tool Name':<30} | "
        f"{'ReadOnly':<10} | "
        f"{'Destructive':<12} | "
        f"{'Source':<15}"
    )
    print("-" * 70)

    # Print each tool
    for tool in tools:
        tool_name = tool.get('tool', 'N/A')
        description = tool.get('description', 'N/A')
        readonly = str(tool.get('readOnlyHint', 'N/A'))
        destructive = str(tool.get('destructiveHint', 'N/A'))
        source = tool.get('source', 'N/A')

        print(
            f"{tool_name:<30} | "
            f"{readonly:<10} | "
            f"{destructive:<12} | "
            f"{source:<15}"
        )

    print("-" * 70)

    # Print detailed information
    print("\n[DETAILED TOOL INFORMATION]\n")

    for idx, tool in enumerate(tools, 1):
        print(f"{idx}. {tool.get('tool', 'Unknown')}")
        print(f"   Description: {tool.get('description', 'N/A')}")
        print(f"   ReadOnly Hint: {tool.get('readOnlyHint', 'N/A')}")
        print(f"   Destructive Hint: {tool.get('destructiveHint', 'N/A')}")
        print(f"   Idempotent Hint: {tool.get('idempotentHint', 'N/A')}")
        print(f"   Open World Hint: {tool.get('openWorldHint', 'N/A')}")
        print(f"   Source: {tool.get('source', 'N/A')}")
        print()