import json
import csv
from pathlib import Path

# --------------------------------------------------
# FILE LOCATIONS
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent

JSON_FILE = BASE_DIR / "S1_mcp_registry.json"
CSV_FILE = BASE_DIR / "tool_metadata.csv"

# --------------------------------------------------
# LOAD CORPUS
# --------------------------------------------------

with open(JSON_FILE, "r", encoding="utf-8") as f:
    corpus = json.load(f)

# --------------------------------------------------
# CSV COLUMNS
# --------------------------------------------------

fieldnames = [
    "server_name",
    "tool_name",
    "description",
    "readOnlyHint",
    "destructiveHint",
    "idempotentHint",
    "openWorldHint",
    "input_schema",
    "total_metadata_content"
]

rows = []

# --------------------------------------------------
# EXTRACT TOOLS
# --------------------------------------------------

for server in corpus.get("servers", []):

    server_name = server.get("server_name", "unknown_server")

    for tool in server.get("tools", []):

        tool_name = tool.get("tool_name", "")
        description = tool.get("desc", "")

        metadata = tool.get("metadata", {})

        read_only = metadata.get("readOnlyHint")
        destructive = metadata.get("destructiveHint")
        idempotent = metadata.get("idempotentHint")
        open_world = metadata.get("openWorldHint")
        input_schema = metadata.get("input_schema", {})

        # Number of fields in the metadata object
        total_metadata_content = len(metadata)

        rows.append({
            "server_name": server_name,
            "tool_name": tool_name,
            "description": description,
            "readOnlyHint": read_only,
            "destructiveHint": destructive,
            "idempotentHint": idempotent,
            "openWorldHint": open_world,
            "input_schema": json.dumps(
                input_schema,
                ensure_ascii=False
            ),
            "total_metadata_content": total_metadata_content
        })

# --------------------------------------------------
# SAVE CSV
# --------------------------------------------------

with open(
    CSV_FILE,
    "w",
    newline="",
    encoding="utf-8-sig"
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=fieldnames
    )

    writer.writeheader()
    writer.writerows(rows)

# --------------------------------------------------
# RESULT
# --------------------------------------------------

print("=" * 80)
print("CSV EXPORT COMPLETE")
print("=" * 80)
print(f"Servers processed: {len(corpus.get('servers', []))}")
print(f"Tools exported: {len(rows)}")
print(f"CSV file: {CSV_FILE}")
print("=" * 80)