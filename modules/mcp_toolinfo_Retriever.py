"""MCP tool-information retriever (metadata / discovery only).

What this module does
---------------------
Connects to an MCP server and reads only what the server *declares* through
the MCP protocol:

    * initialize        -> server info, protocol version, server capabilities
    * tools/list        -> tool names, descriptions, input schemas, annotations

What this module deliberately does NOT do
-----------------------------------------
    * It never calls tools/call. No tool is executed to obtain metadata.
    * It never returns implementation source code. Declared metadata is not
      evidence of what the implementation actually does.

The retrieved tools are converted into the SAME normalized structure that
Module 1 already accepts (``tool`` + ``description`` + optional hints), so
Module 1 -> Module 2 -> Module 3 behave identically for uploaded JSON and
for a live server.

Transports
----------
    * ``stdio``: launches a local MCP server process and speaks JSON-RPC over
      its stdin/stdout (e.g. ``npx -y @modelcontextprotocol/server-git``).
    * ``http``: Streamable HTTP / SSE endpoint, JSON-RPC over POST.

Only the standard library is used, so no extra dependency is required.
"""
import json
import os
import shlex
import shutil
import subprocess
import urllib.error
import urllib.request
import uuid

PROTOCOL_VERSION = "2024-11-05"
CLIENT_INFO = {"name": "AgentPreDeployer", "version": "1.0"}

SUPPORTED_TRANSPORTS = ("stdio", "http")

RETRIEVAL_SCOPE = (
    "Metadata/discovery only: initialize + tools/list. No tool was executed "
    "and no implementation code was retrieved."
)

# MCP annotation key -> normalized hint key used by the existing pipeline
ANNOTATION_KEYS = {
    "readOnlyHint": "readOnlyHint",
    "destructiveHint": "destructiveHint",
    "idempotentHint": "idempotentHint",
    "openWorldHint": "openWorldHint",
}


class McpRetrievalError(Exception):
    """Raised for connection, protocol, transport, or response errors."""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def retrieve_tool_metadata(
    transport,
    command=None,
    url=None,
    headers=None,
    env=None,
    timeout=30,
):
    """Connect to an MCP server and retrieve declared tool metadata.

    Args:
        transport (str): "stdio" or "http".
        command (str): stdio only. Command line to launch the server.
        url (str): http only. Endpoint URL.
        headers (dict): http only. Extra headers (e.g. Authorization).
        env (dict): stdio only. Extra environment variables.
        timeout (int): Per-request timeout in seconds.

    Returns:
        dict: {
            "server_info": {...},
            "protocol_version": "...",
            "server_capabilities": {...},
            "tools": [ normalized tool dicts ],
            "tool_count": int,
            "raw_tools": [ ...as declared by the server... ],
            "source": "mcp://...",
            "retrieval_scope": RETRIEVAL_SCOPE,
        }

    Raises:
        McpRetrievalError: unsupported transport, bad configuration,
            unavailable server, transport failure, or invalid MCP response.
    """
    if transport not in SUPPORTED_TRANSPORTS:
        raise McpRetrievalError(
            "Unsupported transport '{}'. Supported transports: {}.".format(
                transport, ", ".join(SUPPORTED_TRANSPORTS)
            )
        )

    if transport == "stdio":
        if not command or not str(command).strip():
            raise McpRetrievalError(
                "A server command is required for the stdio transport "
                "(for example: npx -y @modelcontextprotocol/server-git)."
            )
        session = _StdioSession(command, env=env, timeout=timeout)
        source = "mcp+stdio://{}".format(str(command).strip())
    else:
        if not url or not str(url).strip():
            raise McpRetrievalError(
                "A server URL is required for the http transport "
                "(for example: http://localhost:3000/mcp)."
            )
        if not str(url).strip().lower().startswith(("http://", "https://")):
            raise McpRetrievalError(
                "Invalid URL '{}'. It must start with http:// or https://.".format(url)
            )
        session = _HttpSession(url, headers=headers, timeout=timeout)
        source = "mcp+http://{}".format(str(url).strip())

    try:
        initialize_result = session.initialize()
        raw_tools = session.list_tools()
    finally:
        session.close()

    normalized = [
        normalize_mcp_tool(raw_tool, source)
        for raw_tool in raw_tools
    ]

    return {
        "server_info": initialize_result.get("serverInfo") or {},
        "protocol_version": initialize_result.get("protocolVersion"),
        "server_capabilities": initialize_result.get("capabilities") or {},
        "instructions": initialize_result.get("instructions"),
        "tools": normalized,
        "tool_count": len(normalized),
        "raw_tools": raw_tools,
        "source": source,
        "transport": transport,
        "retrieval_scope": RETRIEVAL_SCOPE,
    }


def normalize_mcp_tool(raw_tool, source):
    """Convert one MCP tool declaration into the pipeline's normalized form.

    The returned dict uses the keys Module 1 already accepts (``tool``,
    ``description``, the four hints, ``source``) so nothing downstream has
    to change. Extra MCP metadata is attached alongside, and hint
    provenance is recorded so the UI can distinguish a hint the server
    actually declared from one that is simply absent.
    """
    if not isinstance(raw_tool, dict):
        raise McpRetrievalError(
            "Invalid MCP response: each entry in tools/list must be an "
            "object, got {}.".format(type(raw_tool).__name__)
        )

    name = raw_tool.get("name")
    if not name or not isinstance(name, str):
        raise McpRetrievalError(
            "Invalid MCP response: a tool is missing a string 'name' field."
        )

    # MCP allows either description or title; keep the declared text as-is.
    description = raw_tool.get("description")
    if description is None:
        description = raw_tool.get("title") or ""

    annotations = raw_tool.get("annotations")
    if not isinstance(annotations, dict):
        annotations = {}

    normalized = {
        "tool": name,
        "description": str(description),
        "source": source,
    }

    hint_provenance = {}

    for annotation_key, hint_key in ANNOTATION_KEYS.items():
        if annotation_key in annotations:
            value = annotations[annotation_key]
            # Keep only genuine booleans; anything else is not a usable hint.
            if isinstance(value, bool):
                normalized[hint_key] = value
                hint_provenance[hint_key] = "declared_by_server"
            else:
                normalized[hint_key] = None
                hint_provenance[hint_key] = "unavailable"
        else:
            # Absent hint stays unset rather than being assumed False.
            normalized[hint_key] = None
            hint_provenance[hint_key] = "unavailable"

    normalized["hint_provenance"] = hint_provenance

    # Additional metadata the server explicitly exposed (no execution).
    input_schema = raw_tool.get("inputSchema") or raw_tool.get("input_schema")
    if input_schema is not None:
        normalized["input_schema"] = input_schema

    output_schema = raw_tool.get("outputSchema") or raw_tool.get("output_schema")
    if output_schema is not None:
        normalized["output_schema"] = output_schema

    if raw_tool.get("title"):
        normalized["title"] = raw_tool["title"]

    if annotations:
        normalized["annotations"] = annotations

    normalized["metadata_only"] = True

    return normalized


def write_normalized_json(tools, destination_path):
    """Write normalized tools to JSON in the format Module 1 reads.

    This keeps the pipeline entry point unchanged: the retrieved metadata is
    persisted as a normal tool-list JSON file and then handed to Module 1
    exactly like an uploaded file.
    """
    payload = []

    for tool in tools:
        # Module 1 requires 'tool' and 'description'; carry the rest through.
        entry = dict(tool)
        entry.setdefault("description", "")
        payload.append(entry)

    with open(destination_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)

    return destination_path



# ---------------------------------------------------------------------------
# Command resolution for the stdio transport
# ---------------------------------------------------------------------------

# Bundled dependency-free server, so the feature can be exercised on a machine
# without Node.js / npx.
DEMO_SERVER_COMMAND = "python demo_mcp_server/demo_stdio_server.py"


def _resolve_executable(program):
    """Locate an executable, allowing for Windows shims.

    On Windows, tools installed by npm are ``.cmd`` shims (``npx.cmd``), which
    ``subprocess`` cannot launch by bare name. Resolve the real path first so
    the launch either works or fails with a useful message.
    """
    resolved = shutil.which(program)

    if resolved:
        return resolved

    if os.name == "nt":
        for extension in (".cmd", ".bat", ".exe"):
            resolved = shutil.which(program + extension)
            if resolved:
                return resolved

    return None


def _missing_command_message(program):
    """Explain what is missing and how to get a working command."""
    parts = [
        "Could not start the MCP server: '{}' was not found on this "
        "machine.".format(program)
    ]

    if program in ("npx", "npm", "node"):
        parts.append(
            "The reference MCP servers are published on npm, so '{}' needs "
            "Node.js to be installed and on PATH.".format(program)
        )
    elif program in ("uvx", "uv"):
        parts.append(
            "'{}' is provided by the uv tool (pip install uv).".format(program)
        )
    elif program == "python3":
        parts.append(
            "On Windows the interpreter is usually called 'python', not "
            "'python3'."
        )

    parts.append(
        "To retrieve metadata without installing anything, use the bundled "
        "server: {}".format(DEMO_SERVER_COMMAND)
    )

    return " ".join(parts)


# ---------------------------------------------------------------------------
# stdio transport
# ---------------------------------------------------------------------------

class _StdioSession:
    """Minimal JSON-RPC client over a child MCP server process."""

    def __init__(self, command, env=None, timeout=30):
        self.timeout = timeout
        self._process = None

        try:
            argv = shlex.split(str(command))
        except ValueError as error:
            raise McpRetrievalError(
                "Could not parse the server command: {}".format(error)
            )

        if not argv:
            raise McpRetrievalError("The server command is empty.")

        executable = _resolve_executable(argv[0])

        if executable is None:
            raise McpRetrievalError(_missing_command_message(argv[0]))

        argv = [executable] + argv[1:]

        process_env = None
        if env:
            import os

            process_env = dict(os.environ)
            process_env.update({str(k): str(v) for k, v in env.items()})

        try:
            self._process = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                env=process_env,
            )
        except FileNotFoundError:
            raise McpRetrievalError(_missing_command_message(argv[0]))
        except OSError as error:
            raise McpRetrievalError(
                "Could not start the MCP server process: {}".format(error)
            )

    def _send(self, payload):
        if self._process.poll() is not None:
            raise McpRetrievalError(
                "The MCP server process exited before the request could be "
                "sent.{}".format(self._stderr_tail())
            )
        try:
            self._process.stdin.write(json.dumps(payload) + "\n")
            self._process.stdin.flush()
        except (BrokenPipeError, OSError) as error:
            raise McpRetrievalError(
                "Lost connection to the MCP server process: {}{}".format(
                    error, self._stderr_tail()
                )
            )

    def _read_result(self, request_id):
        """Read lines until the matching JSON-RPC response arrives."""
        while True:
            line = self._process.stdout.readline()

            if line == "":
                raise McpRetrievalError(
                    "The MCP server closed the connection without "
                    "responding.{}".format(self._stderr_tail())
                )

            line = line.strip()
            if not line:
                continue

            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                # Servers sometimes print banners on stdout; skip non-JSON.
                continue

            if not isinstance(message, dict):
                continue

            # Ignore notifications and unrelated responses.
            if message.get("id") != request_id:
                continue

            if "error" in message:
                raise McpRetrievalError(
                    "The MCP server returned an error: {}".format(
                        _format_rpc_error(message["error"])
                    )
                )

            if "result" not in message:
                raise McpRetrievalError(
                    "Invalid MCP response: no 'result' field in the reply."
                )

            return message["result"]

    def _stderr_tail(self):
        try:
            if self._process and self._process.stderr:
                self._process.stderr.flush()
        except Exception:
            pass
        return ""

    def initialize(self):
        request_id = 1
        self._send(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "initialize",
                "params": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": CLIENT_INFO,
                },
            }
        )
        result = self._read_result(request_id)

        if not isinstance(result, dict):
            raise McpRetrievalError(
                "Invalid MCP response to initialize: expected an object."
            )

        # Required by the protocol before other requests.
        self._send(
            {
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": {},
            }
        )

        return result

    def list_tools(self):
        tools = []
        cursor = None
        request_id = 2

        while True:
            params = {} if cursor is None else {"cursor": cursor}
            self._send(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "method": "tools/list",
                    "params": params,
                }
            )
            result = self._read_result(request_id)
            request_id += 1

            tools.extend(_extract_tools(result))

            cursor = result.get("nextCursor") if isinstance(result, dict) else None
            if not cursor:
                break

        return tools

    def close(self):
        if not self._process:
            return
        try:
            if self._process.stdin:
                self._process.stdin.close()
        except Exception:
            pass
        try:
            self._process.terminate()
            self._process.wait(timeout=5)
        except Exception:
            try:
                self._process.kill()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# http transport
# ---------------------------------------------------------------------------

class _HttpSession:
    """Minimal JSON-RPC client for Streamable HTTP / SSE MCP endpoints."""

    def __init__(self, url, headers=None, timeout=30):
        self.url = str(url).strip()
        self.timeout = timeout
        self.session_id = None
        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if headers:
            self.headers.update(
                {str(k): str(v) for k, v in headers.items() if k and v}
            )

    def _post(self, payload, expect_response=True):
        data = json.dumps(payload).encode("utf-8")
        headers = dict(self.headers)
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id

        request = urllib.request.Request(
            self.url, data=data, headers=headers, method="POST"
        )

        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                session_id = response.headers.get("Mcp-Session-Id")
                if session_id:
                    self.session_id = session_id

                body = response.read().decode("utf-8", errors="replace")
                content_type = (response.headers.get("Content-Type") or "").lower()
        except urllib.error.HTTPError as error:
            detail = ""
            try:
                detail = error.read().decode("utf-8", errors="replace")[:500]
            except Exception:
                pass
            raise McpRetrievalError(
                "The MCP server returned HTTP {} {}. {}".format(
                    error.code, error.reason, detail
                ).strip()
            )
        except urllib.error.URLError as error:
            raise McpRetrievalError(
                "Could not reach the MCP server at {}: {}".format(
                    self.url, getattr(error, "reason", error)
                )
            )
        except TimeoutError:
            raise McpRetrievalError(
                "Timed out after {}s waiting for {}.".format(self.timeout, self.url)
            )

        if not expect_response:
            return None

        return _parse_http_body(body, content_type)

    def initialize(self):
        result = self._post(
            {
                "jsonrpc": "2.0",
                "id": str(uuid.uuid4()),
                "method": "initialize",
                "params": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": CLIENT_INFO,
                },
            }
        )

        if not isinstance(result, dict):
            raise McpRetrievalError(
                "Invalid MCP response to initialize: expected an object."
            )

        self._post(
            {
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": {},
            },
            expect_response=False,
        )

        return result

    def list_tools(self):
        tools = []
        cursor = None

        while True:
            params = {} if cursor is None else {"cursor": cursor}
            result = self._post(
                {
                    "jsonrpc": "2.0",
                    "id": str(uuid.uuid4()),
                    "method": "tools/list",
                    "params": params,
                }
            )

            tools.extend(_extract_tools(result))

            cursor = result.get("nextCursor") if isinstance(result, dict) else None
            if not cursor:
                break

        return tools

    def close(self):
        return None


# ---------------------------------------------------------------------------
# Shared response handling
# ---------------------------------------------------------------------------

def _parse_http_body(body, content_type):
    """Parse a JSON or SSE response body into a JSON-RPC result."""
    payloads = []

    if "text/event-stream" in content_type or body.lstrip().startswith("event:"):
        for line in body.splitlines():
            line = line.strip()
            if not line.startswith("data:"):
                continue
            chunk = line[len("data:"):].strip()
            if not chunk or chunk == "[DONE]":
                continue
            try:
                payloads.append(json.loads(chunk))
            except json.JSONDecodeError:
                continue
    else:
        if not body.strip():
            raise McpRetrievalError(
                "The MCP server returned an empty response body."
            )
        try:
            payloads.append(json.loads(body))
        except json.JSONDecodeError:
            raise McpRetrievalError(
                "The MCP server returned a response that is not valid JSON. "
                "First 200 characters: {}".format(body[:200])
            )

    for payload in payloads:
        if isinstance(payload, list):
            candidates = payload
        else:
            candidates = [payload]

        for message in candidates:
            if not isinstance(message, dict):
                continue
            if "error" in message:
                raise McpRetrievalError(
                    "The MCP server returned an error: {}".format(
                        _format_rpc_error(message["error"])
                    )
                )
            if "result" in message:
                return message["result"]

    raise McpRetrievalError(
        "Invalid MCP response: no JSON-RPC result was found in the reply."
    )


def _extract_tools(result):
    """Pull the tools array out of a tools/list result."""
    if not isinstance(result, dict):
        raise McpRetrievalError(
            "Invalid MCP response to tools/list: expected an object."
        )

    tools = result.get("tools")

    if tools is None:
        raise McpRetrievalError(
            "Invalid MCP response to tools/list: no 'tools' array. "
            "The server may not expose any tools capability."
        )

    if not isinstance(tools, list):
        raise McpRetrievalError(
            "Invalid MCP response to tools/list: 'tools' must be an array."
        )

    return tools


def _format_rpc_error(error):
    if isinstance(error, dict):
        return "{} (code {})".format(
            error.get("message", "unknown error"), error.get("code", "n/a")
        )
    return str(error)
