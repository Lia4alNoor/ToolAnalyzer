"""
Module 2: Capability Extraction

Extracts semantic capability features from tools.
Creates assumed_capability (tool name + description) for normalization.

Does NOT normalize - that's Module 3's job.
Does NOT map to C1-C6 - that's Module 4's job.
"""


import re


def run(input_data):
    """
    Main entry point for Module 2: Capability Extraction.

    Args:
        input_data (dict): Output from Module 1
            {
                'tools': [...],
                'tool_count': 10,
                'source_file': 'data/...'
            }

    Returns:
        dict: Tools with extracted capability features.
    """
    print("=" * 70)
    print("Module 2: Capability Extraction")
    print("=" * 70)

    return process(input_data)


def process(data):
    """
    Extract capability features from all tools.

    For each tool, extracts semantic features describing
    what the tool can do:

        - is_read_only
        - is_destructive
        - modifies_state
        - accesses_external
        - executes_code
        - communicates_externally

    Also creates:
        - assumed_capability

    Args:
        data (dict): Tools data from Module 1.

    Returns:
        dict: Enhanced tools with extracted features.
    """
    if not data:
        return None

    tools = data.get("tools", [])

    print(f"\nExtracting capabilities from {len(tools)} tools...\n")

    extracted_tools = []

    for tool in tools:
        extracted = extract_tool_capabilities(tool)
        extracted_tools.append(extracted)

        print(f"  [+] {tool.get('tool', 'unknown')}: extracted features")

    result = {
        "tools": extracted_tools,
        "tool_count": len(extracted_tools),
        "source_file": data.get("source_file"),
        "extraction_complete": True
    }

    print(
        f"\n✓ Extraction complete: "
        f"{len(extracted_tools)} tools processed"
    )

    return result


def extract_tool_capabilities(tool):
    """
    Extract semantic capability features from one tool.

    Original tool metadata is preserved.

    Returns:
        dict:
            {
                ... original fields ...,
                "assumed_capability": "...",
                "capability_features": {
                    "is_read_only": bool,
                    "is_destructive": bool,
                    "modifies_state": bool,
                    "accesses_external": bool,
                    "executes_code": bool,
                    "communicates_externally": bool
                }
            }
    """

    # Preserve original tool data
    result = dict(tool)

    tool_name = str(tool.get("tool", ""))
    description = str(tool.get("description", ""))

    combined_text = normalize_text(
        f"{tool_name} {description}"
    )

    # Used by Module 3
    result["assumed_capability"] = (
        f"{tool_name} {description}"
    ).strip()

    capability_features = {
        "is_read_only": extract_is_readonly(
            tool,
            combined_text
        ),
        "is_destructive": extract_is_destructive(
            tool,
            combined_text
        ),
        "modifies_state": extract_modifies_state(
            tool,
            combined_text
        ),
        "accesses_external": extract_accesses_external(
            tool,
            combined_text
        ),
        "executes_code": extract_executes_code(
            tool,
            combined_text
        ),
        "communicates_externally": extract_communication(
            tool,
            combined_text
        ),
    }

    result["capability_features"] = capability_features

    return result


# =========================================================
# TEXT HELPERS
# =========================================================

def normalize_text(text):
    """
    Normalize text for semantic keyword matching.
    """
    text = text.lower()
    text = re.sub(r"[_\-\/]+", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def contains_keyword(text, keywords):
    """
    Match complete words rather than substrings.

    This prevents false positives such as:
        "execute" matching "executed"
        "run" matching "runtime"
        "process" matching "processor"
    """

    return any(
        re.search(
            rf"\b{re.escape(keyword)}\b",
            text
        )
        for keyword in keywords
    )


def matches_patterns(text, patterns):
    """
    Return True if any regular-expression pattern matches.
    """
    return any(
        re.search(pattern, text)
        for pattern in patterns
    )


# =========================================================
# SHARED VOCABULARY
# =========================================================
# FIX: single source of truth for "this action changes persistent
# state". extract_is_readonly() (as negative evidence) and
# extract_modifies_state() (as positive evidence) previously used
# two separately-maintained keyword lists that had drifted apart
# ("save"/"set"/"change"/"drop"/"clear" were missing from one or
# the other). That let a tool be flagged is_read_only=True and
# modifies_state=True at the same time. Both functions now draw
# from this one list so they can't disagree.
STATE_MODIFYING_KEYWORDS = [
    "create",
    "write",
    "delete",
    "edit",
    "modify",
    "update",
    "insert",
    "remove",
    "move",
    "rename",
    "overwrite",
    "alter",
    "truncate",
    "destroy",
    "drop",
    "clear",
    "append",
    "save",
    "set",
    "change"
]


# =========================================================
# READ-ONLY
# =========================================================

def extract_is_readonly(tool, combined_text):
    """
    Determine whether the tool is read-only.

    Strong evidence:
        - readOnlyHint == True

    Negative evidence:
        - destructiveHint == True
        - semantically destructive action (see extract_is_destructive)
        - explicit state modification

    Semantic read actions:
        read, list, get, retrieve, query, show, view,
        display, fetch, search, find, describe
    """

    if tool.get("readOnlyHint") is True:
        return True

    if tool.get("destructiveHint") is True:
        return False

    # FIX: previously only the destructiveHint *metadata* flag was
    # checked here, not the semantic destructive-keyword detector.
    # A tool with no explicit hint but a destructive-sounding
    # description (e.g. "clear the cache") could slip through and
    # get marked read-only. Deferring to extract_is_destructive()
    # keeps this consistent with modifies_state below.
    if extract_is_destructive(tool, combined_text):
        return False

    read_keywords = [
        "read",
        "list",
        "get",
        "retrieve",
        "query",
        "show",
        "view",
        "display",
        "fetch",
        "search",
        "find",
        "describe",
        "inspect"
    ]

    has_read_action = contains_keyword(
        combined_text,
        read_keywords
    )

    has_modification_action = contains_keyword(
        combined_text,
        STATE_MODIFYING_KEYWORDS
    )

    return has_read_action and not has_modification_action


# =========================================================
# DESTRUCTIVE
# =========================================================

def extract_is_destructive(tool, combined_text):
    """
    Determine whether the tool performs a destructive operation.

    Strong evidence:
        - destructiveHint == True

    Semantic destructive actions:
        delete, remove, drop, destroy, clear,
        overwrite, truncate
    """

    if tool.get("destructiveHint") is True:
        return True

    destructive_keywords = [
        "delete",
        "remove",
        "drop",
        "destroy",
        "clear",
        "overwrite",
        "truncate"
    ]

    return contains_keyword(
        combined_text,
        destructive_keywords
    )


# =========================================================
# STATE MODIFICATION
# =========================================================

def extract_modifies_state(tool, combined_text):
    """
    Determine whether the tool can modify persistent state.

    This is broader than destructive behavior.

    Examples:

        create_file      -> modifies_state = True
        update_record    -> modifies_state = True
        delete_file      -> modifies_state = True
        read_file        -> modifies_state = False
        search_web       -> modifies_state = False
    """

    if tool.get("readOnlyHint") is True:
        return False

    if tool.get("destructiveHint") is True:
        return True

    # FIX: a destructive tool modifies state by definition. The
    # keyword+target check below requires one of a fixed list of
    # target nouns (file, database, table, ...) to co-occur with
    # the action, which doesn't cover every noun a destructive
    # tool might act on (e.g. "clear the cache" - "cache" isn't in
    # state_targets). That previously let is_destructive=True and
    # modifies_state=False happen together. Short-circuiting here
    # closes that gap regardless of the target list's coverage.
    if extract_is_destructive(tool, combined_text):
        return True

    state_targets = [
        "file",
        "files",
        "directory",
        "folder",
        "database",
        "record",
        "records",
        "configuration",
        "config",
        "repository",
        "repo",
        "document",
        "documents",
        "table",
        "tables",
        "storage",
        "persistent state",
        "data"
    ]

    has_action = contains_keyword(
        combined_text,
        STATE_MODIFYING_KEYWORDS
    )

    has_target = contains_keyword(
        combined_text,
        state_targets
    )

    return has_action and has_target


# =========================================================
# EXTERNAL ACCESS
# =========================================================

def extract_accesses_external(tool, combined_text):
    """
    Determine whether the tool retrieves or ingests
    information from an external source.

    Strong semantic indicators include:

        - web search
        - HTTP/API requests
        - downloading
        - accessing remote resources
        - fetching external data/content

    Metadata such as openWorldHint is intentionally NOT
    treated as sufficient evidence by itself.
    """

    external_patterns = [
        r"\bfetch\b.*\b(data|content|information|resource)\b",
        r"\bretrieve\b.*\b(data|content|information|resource)\b",
        r"\bdownload\b.*\b(file|content|data|resource)\b",
        r"\bweb search\b",
        r"\bsearch the web\b",
        r"\bbrowse\b.*\bweb\b",
        r"\bhttp\b.*\brequest\b",
        r"\bhttps\b.*\brequest\b",
        r"\bapi\b.*\brequest\b",
        r"\brequest\b.*\bexternal\b",
        r"\baccess\b.*\bremote\b",
        r"\bretrieve\b.*\bremote\b",
        r"\bconnect\b.*\bexternal\b",
        r"\bexternal\b.*\bservice\b",
        r"\bremote\b.*\bservice\b",
        r"\bremote\b.*\bserver\b",
    ]

    return matches_patterns(
        combined_text,
        external_patterns
    )


# =========================================================
# CODE / COMMAND EXECUTION
# =========================================================

def extract_executes_code(tool, combined_text):
    """
    Determine whether the tool executes code or system commands.

    Strong semantic indicators:

        - execute code
        - execute command
        - run command
        - shell command
        - run script
        - evaluate code
        - subprocess
        - spawn process

    Avoids treating generic words such as "process" or
    "run" as execution unless they occur in an execution
    context.
    """

    execution_patterns = [
        r"\bexecute\b.*\b(code|command|script|program)\b",
        r"\bexecute\b.*\bshell\b",
        r"\brun\b.*\b(command|script|code|program|shell)\b",
        r"\brun\b.*\bprocess\b",
        r"\bexecute command\b",
        r"\brun command\b",
        r"\bshell command\b",
        r"\bshell\b.*\bexecution\b",
        r"\bcommand execution\b",
        r"\bevaluate\b.*\b(code|expression|script)\b",
        r"\beval\b.*\b(code|expression)\b",
        r"\bexecute\b.*\bprogram\b",
        r"\bspawn\b.*\bprocess\b",
        r"\bsubprocess\b",
        r"\bchild process\b",
        r"\bterminal command\b",
        r"\bsystem command\b",
        r"\bscript execution\b",
    ]

    return matches_patterns(
        combined_text,
        execution_patterns
    )


# =========================================================
# EXTERNAL COMMUNICATION
# =========================================================

def extract_communication(tool, combined_text):
    """
    Determine whether the tool explicitly communicates
    with an external actor, service, server, user, or model.

    This is intentionally separate from accesses_external.

    Example:

        fetch_web_page
            accesses_external = True
            communicates_externally = True

        send_email
            accesses_external = False
            communicates_externally = True
    """

    communication_patterns = [
        r"\bsend\b.*\bmessage\b",
        r"\bsend\b.*\brequest\b",
        r"\bsend\b.*\bdata\b",
        r"\bsend\b.*\bemail\b",
        r"\bsend\b.*\bnotification\b",
        r"\bsend\b.*\bresponse\b",
        r"\bserver\b.*\brequest\b",
        r"\brequest\b.*\buser\b",
        r"\buser\b.*\brequest\b",
        r"\buser elicitation\b",
        r"\belicitation request\b",
        r"\bsampling request\b",
        r"\bcommunicate\b.*\bwith\b",
        r"\bcommunication\b.*\bwith\b",
        r"\bexternal interaction\b",
        r"\btrigger\b.*\b(elicitation|sampling)\b",
        r"\bcall\b.*\bapi\b",
        r"\bapi\b.*\bcall\b",
        r"\bcall\b.*\bservice\b",
        r"\bcontact\b.*\bserver\b",
        r"\bnotify\b.*\buser\b",
    ]

    return matches_patterns(
        combined_text,
        communication_patterns
    )