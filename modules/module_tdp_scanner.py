"""Simple Tool Description Poisoning (TDP) scanner.

Heuristic scan of *declared* tool names and descriptions only.
This is not a complete TDP detector, does not connect to a live MCP
server, and does not inspect implementation.

A hit means the declared text *resembles* literature TDP / prompt-injection
phrasing (P7). It is not proof that the tool is poisoned.
"""
import re
import unicodedata

SCANNER_SCOPE = (
    "TDP scanner: declared name + description text only. "
    "Heuristic patterns, not a model and not a code audit."
)

ZERO_WIDTH = [
    "\u200b",  # zero-width space
    "\u200c",  # zero-width non-joiner
    "\u200d",  # zero-width joiner
    "\u2060",  # word joiner
    "\ufeff",  # BOM
    "\u00ad",  # soft hyphen
]

PATTERNS = [
    (
        "instruction_override",
        r"ignore (all )?(previous|prior|above) (instructions?|prompts?)",
        "High",
        "Description tries to override prior instructions.",
    ),
    (
        "hidden_from_user",
        r"do not (tell|inform|mention|reveal|show) (the )?user",
        "High",
        "Description asks the model to hide behaviour from the user.",
    ),
    (
        "forced_behavior",
        r"\byou (must|should always|are required to)\b",
        "Medium",
        "Description issues an imperative to the model rather than describing the tool.",
    ),
    (
        "system_role",
        r"\[SYSTEM\]|\[INST\]|<\|im_start\|>|<<SYS>>",
        "High",
        "Description contains chat/system role markup.",
    ),
    (
        "obfuscation_marker",
        r"obfuscat(?:ed|ion)?|prompt injection",
        "High",
        "Description contains an explicit poisoning/injection marker.",
    ),
    (
        "model_aside",
        r"\b(IMPORTANT|NOTE TO (THE )?MODEL|BEFORE USING THIS TOOL|"
        r"INSTRUCTION FOR THE ASSISTANT)\s*:",
        "High",
        "Description contains an instruction block aimed at the model.",
    ),
    (
        "exfil_instruction",
        r"send (this|the) (conversation|history|secrets?) to",
        "High",
        "Description instructs sending conversation or secrets elsewhere.",
    ),
]

_COMPILED = [
    (fid, re.compile(pat, re.IGNORECASE), sev, reason)
    for fid, pat, sev, reason in PATTERNS
]


def run(input_data):
    print("Running TDP scanner (declared-text heuristics)")
    return process(input_data)


def process(data):
    if not isinstance(data, dict):
        return data

    tools = data.get("tools") or []
    all_findings = []
    flagged = 0

    for tool in tools:
        if not isinstance(tool, dict):
            continue
        findings = scan_tool(tool)
        tool["tdp_findings"] = findings
        tool["tdp_flagged"] = bool(findings)
        if findings:
            flagged += 1
            all_findings.append(
                {
                    "tool": tool.get("tool") or tool.get("tool_name") or "unknown",
                    "findings": findings,
                }
            )

    data["tdp_scan"] = {
        "scope": SCANNER_SCOPE,
        "tools_scanned": len(tools),
        "tools_flagged": flagged,
        "findings": all_findings,
        "pattern_id_reference": "P7",
        "pattern_name_reference": "Tool Description Poisoning",
        "limitation": (
            "Heuristic only. Absence of a flag is not evidence the "
            "description is clean. Presence of a flag is not confirmation "
            "of an exploit."
        ),
    }
    data["tdp_scan_complete"] = True
    print(
        f"[OK] TDP scanner: {flagged}/{len(tools)} tool(s) flagged"
    )
    return data


def scan_tool(tool):
    name = str(tool.get("tool") or tool.get("tool_name") or "")
    desc = str(tool.get("description") or tool.get("tool_content") or "")
    blob = name + "\n" + desc
    findings = []

    hidden = [c for c in ZERO_WIDTH if c in blob]
    if hidden:
        codes = ", ".join(f"U+{ord(c):04X}" for c in hidden)
        findings.append(
            {
                "id": "hidden_unicode",
                "severity": "High",
                "matched": codes,
                "reason": "Name or description contains hidden/zero-width characters.",
            }
        )

    suspicious_cf = [
        ch for ch in desc
        if unicodedata.category(ch) in {"Cf", "Cc"} and ch not in "\n\r\t"
    ]
    if suspicious_cf and not hidden:
        findings.append(
            {
                "id": "control_characters",
                "severity": "Medium",
                "matched": ", ".join(f"U+{ord(c):04X}" for c in suspicious_cf[:8]),
                "reason": "Description contains non-printing control characters.",
            }
        )

    for fid, regex, sev, reason in _COMPILED:
        match = regex.search(desc) or regex.search(name)
        if match:
            findings.append(
                {
                    "id": fid,
                    "severity": sev,
                    "matched": match.group(0),
                    "reason": reason,
                }
            )

    if len(desc) > 400 and re.search(
        r"\b(you must|ignore|do not tell|instead of)\b", desc, re.I
    ):
        findings.append(
            {
                "id": "oversized_imperative_description",
                "severity": "Medium",
                "matched": f"{len(desc)} characters",
                "reason": (
                    "Description is unusually long and contains imperative "
                    "phrasing more typical of a prompt than a tool manual."
                ),
            }
        )

    return findings
