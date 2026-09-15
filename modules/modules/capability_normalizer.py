"""
capability_normalizer — canonical normalization vocabulary (canon_normalizer)

Normalizes raw tool expressions (name + description) into the canonical
C1-C6 capability concepts, following the Capability Ontology Mapper design:

1. Lexicon (capability_lexicon/*.json): each rule is one signal — a regex pattern searched in the
   tool's assumed_capability (name + description), pointing to a capability
   with a reason and a base confidence (High / Medium / Low).
2. Multi-label matching: every rule is checked independently; one tool can
   collect several capabilities. If several rules hit the same capability,
   only the strongest (highest-confidence) hit is kept.
3. Hint cross-checks (supporting evidence, never ground truth):
   - readOnlyHint = true contradicts write-side capabilities (C3-C6)
     -> confidence lowered one step, note recorded.
   - openWorldHint = true supports external-facing capabilities (C1, C3)
     -> confidence raised one step.
   - destructiveHint = true confirms C4 -> confidence forced to High.
4. Hint-only fallbacks (Low confidence, manual-review queue):
   - openWorldHint = true with no C1/C3 match -> tag C1 (Low).
   - readOnlyHint = false plus a mutating verb -> tag C4 (Low).
5. UNMAPPED: nothing matched -> primary_capability = None.

Exports (used by module_3_capability_normalization):
    normalize_tool(tool) -> dict
    get_normalization_matches(tool) -> list
"""

import re

# ---------------------------------------------------------------------------
# Canonical C1-C6 concepts (must stay in sync with Module 4's ontology)
# ---------------------------------------------------------------------------

CANONICAL_CONCEPTS = {
    "C1": "External Data Ingestion",
    "C2": "Sensitive Data Access",
    "C3": "External Communication",
    "C4": "State Modification",
    "C5": "System Execution",
    "C6": "Physical Actuation",
}

# Confidence levels and one-step raise/lower
CONFIDENCE_SCORES = {"High": 1.0, "Medium": 0.7, "Low": 0.4}
_LEVELS = ["Low", "Medium", "High"]


def _raise_level(level):
    idx = _LEVELS.index(level)
    return _LEVELS[min(idx + 1, len(_LEVELS) - 1)]


def _lower_level(level):
    idx = _LEVELS.index(level)
    return _LEVELS[max(idx - 1, 0)]


# ---------------------------------------------------------------------------
# Lexical rules are NOT defined in Python.
#
# They live in capability_lexicon/*.json (one labelled file per capability)
# and are read through modules/capability_lexicon_loader.py. There is no
# hardcoded fallback lexicon: if a file is missing or malformed, LexiconError
# propagates so the UI can show a clear error instead of silently analysing
# with different rules.
#
# The fixed C1-C6 ontology above is unchanged.
# ---------------------------------------------------------------------------

from modules.capability_lexicon_loader import (
    LEXICON_FILES,
    LexiconError,
    lexicon_path,
    load_rules,
)

_RULES_CACHE = {"signature": None, "compiled": None}


def _lexicon_signature():
    """Modification stamp of the lexicon files, so edits are picked up."""
    stamp = []

    for capability_id in sorted(LEXICON_FILES):
        path = lexicon_path(capability_id)
        stamp.append(
            (
                capability_id,
                path.stat().st_mtime_ns if path.exists() else None,
            )
        )

    return tuple(stamp)


def load_active_rules():
    """Return the lexical rules currently defined in capability_lexicon/.

    Returns:
        list[tuple]: (capability_id, pattern, reason, confidence)
    """
    return load_rules()


def _compiled_active_rules():
    """Compile the external lexicon, caching until a rule file changes."""
    signature = _lexicon_signature()

    if (
        _RULES_CACHE["compiled"] is not None
        and _RULES_CACHE["signature"] == signature
    ):
        return _RULES_CACHE["compiled"]

    compiled = []

    for cap, pattern, reason, confidence in load_active_rules():
        try:
            compiled.append(
                (cap, re.compile(pattern, re.IGNORECASE), reason, confidence)
            )
        except re.error as error:
            raise LexiconError(
                "Invalid regular expression in the {} lexicon: {!r} ({})".format(
                    cap, pattern, error
                )
            )

    _RULES_CACHE["signature"] = signature
    _RULES_CACHE["compiled"] = compiled

    return compiled


# Mutating verbs used by the readOnlyHint=false fallback
_MUTATING_VERBS = re.compile(
    r"\b(toggle|start|stop|restart|reset|switch|activate|deactivate)\b",
    re.IGNORECASE,
)

# Severity order used only to break confidence ties for primary capability
_SEVERITY_ORDER = ["C5", "C6", "C3", "C2", "C4", "C1"]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_normalization_matches(tool):
    """
    Run the canon_normalizer lexicon over one tool.

    Args:
        tool (dict): Tool with at least 'tool' and 'description'
                     (and optionally 'assumed_capability' and MCP hints).

    Returns:
        list[dict]: One match per capability, strongest hit kept:
            {
                "capability_id": "C4",
                "canonical": "State Modification",
                "matched_expression": "write",
                "confidence": 1.0,
                "confidence_level": "High",
                "reason": "...",
                "hint_adjustments": ["..."]
            }
    """
    text = tool.get("assumed_capability") or "{} {}".format(
        tool.get("tool", ""), tool.get("description", "")
    )
    text = text.strip()

    # 1-2. Rule matching, multi-label, strongest hit per capability
    best = {}  # capability_id -> match dict
    for cap_id, regex, reason, base_level in _compiled_active_rules():
        m = regex.search(text)
        if not m:
            continue
        candidate = {
            "capability_id": cap_id,
            "canonical": CANONICAL_CONCEPTS[cap_id],
            "matched_expression": m.group(0).strip().lower(),
            "confidence_level": base_level,
            "reason": reason,
            "hint_adjustments": [],
        }
        current = best.get(cap_id)
        if current is None or (
            CONFIDENCE_SCORES[base_level]
            > CONFIDENCE_SCORES[current["confidence_level"]]
        ):
            best[cap_id] = candidate

    # 3. Hint cross-checks (supporting evidence, never ground truth)
    read_only = tool.get("readOnlyHint")
    open_world = tool.get("openWorldHint")
    destructive = tool.get("destructiveHint")

    for cap_id, match in best.items():
        if read_only is True and cap_id in ("C3", "C4", "C5", "C6"):
            match["confidence_level"] = _lower_level(match["confidence_level"])
            match["hint_adjustments"].append(
                "readOnlyHint=true contradicts write-side capability -> lowered one step"
            )
        if open_world is True and cap_id in ("C1", "C3"):
            match["confidence_level"] = _raise_level(match["confidence_level"])
            match["hint_adjustments"].append(
                "openWorldHint=true supports external-facing capability -> raised one step"
            )
        if destructive is True and cap_id == "C4":
            match["confidence_level"] = "High"
            match["hint_adjustments"].append(
                "destructiveHint=true confirms C4 -> confidence forced to High"
            )

    if read_only is False and "C4" not in best and _MUTATING_VERBS.search(text):
        verb = _MUTATING_VERBS.search(text).group(0).lower()
        best["C4"] = {
            "capability_id": "C4",
            "canonical": CANONICAL_CONCEPTS["C4"],
            "matched_expression": verb,
            "confidence_level": "Low",
            "reason": (
                "Hint-only fallback: readOnlyHint=false plus mutating verb "
                "'{}' — possible state change; needs manual review.".format(verb)
            ),
            "hint_adjustments": [],
        }

    # Finalize numeric confidence
    matches = []
    for cap_id in sorted(best.keys()):
        match = best[cap_id]
        match["confidence"] = CONFIDENCE_SCORES[match["confidence_level"]]
        matches.append(match)

    return matches


def normalize_tool(tool):
    """
    Normalize a single tool into canonical C1-C6 concepts.

    Args:
        tool (dict): Tool from Module 2 with 'assumed_capability',
                     MCP hints, and 'capability_features'.

    Returns:
        dict: {
            "primary_capability": "C4" or None (UNMAPPED),
            "all_capabilities": ["C4", ...],
            "normalized_matches": [ ...match dicts... ],
            "confidence_score": 1.0,
            "evidence": "..."
        }
    """
    matches = get_normalization_matches(tool)

    if not matches:
        # 5. UNMAPPED — pure computation like echo / get-sum
        return {
            "primary_capability": None,
            "all_capabilities": [],
            "normalized_matches": [],
            "confidence_score": 1.0,
            "evidence": "UNMAPPED: no canonical capability expression matched (pure computation/demo tool).",
        }

    # Primary = highest confidence; ties broken by severity order
    def sort_key(m):
        return (
            -m["confidence"],
            _SEVERITY_ORDER.index(m["capability_id"]),
        )

    ordered = sorted(matches, key=sort_key)
    primary = ordered[0]

    evidence_parts = []
    for m in ordered:
        part = "{} {} via '{}' ({})".format(
            m["capability_id"], m["canonical"], m["matched_expression"], m["confidence_level"]
        )
        if m["hint_adjustments"]:
            part += " [{}]".format("; ".join(m["hint_adjustments"]))
        evidence_parts.append(part)

    return {
        "primary_capability": primary["capability_id"],
        "all_capabilities": [m["capability_id"] for m in ordered],
        "normalized_matches": ordered,
        "confidence_score": primary["confidence"],
        "evidence": "; ".join(evidence_parts),
    }
