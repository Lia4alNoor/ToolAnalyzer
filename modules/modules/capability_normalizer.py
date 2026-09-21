"""
capability_normalizer — canonical normalization vocabulary (canon_normalizer)

Normalizes raw tool expressions (name + description) into the canonical
C1-C6 capability concepts, following the Capability Ontology Mapper design.

EVIDENCE MODEL — two independent channels, additively scored
-----------------------------------------------------------
Every capability assignment is scored from two independent evidence channels.
Neither channel is treated as ground truth on its own.

  1. Description channel (lexical).
     capability_lexicon/*.json — each rule is one signal: a regex pattern
     searched in the tool's assumed_capability (name + description), pointing
     to a capability with a reason and a base confidence
     (High / Medium / Low).
         High = 0.45, Medium = 0.30, Low = 0.20   (W_DESC)

  2. Metadata channel (server-declared MCP annotations).
     A supporting hint contributes a single flat weight:
         0.50   (W_META)
     This sits one notch ABOVE the strongest description evidence (0.45):
     an explicit machine-readable declaration is treated as marginally
     stronger evidence than wording inferred from prose. This ordering holds
     for honest servers only — a malicious author controls both channels.

Combination rules:
     description only         -> 0.20 / 0.30 / 0.45   (source "lexical")
     metadata only            -> 0.50                 (source "metadata")
     both channels in line    -> 1.00 = FULL_SCORE    (source "both")
     metadata contradicts     -> 0.00                 (source "contradicted")

  - Metadata can CREATE a capability that no lexical rule matched
    (see META_ASSIGNS). Under the previous design a hint could only nudge
    confidence on a label the description had already produced, which made the
    metadata channel analytically inert.
  - A contradicting hint is an OVERRIDE, not a subtraction: the score is forced
    to 0.00 regardless of how strong the description evidence was, and
    regardless of any supporting hint on the same capability. Contradicted
    capabilities are excluded from 'all_capabilities' and returned separately
    under 'suppressed_matches' so nothing is silently discarded.
  - Because a contradiction is unconditional, a tool declaring both
    destructiveHint=true and readOnlyHint=true scores C4 = 0.00 and is flagged
    with hint_conflict=True. That is a deliberate false-negative trade: an
    incoherent declaration is not trusted in either direction, but it is
    counted so declaration quality can be reported.

Reported bands (presentation only — the score is the primary value):
     >= 0.90 High | >= 0.45 Medium | >= 0.01 Low | below that "Contradicted"

The score is an EVIDENCE-AGREEMENT score. It is not a probability of
exploitation, an exploitability rating, or a risk score.

Pipeline behaviour:
  - Multi-label matching: every rule is checked independently; one tool can
    collect several capabilities. If several rules hit the same capability,
    only the strongest (highest base confidence) lexical hit is kept.
  - Hint-only fallback (manual-review queue): readOnlyHint=false plus a
    mutating verb tags C4. The verb itself is description evidence, so this
    scores as a Low description hit (0.20); the hint only unlocks the check.
  - UNMAPPED: nothing matched -> primary_capability = None.

Exports (used by module_3_capability_normalization and
module_5_ontology_database):
    normalize_tool(tool) -> dict
    get_normalization_matches(tool) -> list
    load_active_rules() -> list[tuple]
    _band(score) -> str
"""

import re

# ---------------------------------------------------------------------------
# Canonical C1-C6 concepts (must stay in sync with Module 5's ontology seed)
# ---------------------------------------------------------------------------
CANONICAL_CONCEPTS = {
    "C1": "External Data Ingestion",
    "C2": "Sensitive Data Access",
    "C3": "External Communication",
    "C4": "State Modification",
    "C5": "System Execution",
    "C6": "Physical Actuation",
}

# ---------------------------------------------------------------------------
# Scoring weights
#
# W_DESC   : description (lexical) channel, keyed by the rule's base confidence
#            as declared in capability_lexicon/*.json.
# W_META   : metadata (MCP annotation) channel — flat weight for one
#            supporting hint. Deliberately > max(W_DESC) so that metadata
#            alone outranks description alone ("one extra score").
# FULL_SCORE       : awarded when both channels agree on the same capability.
# CONTRADICTED_SCORE : forced score when a hint contradicts the capability.
#
# Sensitivity note: these weights are a judgement call, not a derivation.
# Re-run the corpus at W_META in {0.40, 0.50, 0.60} and confirm that Module 6
# composition matches stay stable; instability is itself a reportable finding.
# ---------------------------------------------------------------------------
W_DESC = {"High": 0.45, "Medium": 0.30, "Low": 0.20}
W_META = 0.50
FULL_SCORE = 1.00
CONTRADICTED_SCORE = 0.00

# Any capability scoring below this is excluded from 'all_capabilities' and
# reported under 'suppressed_matches' instead.
INCLUSION_THRESHOLD = 0.01

# Presentation bands, highest first. Anything below the last threshold is
# "Contradicted" (i.e. zeroed by a metadata contradiction).
BANDS = (
    (0.90, "High"),
    (0.45, "Medium"),
    (0.01, "Low"),
)


def _band(score):
    """Map a numeric evidence-agreement score onto its reported band.

    Also used by module_5_ontology_database to write the TEXT
    tool_capabilities.confidence column.
    """
    for threshold, label in BANDS:
        if (score or 0.0) >= threshold:
            return label
    return "Contradicted"


# ---------------------------------------------------------------------------
# Metadata channel: which MCP annotation says what about which capability.
#
# META_SUPPORTS   : hint corroborates the capability -> contributes W_META.
# META_ASSIGNS    : hint is strong enough to CREATE the capability when no
#                   lexical rule matched. Narrower than META_SUPPORTS on
#                   purpose: openWorldHint alone justifies C1 (ingestion from
#                   an open world) but must not manufacture C3 (an
#                   exfiltration channel), which would be a costly
#                   false positive.
# META_CONTRADICTS: hint is incompatible with the capability -> score forced
#                   to CONTRADICTED_SCORE.
#
# idempotentHint is intentionally unused: it describes repeat-call safety,
# not capability presence.
# ---------------------------------------------------------------------------
META_SUPPORTS = {
    "destructiveHint": ("C4",),
    "openWorldHint": ("C1", "C3"),
}

META_ASSIGNS = {
    "destructiveHint": ("C4",),
    "openWorldHint": ("C1",),
}

META_CONTRADICTS = {
    "readOnlyHint": ("C3", "C4", "C5", "C6"),
}

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

# Severity order used only to break score ties when picking the primary
# capability
_SEVERITY_ORDER = ["C5", "C6", "C3", "C2", "C4", "C1"]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def get_normalization_matches(tool):
    """
    Run the canon_normalizer lexicon and the metadata channel over one tool.

    Args:
        tool (dict): Tool with at least 'tool' and 'description'
                     (and optionally 'assumed_capability' and MCP hints).

    Returns:
        list[dict]: One match per capability, including contradicted ones
            (score 0.00) so that suppression is auditable. Callers decide
            what to keep — normalize_tool() applies INCLUSION_THRESHOLD.
            {
                "capability_id": "C4",
                "canonical": "State Modification",
                "matched_expression": "write",
                "confidence": 1.0,            # evidence-agreement score
                "confidence_level": "High",   # reported band
                "source": "both",             # lexical | metadata | both
                                              #   | contradicted
                "score_breakdown": {
                    "description": 0.45,
                    "metadata": 0.50,
                    "contradicted": False,
                },
                "hint_conflict": False,       # supporting + contradicting
                                              #   hints on one capability
                "reason": "...",
                "hint_adjustments": ["..."]
            }
    """
    text = tool.get("assumed_capability") or "{} {}".format(
        tool.get("tool", ""), tool.get("description", "")
    )
    text = text.strip()

    # ------------------------------------------------------------------
    # 1. Description channel: rule matching, multi-label, strongest
    #    lexical hit per capability.
    # ------------------------------------------------------------------
    best = {}  # capability_id -> match dict
    for cap_id, regex, reason, base_level in _compiled_active_rules():
        m = regex.search(text)
        if not m:
            continue
        candidate = {
            "capability_id": cap_id,
            "canonical": CANONICAL_CONCEPTS[cap_id],
            "matched_expression": m.group(0).strip().lower(),
            # desc_level is the rule's declared base confidence; it feeds
            # W_DESC in the scoring pass below. None means "no description
            # evidence" (metadata-assigned capability).
            "desc_level": base_level,
            "reason": reason,
            "hint_adjustments": [],
        }
        current = best.get(cap_id)
        if current is None or (
            W_DESC[base_level] > W_DESC[current["desc_level"]]
        ):
            best[cap_id] = candidate

    # ------------------------------------------------------------------
    # 2. Hint-only fallback (manual-review queue).
    #    readOnlyHint=false plus a mutating verb tags C4. The verb is
    #    description evidence, so this enters the description channel at
    #    Low; the hint merely authorizes the check.
    # ------------------------------------------------------------------
    read_only = tool.get("readOnlyHint")
    if read_only is False and "C4" not in best:
        verb_match = _MUTATING_VERBS.search(text)
        if verb_match:
            verb = verb_match.group(0).lower()
            best["C4"] = {
                "capability_id": "C4",
                "canonical": CANONICAL_CONCEPTS["C4"],
                "matched_expression": verb,
                "desc_level": "Low",
                "reason": (
                    "Hint-only fallback: readOnlyHint=false plus mutating verb "
                    "'{}' — possible state change; needs manual review.".format(verb)
                ),
                "hint_adjustments": [
                    "readOnlyHint=false plus mutating verb '{}' -> C4 queued "
                    "for manual review".format(verb)
                ],
            }

    # ------------------------------------------------------------------
    # 3. Metadata channel: collect which capabilities the declared hints
    #    support and which they contradict.
    # ------------------------------------------------------------------
    supports = {}     # capability_id -> [hint names]
    contradicts = {}  # capability_id -> [hint names]

    for hint_name, capability_ids in META_SUPPORTS.items():
        if tool.get(hint_name) is True:
            for cap_id in capability_ids:
                supports.setdefault(cap_id, []).append(hint_name)

    for hint_name, capability_ids in META_CONTRADICTS.items():
        if tool.get(hint_name) is True:
            for cap_id in capability_ids:
                contradicts.setdefault(cap_id, []).append(hint_name)

    # 3a. Metadata may CREATE a capability the description never mentioned.
    #     A hint that also contradicts the same capability never assigns it.
    for hint_name, capability_ids in META_ASSIGNS.items():
        if tool.get(hint_name) is not True:
            continue
        for cap_id in capability_ids:
            if cap_id in best or cap_id in contradicts:
                continue
            best[cap_id] = {
                "capability_id": cap_id,
                "canonical": CANONICAL_CONCEPTS[cap_id],
                "matched_expression": "{}=true".format(hint_name),
                "desc_level": None,  # no description evidence
                "reason": (
                    "Metadata-only assignment: the server declares "
                    "{}=true, which asserts {} even though no lexical rule "
                    "matched the tool name or description.".format(
                        hint_name, cap_id
                    )
                ),
                "hint_adjustments": [],
            }

    # ------------------------------------------------------------------
    # 4. Score each capability from the two channels.
    # ------------------------------------------------------------------
    for cap_id, match in best.items():
        desc_pts = W_DESC.get(match.get("desc_level")) or 0.0
        has_meta = cap_id in supports
        has_conflict = cap_id in contradicts

        if has_conflict:
            # Contradiction overrides all other evidence, including a
            # supporting hint on the same capability.
            score = CONTRADICTED_SCORE
            source = "contradicted"
            match["hint_adjustments"].append(
                "{}=true contradicts {} -> score forced to {:.2f}".format(
                    ", ".join(contradicts[cap_id]), cap_id, CONTRADICTED_SCORE
                )
            )
            if has_meta:
                match["hint_adjustments"].append(
                    "INCOHERENT DECLARATION: {}=true also supports {}; the "
                    "contradiction still wins".format(
                        ", ".join(supports[cap_id]), cap_id
                    )
                )
        elif desc_pts > 0.0 and has_meta:
            # Both channels in line -> full score.
            score = FULL_SCORE
            source = "both"
            match["hint_adjustments"].append(
                "{}=true agrees with the description evidence -> full "
                "score".format(", ".join(supports[cap_id]))
            )
        elif has_meta:
            score = W_META
            source = "metadata"
            match["hint_adjustments"].append(
                "{}=true is the only evidence for {}".format(
                    ", ".join(supports[cap_id]), cap_id
                )
            )
        else:
            score = desc_pts
            source = "lexical"

        match["confidence"] = round(score, 3)
        match["confidence_level"] = _band(score)
        match["source"] = source
        match["score_breakdown"] = {
            "description": round(desc_pts, 3),
            "metadata": W_META if has_meta else 0.0,
            "contradicted": has_conflict,
        }
        # True only when the server declares supporting AND contradicting
        # hints for the same capability — a declaration-quality signal, not
        # a capability signal.
        match["hint_conflict"] = bool(has_conflict and has_meta)

    return [best[cap_id] for cap_id in sorted(best.keys())]


def normalize_tool(tool):
    """
    Normalize a single tool into canonical C1-C6 concepts.

    Args:
        tool (dict): Tool from Module 2 with 'assumed_capability' and
                     MCP hints.

    Returns:
        dict: {
            "primary_capability": "C4" or None (UNMAPPED),
            "all_capabilities": ["C4", ...],   # retained only
            "normalized_matches": [ ...match dicts... ],
            "suppressed_matches": [ ...contradicted match dicts... ],
            "capability_sources": {"C4": "both", ...},
            "confidence_score": 1.0,
            "evidence": "..."
        }

        Capabilities zeroed by a metadata contradiction are NOT included in
        'all_capabilities' or 'normalized_matches'; they are returned under
        'suppressed_matches' so the decision stays visible to Module 9 and to
        manual review. Downstream modules that key on capability presence
        (Module 6) therefore never see them.
    """
    scored = get_normalization_matches(tool)

    retained = [m for m in scored if m["confidence"] >= INCLUSION_THRESHOLD]
    suppressed = [m for m in scored if m["confidence"] < INCLUSION_THRESHOLD]

    if not retained:
        # UNMAPPED — either nothing matched (pure computation like
        # echo / get-sum), or every candidate capability was contradicted by
        # the declared metadata.
        if suppressed:
            evidence = (
                "UNMAPPED: every candidate capability was contradicted by the "
                "declared metadata ({}).".format(
                    ", ".join(
                        "{} [{}]".format(m["capability_id"],
                                         "; ".join(m["hint_adjustments"]))
                        for m in suppressed
                    )
                )
            )
        else:
            evidence = (
                "UNMAPPED: no canonical capability expression matched "
                "(pure computation/demo tool)."
            )
        return {
            "primary_capability": None,
            "all_capabilities": [],
            "normalized_matches": [],
            "suppressed_matches": suppressed,
            "capability_sources": {},
            # Certainty that nothing was assigned — NOT a capability score.
            "confidence_score": 1.0,
            "evidence": evidence,
        }

    # Primary = highest evidence-agreement score; ties broken by severity
    def sort_key(m):
        return (
            -m["confidence"],
            _SEVERITY_ORDER.index(m["capability_id"]),
        )

    ordered = sorted(retained, key=sort_key)
    primary = ordered[0]

    evidence_parts = []
    for m in ordered + suppressed:
        part = "{} {} via '{}' ({}, {:.2f}, source={})".format(
            m["capability_id"],
            m["canonical"],
            m["matched_expression"],
            m["confidence_level"],
            m["confidence"],
            m["source"],
        )
        if m["hint_adjustments"]:
            part += " [{}]".format("; ".join(m["hint_adjustments"]))
        if m["confidence"] < INCLUSION_THRESHOLD:
            part += " {SUPPRESSED: excluded from capability profile}"
        evidence_parts.append(part)

    return {
        "primary_capability": primary["capability_id"],
        "all_capabilities": [m["capability_id"] for m in ordered],
        "normalized_matches": ordered,
        "suppressed_matches": suppressed,
        "capability_sources": {m["capability_id"]: m["source"] for m in ordered},
        "confidence_score": primary["confidence"],
        "evidence": "; ".join(evidence_parts),
    }
