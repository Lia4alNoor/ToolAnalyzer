"""Loader for the external capability lexicon (capability_lexicon/*.json).

The lexical rules used for capability identification live in JSON files, one
per capability, and are NOT duplicated in Python. This module is the single
place that reads them.

Design notes
------------
* The fixed C1-C6 ontology is unchanged; only the lexical rules moved.
* There is deliberately NO hardcoded fallback lexicon. If a file is missing,
  malformed, or unreadable, a LexiconError is raised so the UI can show a
  clear error instead of silently analysing with different rules.
* Rules are returned in file order, matching the original RULES ordering,
  so capability identification behaves as before.
"""
import json
from pathlib import Path

# capability_lexicon/ sits next to the modules/ package, at project root.
LEXICON_DIR = Path(__file__).resolve().parent.parent / "capability_lexicon"

# capability_id -> filename. Capability ids themselves are fixed (C1-C6).
LEXICON_FILES = {
    "C1": "C1_external_data_ingestion.json",
    "C2": "C2_sensitive_data_access.json",
    "C3": "C3_external_communication.json",
    "C4": "C4_state_modification.json",
    "C5": "C5_system_execution.json",
    "C6": "C6_physical_actuation.json",
}

VALID_CONFIDENCE = ("High", "Medium", "Low")


class LexiconError(Exception):
    """Raised when a lexical-rule file is missing or malformed."""


def lexicon_path(capability_id):
    """Absolute path of the lexical-rule file for one capability."""
    try:
        filename = LEXICON_FILES[capability_id]
    except KeyError:
        raise LexiconError(
            "Unknown capability id '{}'. Expected one of: {}".format(
                capability_id, ", ".join(sorted(LEXICON_FILES))
            )
        )
    return LEXICON_DIR / filename


def load_capability_file(capability_id):
    """Load and validate one capability's lexical-rule document.

    Returns the parsed document dict. Raises LexiconError with a message
    that names the file and the problem.
    """
    path = lexicon_path(capability_id)

    if not path.exists():
        raise LexiconError(
            "Lexical-rule file missing for {}: {}".format(capability_id, path)
        )

    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as error:
        raise LexiconError(
            "Could not read lexical-rule file {}: {}".format(path, error)
        )

    try:
        document = json.loads(raw)
    except json.JSONDecodeError as error:
        raise LexiconError(
            "Malformed JSON in {} (line {}, column {}): {}".format(
                path.name, error.lineno, error.colno, error.msg
            )
        )

    if not isinstance(document, dict):
        raise LexiconError(
            "{} must contain a JSON object at the top level.".format(path.name)
        )

    declared_id = document.get("capability_id")
    if declared_id != capability_id:
        raise LexiconError(
            "{} declares capability_id '{}' but should declare '{}'.".format(
                path.name, declared_id, capability_id
            )
        )

    rules = document.get("rules")
    if not isinstance(rules, list):
        raise LexiconError(
            "{} must contain a 'rules' array.".format(path.name)
        )

    for index, rule in enumerate(rules, start=1):
        _validate_rule(path.name, index, rule)

    return document


def _validate_rule(filename, index, rule):
    """Validate one rule entry, raising LexiconError on any problem."""
    if not isinstance(rule, dict):
        raise LexiconError(
            "{}: rule #{} must be a JSON object.".format(filename, index)
        )

    pattern = rule.get("pattern")
    if not isinstance(pattern, str) or not pattern.strip():
        raise LexiconError(
            "{}: rule #{} ({}) has an empty or non-string 'pattern'.".format(
                filename, index, rule.get("rule_id", "no rule_id")
            )
        )

    confidence = rule.get("confidence")
    if confidence not in VALID_CONFIDENCE:
        raise LexiconError(
            "{}: rule #{} ({}) has confidence '{}'. Expected one of {}.".format(
                filename,
                index,
                rule.get("rule_id", "no rule_id"),
                confidence,
                ", ".join(VALID_CONFIDENCE),
            )
        )

    reason = rule.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        raise LexiconError(
            "{}: rule #{} ({}) has an empty 'reason'.".format(
                filename, index, rule.get("rule_id", "no rule_id")
            )
        )


def load_documents():
    """Load all six capability documents as {capability_id: document}."""
    return {
        capability_id: load_capability_file(capability_id)
        for capability_id in LEXICON_FILES
    }


def load_rules():
    """Load the full lexicon as the tuple form the normalizer consumes.

    Returns:
        list[tuple]: (capability_id, pattern, reason, confidence)

    Disabled rules ("enabled": false) are skipped, so a rule can be parked
    in the file without affecting capability identification.
    """
    rules = []

    for capability_id in LEXICON_FILES:
        document = load_capability_file(capability_id)

        for rule in document["rules"]:
            if rule.get("enabled") is False:
                continue

            rules.append(
                (
                    capability_id,
                    rule["pattern"],
                    rule["reason"],
                    rule["confidence"],
                )
            )

    if not rules:
        raise LexiconError(
            "The capability lexicon contains no enabled rules. "
            "Capability identification cannot run. Checked: {}".format(
                LEXICON_DIR
            )
        )

    return rules


def save_capability_rules(capability_id, rules, notes=None):
    """Write edited rules back to that capability's lexical-rule file.

    Args:
        capability_id (str): C1-C6.
        rules (list[dict]): Rule dicts (pattern / reason / confidence / ...).
        notes (str | None): Optional replacement for the document notes.

    The existing document is loaded first so capability_id, capability_name,
    and schema metadata are preserved. Rules are validated before writing,
    so a bad edit fails loudly instead of corrupting the file.
    """
    document = load_capability_file(capability_id)
    path = lexicon_path(capability_id)

    cleaned = []
    for index, rule in enumerate(rules, start=1):
        _validate_rule(path.name, index, rule)

        cleaned.append(
            {
                "rule_id": rule.get("rule_id")
                or "{}-R{:02d}".format(capability_id, index),
                "category": rule.get("category") or "lexical_regex",
                "match_scope": rule.get("match_scope")
                or "tool_name_and_description",
                "pattern": rule["pattern"],
                "reason": rule["reason"],
                "confidence": rule["confidence"],
                "enabled": bool(rule.get("enabled", True)),
            }
        )

    document["rules"] = cleaned
    if notes:
        document["notes"] = notes

    path.write_text(
        json.dumps(document, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    # Verify that the exact file we just wrote can be
    # immediately reloaded and contains the new rules.
    verify = load_capability_file(capability_id)

    if verify["rules"] != cleaned:
        raise LexiconError(
            f"Lexicon save verification failed for {path}. "
            "The file was written but its contents do not match "
            "the edited rules."
        )

    return len(cleaned)
