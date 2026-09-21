"""
Module 5: Ontology Database

Persists the C1-C6 ontology, the normalizer rule lexicon, the analysed tools,
and their capability mappings into an SQLite database (capability_ontology.db).

Follows the create_ontology_db design:
- Four tables: capabilities, mapping_rules, tools, tool_capabilities.
- The tool_capabilities.source column distinguishes 'manual' (hand-labelled
  manual validation set) from 'mapper' (pipeline verdicts) so mapper
  accuracy can be measured against the manually labelled reference.
- Safe to re-run: nothing is duplicated.

Confidence storage: tool_capabilities.confidence is a TEXT band
(High / Medium / Low), while the normalizer produces a numeric
evidence-agreement score. The conversion goes through
capability_normalizer._band(), which is the single source of truth for the
score-to-band thresholds. Never re-implement those thresholds here.

Input:  Module 3 output (tools with C1-C6 mappings)
Output: same data, plus database metadata under 'ontology_db'
"""

import json
import sqlite3
from pathlib import Path

# Lexical rules live in capability_lexicon/*.json and are read through
# capability_normalizer.load_active_rules() (same tuple shape as the old
# in-code RULES list, same rules). _band() converts the normalizer's numeric
# evidence-agreement score into the TEXT band stored in the database.
from modules.modules.capability_normalizer import (
    _band,
    load_active_rules,
)

DB_PATH = Path(__file__).parent / "capability_ontology.db"

# C1-C6 ontology with example abuse scenarios
CAPABILITY_SEED = [
    ("C1", "External Data Ingestion",
     "Ability to retrieve or ingest data/content from external or potentially untrusted sources into the agent's context.",
     "Attacker-controlled content enters the agent -> prompt injection."),
    ("C2", "Sensitive Data Access",
     "Ability to read or retrieve private, sensitive, local, or user-specific data.",
     "Private data becomes available to steal."),
    ("C3", "External Communication",
     "Ability to transmit, send, publish, or communicate data to an external service, endpoint, or recipient.",
     "The exfiltration channel - data can leave."),
    ("C4", "State Modification",
     "Ability to create, modify, update, or delete persistent system/application/environment state.",
     "Attacker changes survive the session."),
    ("C5", "System Execution",
     "Ability to execute commands, scripts, programs, or code on the underlying system/environment.",
     "Full environment compromise."),
    ("C6", "Physical Actuation",
     "Ability to control hardware, IoT devices, or physical systems causing real-world changes.",
     "Physical harm."),
]

# Manually labelled validation set (source='manual'): reference tools with
# known-correct C1-C6 labels, used to measure mapper accuracy
MANUAL_VALIDATION_SET = [
    ("fetch", "Fetches a URL from the internet", [("C1", "High", "Retrieves external web content into the agent context.")]),
    ("read_mail", "Reads messages from the user's mailbox", [("C2", "High", "Reads private mail contents.")]),
    ("send_mail", "Sends an email to a recipient", [("C3", "High", "Transmits data to an external recipient.")]),
    ("create_issue", "Creates an issue on an external tracker", [
        ("C3", "High", "Data leaves the system to an external tracker."),
        ("C4", "High", "Creates a persistent record.")]),
    ("execute-command", "Executes a shell command", [("C5", "High", "Runs commands on the underlying system.")]),
    ("AugustSmartLockUnlockDoor", "Unlocks the front door smart lock", [("C6", "High", "Controls a physical lock.")]),
    ("calculate", "Evaluates an arithmetic expression", []),  # UNMAPPED
]


def run(input_data):
    """
    Main entry point for Module 5: Ontology Database

    Args:
        input_data (dict): Output from Module 3 (tools with 'mapping')

    Returns:
        dict: input data plus 'ontology_db' metadata
    """
    print("=" * 70)
    print("Module 5: Ontology Database")
    print("=" * 70)

    result = process(input_data)
    return result


def process(data):
    if not data:
        return None

    conn = sqlite3.connect(DB_PATH)
    try:
        _create_tables(conn)
        _ensure_cia_columns(conn)
        _seed_capabilities(conn)
        _seed_rules(conn)
        _seed_manual_validation_set(conn)
        _seed_attack_patterns(conn)

        tools = data.get('tools', [])
        source_file = data.get('source_file') or 'unknown'
        stored = 0
        for tool in tools:
            _store_tool_with_mappings(conn, tool, source_file)
            stored += 1
        conn.commit()

        counts = _report(conn)
    finally:
        conn.close()

    result = dict(data)
    result['ontology_db'] = {
        'db_path': str(DB_PATH),
        'tools_stored': stored,
        **counts,
    }
    result['ontology_db_complete'] = True

    print(f"\n\u2713 Ontology database updated: {DB_PATH.name} "
          f"({stored} tools stored from {source_file})")
    return result


def _create_tables(conn):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS capabilities (
            capability_id TEXT PRIMARY KEY,
            name          TEXT NOT NULL,
            definition    TEXT NOT NULL,
            example_risk  TEXT
        );
        CREATE TABLE IF NOT EXISTS mapping_rules (
            rule_id       INTEGER PRIMARY KEY AUTOINCREMENT,
            capability_id TEXT NOT NULL REFERENCES capabilities(capability_id),
            pattern       TEXT NOT NULL,
            reason        TEXT NOT NULL,
            confidence    TEXT NOT NULL,
            UNIQUE (capability_id, pattern)
        );
        CREATE TABLE IF NOT EXISTS tools (
            tool_id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name            TEXT NOT NULL,
            description     TEXT,
            server_source   TEXT,
            read_only_hint  INTEGER,
            destructive_hint INTEGER,
            idempotent_hint INTEGER,
            open_world_hint INTEGER,
            UNIQUE (name, server_source)
        );
        CREATE TABLE IF NOT EXISTS tool_capabilities (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            tool_id       INTEGER NOT NULL REFERENCES tools(tool_id),
            capability_id TEXT NOT NULL REFERENCES capabilities(capability_id),
            confidence    TEXT NOT NULL,   -- High | Medium | Low band from capability_normalizer._band()
            reason        TEXT,
            source        TEXT NOT NULL CHECK (source IN ('manual', 'mapper')),
            UNIQUE (tool_id, capability_id, source)
        );
        CREATE TABLE IF NOT EXISTS attack_patterns (
            pattern_id           TEXT PRIMARY KEY,
            pattern_name         TEXT NOT NULL,
            capability_sequence  TEXT,          -- ordered JSON array e.g. ["C1","C2","C3"]; NULL when order not established
            attack_goal          TEXT,
            supporting_papers    TEXT,
            evidence_type        TEXT,          -- DIRECT | PARTIAL
            confidence           TEXT,          -- High | Medium | Low (literature confidence)
            evidence_summary     TEXT,
            module_6_eligibility TEXT NOT NULL,  -- ELIGIBLE | ELIGIBLE_SYNTHESIZED | NOT_ELIGIBLE
            severity             TEXT,           -- project-defined risk ranking (NOT a literature claim)
            confidentiality_impact NUMERIC,      -- 0-3, 'IE', or 'EXCLUDED'; project-derived impact, NOT probability/exploitability
            integrity_impact       NUMERIC,
            availability_impact    NUMERIC,
            cia_total              NUMERIC,      -- C+I+A for numeric scores; 'IE'; 'N/A' (P7). CIA IMPACT TOTAL, not a risk score.
            cia_evidence_type      TEXT,         -- PROJECT-DERIVED | INSUFFICIENT_EVIDENCE | EXCLUDED
            cia_rationale          TEXT
        );
    """)


def _seed_capabilities(conn):
    conn.executemany(
        "INSERT OR REPLACE INTO capabilities (capability_id, name, definition, example_risk) VALUES (?, ?, ?, ?)",
        CAPABILITY_SEED,
    )


def _seed_rules(conn):
    """Copy the exact rule lexicon out of capability_normalizer so the
    codebook version is stored with the results. The confidence stored here
    is the rule's DECLARED base confidence (the description channel's input),
    not a scored verdict."""
    conn.executemany(
        "INSERT OR IGNORE INTO mapping_rules (capability_id, pattern, reason, confidence) VALUES (?, ?, ?, ?)",
        [(cap, pattern, reason, confidence) for cap, pattern, reason, confidence in load_active_rules()],
    )


def _seed_manual_validation_set(conn):
    for name, description, labels in MANUAL_VALIDATION_SET:
        tool_id = _upsert_tool(conn, name, description, 'manual_validation_set', None, None, None, None)
        for capability_id, confidence, reason in labels:
            conn.execute(
                """INSERT OR REPLACE INTO tool_capabilities
                   (tool_id, capability_id, confidence, reason, source)
                   VALUES (?, ?, ?, ?, 'manual')""",
                (tool_id, capability_id, confidence, reason),
            )


def _upsert_tool(conn, name, description, server_source, ro, de, idem, ow):
    def as_int(v):
        return None if v is None else int(bool(v))
    conn.execute(
        """INSERT INTO tools (name, description, server_source,
                              read_only_hint, destructive_hint, idempotent_hint, open_world_hint)
           VALUES (?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT (name, server_source) DO UPDATE SET
               description = excluded.description,
               read_only_hint = excluded.read_only_hint,
               destructive_hint = excluded.destructive_hint,
               idempotent_hint = excluded.idempotent_hint,
               open_world_hint = excluded.open_world_hint""",
        (name, description, server_source, as_int(ro), as_int(de), as_int(idem), as_int(ow)),
    )
    row = conn.execute(
        "SELECT tool_id FROM tools WHERE name = ? AND server_source = ?",
        (name, server_source),
    ).fetchone()
    return row[0]


def _numeric_to_level(score):
    """Convert a numeric evidence-agreement score into its TEXT band.

    Delegates to capability_normalizer._band() so the thresholds live in
    exactly one place. Note this is a BAND lookup, not an exact-value match:
    the normalizer emits many distinct scores (0.20 / 0.30 / 0.45 / 0.50 /
    1.00) and any future weight change must not silently collapse them all
    to 'Low' here.
    """
    return _band(score)


def _store_tool_with_mappings(conn, tool, server_source):
    tool_id = _upsert_tool(
        conn,
        tool.get('tool'),
        tool.get('description'),
        server_source,
        tool.get('readOnlyHint'),
        tool.get('destructiveHint'),
        tool.get('idempotentHint'),
        tool.get('openWorldHint'),
    )
    mapping = tool.get('mapping', {})
    # Capabilities zeroed by a metadata contradiction are already filtered out
    # upstream by normalize_tool(), so they never reach tool_capabilities.
    # They remain available on the pipeline dict under 'suppressed_matches'.
    for entry in mapping.get('mappings', []):
        conn.execute(
            """INSERT OR REPLACE INTO tool_capabilities
               (tool_id, capability_id, confidence, reason, source)
               VALUES (?, ?, ?, ?, 'mapper')""",
            (tool_id, entry['capability_id'],
             _numeric_to_level(entry.get('confidence')),
             entry.get('reason')),
        )


def _report(conn):
    counts = {}
    for table in ('capabilities', 'mapping_rules', 'tools', 'tool_capabilities'):
        counts[f'{table}_count'] = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    print("\nDatabase contents:")
    for key, value in counts.items():
        print(f"  {key}: {value}")
    per_cap = conn.execute(
        """SELECT capability_id, COUNT(*) FROM tool_capabilities
           WHERE source = 'mapper' GROUP BY capability_id ORDER BY capability_id"""
    ).fetchall()
    if per_cap:
        print("  mapper verdicts per capability: " + ", ".join(f"{c}={n}" for c, n in per_cap))
    return counts

# Literature-backed attack patterns (reference data read by Module 6).
# capability_sequence is an ORDERED JSON array (repeats preserved, e.g.
# ["C4","C4","C4"]); None when the literature establishes no C1-C6 order.
# severity is a project-defined risk ranking, NOT a literature claim.
# (pattern_id, pattern_name, capability_sequence, attack_goal,
#  supporting_papers, evidence_type, confidence, evidence_summary,
#  module_6_eligibility, severity)
ATTACK_PATTERN_SEED = [
    ("P1", "MCP-UPD / IPI Data Stealing", ["C1", "C2", "C3"],
     "Sensitive-data exfiltration",
     "Parasites in the Toolchain; InjecAgent", "DIRECT", "High",
     "Untrusted content is ingested, sensitive data is accessed, and the "
     "data is transmitted externally.",
     "ELIGIBLE", "Critical"),
    ("P2", "Sequential Tool Attack Chaining (STAC)", ["C4", "C4", "C4"],
     "Cumulative harm from sequential state modifications",
     "STAC", "DIRECT", "High",
     "Individually benign state modifications combine, in order, into a "
     "harmful cumulative outcome (repeated C4 steps are preserved).",
     "ELIGIBLE", "High"),
    ("P3", "Remote Command Execution via Ingestion", ["C1", "C5"],
     "Attacker-influenced command/code execution",
     "Parasites in the Toolchain", "DIRECT", "High",
     "Ingested untrusted content is followed by system execution.",
     "ELIGIBLE", "Critical"),
    ("P4", "Smart Device / IoT Hijacking", ["C1", "C6"],
     "Unauthorized physical actuation",
     "SEAgent; InjecAgent", "DIRECT", "High",
     "Ingested untrusted content is followed by physical actuation.",
     "ELIGIBLE", "Critical"),
    ("P5", "Persistent Context Takeover", ["C1", "C4", "C5"],
     "Persistent compromise of the agent environment",
     "Parasites in the Toolchain", "DIRECT", "High",
     "Ingested untrusted content is followed by persistent state "
     "modification and system execution.",
     "ELIGIBLE", "Critical"),
    ("P6", "Direct Privacy Exfiltration", ["C2", "C3"],
     "Sensitive-data transmission",
     "SEAgent; InjecAgent", "DIRECT", "High",
     "Sensitive data access is followed by external communication.",
     "ELIGIBLE", "High"),
    ("P7", "Tool Description Poisoning", None,
     "Manipulation of agent behaviour via poisoned tool metadata",
     "When the Manual Lies", "PARTIAL", "High",
     "Literature-documented attack, but no established ordered C1-C6 "
     "capability sequence; stored as evidence only.",
     "NOT_ELIGIBLE", "High"),
    ("P8", "Ingestion-to-Write", ["C1", "C4"],
     "Attacker-influenced persistent state modification",
     "MiniScope; SEAgent", "PARTIAL", "Medium",
     "Synthesized from partial evidence: ingestion of untrusted content "
     "followed by state modification.",
     "ELIGIBLE_SYNTHESIZED", "Medium"),
    ("P9", "Ingestion-to-Communication", ["C1", "C3"],
     "Attacker-influenced external communication",
     "MiniScope; SEAgent", "PARTIAL", "Medium",
     "Synthesized from partial evidence: ingestion of untrusted content "
     "followed by external communication.",
     "ELIGIBLE_SYNTHESIZED", "Medium"),
]


# Project-derived CIA impact classifications, keyed by pattern_id.
# PROJECT-DERIVED means: an analytical classification produced by THIS
# project from consequences demonstrated in the cited literature; the papers
# do not necessarily assign these numerical CIA values themselves.
# CIA describes literature-demonstrated IMPACT only - never probability,
# likelihood, exploitability, attack success, or runtime evidence.
# NOTE (resolved 2026-08-22 via source-verified evidence recheck): CIA
# values are keyed by demonstrated consequence, verified against the
# sources. P4 (C1->C6) carries the verified smart-lock/IoT impact;
# P6 (C2->C3) carries the verified confidentiality-only exfiltration
# impact; P5 remains INSUFFICIENT_EVIDENCE. The conceptual .bashrc
# startup-write is future work in its source and is not CIA-scored.
# Tuple: (confidentiality, integrity, availability, total, evidence, rationale)
CIA_IMPACT = {
    "P1": (3, 0, 0, 3, "PROJECT-DERIVED",
           "Sensitive credentials/private data are exfiltrated. The "
           "demonstrated attack does not modify local state or cause "
           "service disruption."),
    "P2": (0, 3, 3, 6, "PROJECT-DERIVED",
           "STAC demonstrates sequential destructive filesystem operations "
           "resulting in permanent loss of critical data."),
    "P3": (3, 3, 3, 9, "PROJECT-DERIVED",
           "Reverse-shell command execution can provide the attacker with "
           "the ability to read, modify, and delete resources accessible "
           "to the compromised process. Impact is bounded by the "
           "privileges/resources of the compromised host process; root or "
           "unrestricted host access is not assumed."),
    "P4": (0, 3, 2, 5, "PROJECT-DERIVED",
           "Literature demonstrates unauthorized physical/device actions "
           "such as unlocking a smart lock (SEAgent; InjecAgent). "
           "Physical-state integrity is severely affected; availability "
           "impact is moderate. The sources do not use CIA terminology; "
           "this classification is project-derived."),
    "P5": ("IE", "IE", "IE", "IE", "INSUFFICIENT_EVIDENCE",
           "The selected literature does not empirically establish the "
           "C1->C4->C5 pattern sufficiently to justify a CIA impact "
           "classification. A related startup-configuration write (e.g. "
           ".bashrc) is discussed only conceptually as future work and is "
           "not empirically evaluated."),
    "P6": (3, 0, 0, 3, "PROJECT-DERIVED",
           "Demonstrated attacks read private/stored data and transmit it "
           "outbound, resulting strictly in confidentiality loss; no "
           "file/state modification or service disruption is "
           "demonstrated."),
    "P7": ("EXCLUDED", "EXCLUDED", "EXCLUDED", "N/A", "EXCLUDED",
           "Not CIA-scored: NOT_ELIGIBLE evidence-only pattern with no "
           "established ordered sequence."),
    "P8": (0, 2, 2, 4, "PROJECT-DERIVED",
           "Literature demonstrates unauthorized local state changes such "
           "as deleting emails, modifying data, or uninstalling "
           "applications."),
    "P9": (0, 2, 0, 2, "PROJECT-DERIVED",
           "Unauthorized phishing/spam communication compromises "
           "communication authenticity/integrity but does not demonstrate "
           "confidentiality loss or service unavailability."),
}

_CIA_COLUMNS = (
    ("confidentiality_impact", "NUMERIC"),
    ("integrity_impact", "NUMERIC"),
    ("availability_impact", "NUMERIC"),
    ("cia_total", "NUMERIC"),
    ("cia_evidence_type", "TEXT"),
    ("cia_rationale", "TEXT"),
)


def _ensure_cia_columns(conn):
    """Add CIA columns to attack_patterns on pre-existing databases
    (CREATE TABLE IF NOT EXISTS cannot extend an already-created table)."""
    for col, affinity in _CIA_COLUMNS:
        try:
            conn.execute(
                f"ALTER TABLE attack_patterns ADD COLUMN {col} {affinity}")
        except sqlite3.OperationalError:
            pass  # column already exists


def _seed_attack_patterns(conn):
    """Store the literature-backed attack patterns (read by Module 6).
    capability_sequence is serialized as ordered JSON TEXT; repeats are
    preserved (e.g. ["C4","C4","C4"]). NULL means order not established."""
    rows = []
    for (pid, name, seq, goal, papers, ev_type, conf,
         summary, eligibility, severity) in ATTACK_PATTERN_SEED:
        seq_json = None if seq is None else json.dumps(seq)
        rows.append((pid, name, seq_json, goal, papers, ev_type, conf,
                     summary, eligibility, severity) + CIA_IMPACT[pid])
    conn.executemany(
        """INSERT OR IGNORE INTO attack_patterns
           (pattern_id, pattern_name, capability_sequence, attack_goal,
            supporting_papers, evidence_type, confidence, evidence_summary,
            module_6_eligibility, severity, confidentiality_impact,
            integrity_impact, availability_impact, cia_total,
            cia_evidence_type, cia_rationale)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        rows,
    )


def save_manual_capabilities(
    tool_name,
    capabilities,
    server_source="manual_review",
    confidence="High",
    reason="Human-validated capability assignment.",
):
    """
    Save a human-validated capability assignment for one tool.

    The mapper verdicts are preserved separately as source='mapper'.
    Manual assignments are stored as source='manual'.

    confidence is a TEXT band supplied by the reviewer, NOT a numeric
    evidence-agreement score: a human decision is ground truth and is not
    routed through the two-channel scoring model.

    capabilities:
        Iterable of C1-C6 capability IDs.
        An empty iterable means the tool is manually marked as unmapped.
    """
    allowed_capabilities = {
        row[0] for row in CAPABILITY_SEED
    }

    capabilities = list(dict.fromkeys(capabilities))

    invalid = set(capabilities) - allowed_capabilities
    if invalid:
        raise ValueError(
            f"Invalid capability ID(s): {sorted(invalid)}"
        )

    conn = sqlite3.connect(DB_PATH)
    try:
        _create_tables(conn)

        # Find the tool regardless of whether it originally came
        # from the mapper or another source.
        row = conn.execute(
            """
            SELECT tool_id
            FROM tools
            WHERE name = ?
            ORDER BY tool_id DESC
            LIMIT 1
            """,
            (tool_name,),
        ).fetchone()

        if row is None:
            raise ValueError(
                f"Tool '{tool_name}' was not found in the ontology database."
            )

        tool_id = row[0]

        # Remove the previous human decision for this tool.
        conn.execute(
            """
            DELETE FROM tool_capabilities
            WHERE tool_id = ?
              AND source = 'manual'
            """,
            (tool_id,),
        )

        # Empty list = explicit human decision that the tool has
        # no C1-C6 capability.
        for capability_id in capabilities:
            conn.execute(
                """
                INSERT INTO tool_capabilities
                (
                    tool_id,
                    capability_id,
                    confidence,
                    reason,
                    source
                )
                VALUES (?, ?, ?, ?, 'manual')
                """,
                (
                    tool_id,
                    capability_id,
                    confidence,
                    reason,
                ),
            )

        conn.commit()

        return {
            "tool_name": tool_name,
            "capabilities": capabilities,
            "source": "manual",
            "confidence": confidence,
            "reason": reason,
        }
    finally:
        conn.close()


def apply_manual_capability_override(tool):
    """
    Apply the latest human capability assignment to a tool.

    If a manual decision exists in the database, it overrides the
    automated mapper classification for downstream pipeline stages.
    An empty manual capability list is an explicit decision that the
    tool has no C1-C6 capability.

    A human override is ground truth, so each mapping is written with
    confidence 1.0 (the same value the normalizer reserves for FULL_SCORE,
    i.e. band 'High'). It is deliberately NOT recomputed from the
    description/metadata channels.
    """
    tool_name = tool.get("tool")
    if not tool_name:
        return tool

    conn = sqlite3.connect(DB_PATH)
    try:
        _create_tables(conn)
        rows = conn.execute(
            """
            SELECT
                tc.capability_id,
                tc.confidence,
                tc.reason
            FROM tool_capabilities tc
            JOIN tools t
                ON t.tool_id = tc.tool_id
            WHERE t.name = ?
              AND tc.source = 'manual'
            ORDER BY tc.capability_id
            """,
            (tool_name,),
        ).fetchall()
    finally:
        conn.close()

    # No human decision exists.
    # Leave the automated mapping untouched.
    if not rows:
        return tool

    mappings = [
        {
            "capability_id": capability_id,
            "confidence": 1.0,
            "reason": reason or "Human-validated capability assignment.",
            "normalized_match": None,
            "source": "manual",
        }
        for capability_id, confidence, reason in rows
    ]

    tool.setdefault("mapping", {})
    tool["mapping"]["mappings"] = mappings
    tool["mapping"]["is_ambiguous"] = len(mappings) > 1

    if mappings:
        tool["mapping"]["mapping_reason"] = (
            "Human-validated capability assignment."
        )
    else:
        tool["mapping"]["mapping_reason"] = (
            "Human reviewer marked this tool as "
            "having no C1-C6 capability."
        )

    tool["mapping"]["source"] = "manual"

    # Important:
    # Explicitly record that this is a human override so downstream
    # modules do not mistake it for an automated mapper result.
    tool["manual_capability_override"] = True
    tool["manual_capabilities"] = [
        mapping["capability_id"]
        for mapping in mappings
    ]

    return tool
