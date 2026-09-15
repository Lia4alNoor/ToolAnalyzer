"""
Module 7: Attack Pattern Analysis (slimmed)

Purpose:
    Interprets the potential composition findings produced by Module 6.

Module 7 does NOT:
    - invent tool execution order
    - claim runtime execution
    - claim inter-tool data flow
    - claim that an attack succeeded
    - calculate final risk scores
    - attach mitigations (Module 8 is the single source of truth for
      pattern-level mitigation coverage)

Module 7 DOES:
    1. Read Module 6 composition findings.
    2. Interpret the matched literature-backed attack patterns.
    3. Identify the capabilities involved (canonical C1-C6 definitions).
    4. Identify candidate contributing tools.
    5. Build an evidence/limitation summary (A/B/C evidence model).
    6. Produce structured output for Module 8.

Evidence model:
    A = Literature evidence        -> available
    B = Static capability evidence -> available
    C = Runtime execution evidence -> NOT available

Therefore Module 7 never describes a finding as a confirmed attack.
"""

import json
import sqlite3
from pathlib import Path

# ---------------------------------------------------------------------------
# DATABASE
# ---------------------------------------------------------------------------

DB_PATH = Path(__file__).parent / "capability_ontology.db"

# ---------------------------------------------------------------------------
# MODULE CONSTANTS
# ---------------------------------------------------------------------------

MODULE_NAME = "Module 7: Attack Pattern Analysis"

RUNTIME_EVIDENCE_AVAILABLE = False

RUNTIME_LIMITATION = (
    "Runtime execution evidence is not available in the current pipeline. "
    "The finding therefore does not establish that the tools were executed, "
    "that data propagated between tools, or that the attack succeeded."
)

STATIC_LIMITATION = (
    "Static analysis establishes capability presence and candidate tools "
    "only. It does not establish execution order, inter-tool data flow, "
    "input/output compatibility, or successful exploitation."
)

MITIGATION_NOTE = (
    "Mitigation coverage is assessed exclusively by Module 8 "
    "(mitigation_assessment), which is the single source of truth for "
    "pattern-level mitigation coverage. Module 7 does not attach "
    "mitigations."
)

EVIDENCE_INTERPRETATION = {
    "A": "Literature evidence: the attack pattern and/or capability structure is supported by the selected literature.",
    "B": "Static capability evidence: the server exposes the capabilities required by the literature-backed pattern.",
    "C": "Runtime evidence: actual execution order and data propagation. NOT AVAILABLE in the current pipeline.",
}

# ---------------------------------------------------------------------------
# PUBLIC ENTRY POINT
# ---------------------------------------------------------------------------

def run(input_data):
    """
    Main entry point for Module 7.

    Args:
        input_data (dict): Output from Module 6.

    Returns:
        dict: Input data plus attack_pattern_analysis.
    """
    print("=" * 70)
    print(MODULE_NAME)
    print("=" * 70)
    return process(input_data)

# ---------------------------------------------------------------------------
# DATABASE HELPERS
# ---------------------------------------------------------------------------

def _connect_db():
    """Open the ontology database."""
    if not DB_PATH.exists():
        return None
    return sqlite3.connect(DB_PATH)


def _load_capabilities(conn):
    """
    Load canonical capability definitions.

    NOTE: the actual `capabilities` schema is
        capability_id | name | definition | example_risk
    (there are no `canonical_name` / `security_meaning` columns).
    """
    try:
        rows = conn.execute(
            """
            SELECT capability_id, name, definition, example_risk
            FROM capabilities
            ORDER BY capability_id
            """
        ).fetchall()
    except sqlite3.OperationalError:
        return {}

    capabilities = {}
    for row in rows:
        capabilities[row[0]] = {
            "capability_id": row[0],
            "name": row[1],
            "definition": row[2],
            "security_meaning": row[3],
        }
    return capabilities
def _load_pattern_from_db(conn, pattern_id):
    """
    Retrieve pattern details from attack_patterns (database-backed
    fallback; Module 6 already provides most of this information).
    """
    try:
        row = conn.execute(
            """
            SELECT pattern_id, pattern_name, capability_sequence,
                   attack_goal, supporting_papers, evidence_type,
                   confidence, module_6_eligibility, severity,
                   confidentiality_impact, integrity_impact,
                   availability_impact, cia_total, cia_evidence_type,
                   cia_rationale
            FROM attack_patterns
            WHERE pattern_id = ?
            """,
            (pattern_id,),
        ).fetchone()
    except sqlite3.OperationalError:
        return None

    if not row:
        return None

    return {
        "pattern_id": row[0],
        "pattern_name": row[1],
        "capability_sequence": _safe_json(row[2]),
        "attack_goal": row[3],
        "supporting_papers": row[4],
        "evidence_type": row[5],
        "confidence": row[6],
        "module_6_eligibility": row[7],
        "severity": row[8],
        "confidentiality_impact": row[9],
        "integrity_impact": row[10],
        "availability_impact": row[11],
        "cia_total": row[12],
        "cia_evidence_type": row[13],
        "cia_rationale": row[14],
    }

# ---------------------------------------------------------------------------
# JSON HELPERS
# ---------------------------------------------------------------------------

def _safe_json(value):
    """Safely parse JSON stored in SQLite; return original on failure."""
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return value

# ---------------------------------------------------------------------------
# CAPABILITY ANALYSIS
# ---------------------------------------------------------------------------

def _analyse_capabilities(sequence, capability_definitions):
    """Convert C1-C6 IDs into structured capability information."""
    result = []
    for index, capability_id in enumerate(sequence):
        definition = capability_definitions.get(capability_id)
        item = {
            "step_index": index,
            "capability_id": capability_id,
        }
        if definition:
            item.update({
                "canonical_name": definition["name"],
                "definition": definition["definition"],
                "security_meaning": definition["security_meaning"],
            })
        else:
            item.update({
                "canonical_name": None,
                "definition": None,
                "security_meaning": None,
            })
        result.append(item)
    return result

# ---------------------------------------------------------------------------
# TOOL ANALYSIS
# ---------------------------------------------------------------------------

def _analyse_contributing_tools(detection):
    """
    Convert Module 6 candidate-tool information into an explicit structure.

    IMPORTANT:
        Candidate tools are alternatives.
        They are NOT claimed to have executed in sequence.
    """
    contributing = detection.get("contributing_tools", [])
    result = []
    for step in contributing:
        result.append({
            "step_index": step.get("step_index"),
            "capability": step.get("capability"),
            "candidate_tools": step.get("candidate_tools", []),
            "execution_confirmed": False,
        })
    return result

# ---------------------------------------------------------------------------
# EVIDENCE ANALYSIS
# ---------------------------------------------------------------------------

def _build_evidence_assessment(detection):
    """
    Build explicit evidence classification.
    A = Literature, B = Static, C = Runtime (NOT available).
    """
    return {
        "A_literature_evidence": {
            "available": True,
            "evidence_type": detection.get("evidence_type"),
            "supporting_papers": detection.get("supporting_papers"),
        },
        "B_static_capability_evidence": {
            "available": True,
            "basis": detection.get("basis"),
            "capability_sequence": detection.get("capability_sequence", []),
            "contributing_tools": _analyse_contributing_tools(detection),
        },
        "C_runtime_execution_evidence": {
            "available": False,
            "execution_order_confirmed": False,
            "data_flow_confirmed": False,
            "attack_success_confirmed": False,
            "reason": RUNTIME_LIMITATION,
        },
    }
# ---------------------------------------------------------------------------
# ATTACK INTERPRETATION
# ---------------------------------------------------------------------------

def _build_attack_interpretation(pattern, detection, capability_information):
    """
    Conservative interpretation: describes what the capability
    configuration resembles, never that the attack happened.
    """
    pattern_id = pattern.get("pattern_id")
    pattern_name = pattern.get("pattern_name")
    sequence = pattern.get("capability_sequence") or detection.get(
        "capability_sequence", []
    )

    names = [
        item["canonical_name"]
        for item in capability_information
        if item.get("canonical_name")
    ]
    if names:
        capability_text = " -> ".join(names)
    else:
        capability_text = " -> ".join(sequence)

    return (
        f"The server exposes a capability configuration consistent with "
        f"literature-backed attack pattern {pattern_id} "
        f"({pattern_name}). The literature-defined capability structure "
        f"is {capability_text}. This indicates potential attack relevance "
        f"at the static capability level. It does not establish that the "
        f"attack was executed or succeeded."
    )

# ---------------------------------------------------------------------------
# MAIN PATTERN ANALYSIS
# ---------------------------------------------------------------------------

def _analyse_detection(detection, conn, capability_definitions):
    """Analyse one Module 6 detection (no mitigation attachment)."""
    pattern_id = detection.get("pattern_id")

    pattern = _load_pattern_from_db(conn, pattern_id)
    if pattern is None:
        pattern = {
            "pattern_id": pattern_id,
            "pattern_name": detection.get("pattern_name"),
            "capability_sequence": detection.get("capability_sequence", []),
            "attack_goal": detection.get("attack_goal"),
            "supporting_papers": detection.get("supporting_papers"),
            "evidence_type": detection.get("evidence_type"),
            "confidence": detection.get("confidence"),
            "severity": detection.get("severity"),
        }

    sequence = pattern.get("capability_sequence") or detection.get(
        "capability_sequence", []
    )

    capability_information = _analyse_capabilities(
        sequence, capability_definitions
    )

    evidence = _build_evidence_assessment(detection)

    interpretation = _build_attack_interpretation(
        pattern, detection, capability_information
    )

    repeated = detection.get("repeated_capability_analysis")
    sequence_warning = None
    if repeated:
        sequence_warning = (
            "The pattern contains repeated capabilities. Static analysis "
            "cannot establish repeated execution of those capabilities. "
            "The repeated sequence is derived from the literature pattern "
            "and is not an observed execution sequence."
        )

    return {
        "pattern_id": pattern_id,
        "pattern_name": pattern.get("pattern_name"),
        "attack_goal": pattern.get("attack_goal"),
        "capability_sequence": sequence,
        "capabilities": capability_information,
        "severity_from_module_6": detection.get("severity"),
        "literature_confidence": pattern.get("confidence"),
        "evidence_type": pattern.get("evidence_type"),
        "attack_interpretation": interpretation,
        "contributing_tools": _analyse_contributing_tools(detection),
        "evidence_assessment": evidence,
        "repeated_capability_analysis": repeated,
        "sequence_warning": sequence_warning,
        "mitigation_coverage": MITIGATION_NOTE,
        "runtime_execution_confirmed": False,
        "data_flow_confirmed": False,
        "attack_success_confirmed": False,
        "finding_type": "Static potential attack-pattern relevance",
        "limitations": [STATIC_LIMITATION, RUNTIME_LIMITATION],
    }

# ---------------------------------------------------------------------------
# MAIN PROCESS
# ---------------------------------------------------------------------------

def process(data):
    """
    Process Module 6 output.

    Returns the input data plus "attack_pattern_analysis".
    """
    if not data:
        return None

    composition = data.get("composition_analysis", {})
    detections = composition.get("detections", [])
    source_file = data.get("source_file", "unknown")

    print(
        f"\nAnalysing {len(detections)} "
        "potential attack-pattern finding(s)...\n"
    )

    conn = _connect_db()
    if conn is None:
        print("  [x] capability_ontology.db not found.")
        result = dict(data)
        result["attack_pattern_analysis"] = {
            "error": "capability_ontology.db not found",
            "analyses": [],
        }
        result["attack_pattern_analysis_complete"] = False
        return result

    try:
        capability_definitions = _load_capabilities(conn)

        print(
            f"Loaded {len(capability_definitions)} canonical capabilities."
        )
        print("Mitigation coverage: assessed by Module 8 (not Module 7).\n")

        analyses = []
        for detection in detections:
            analysis = _analyse_detection(
                detection, conn, capability_definitions
            )
            analyses.append(analysis)

            print(f"  [!] {analysis['pattern_id']} "
                  f"{analysis['pattern_name']}")
            print(f"      Goal: {analysis['attack_goal']}")
            print(
                f"      Capabilities: "
                f"{' -> '.join(analysis['capability_sequence'])}"
            )
            print(
                f"      Severity from M6: "
                f"{analysis['severity_from_module_6']}"
            )
            print(
                f"      Literature confidence: "
                f"{analysis['literature_confidence']}"
            )
            print("      Mitigation coverage: see Module 8")
            print("      Runtime execution confirmed: NO")
            print("      Data flow confirmed: NO")
            if analysis["sequence_warning"]:
                print(
                    "      [!] Repeated-capability sequence: "
                    "runtime sequence NOT confirmed."
                )
            print()
    finally:
        conn.close()

    result = dict(data)
    result["attack_pattern_analysis"] = {
        "module": MODULE_NAME,
        "purpose": (
            "Interpret Module 6 static composition findings using "
            "literature-backed attack patterns. Mitigation coverage is "
            "assessed by Module 8."
        ),
        "source_server": source_file,
        "patterns_analyzed": len(analyses),
        "runtime_evidence_available": RUNTIME_EVIDENCE_AVAILABLE,
        "evidence_model": EVIDENCE_INTERPRETATION,
        "mitigation_note": MITIGATION_NOTE,
        "analyses": analyses,
        "limitations": [STATIC_LIMITATION, RUNTIME_LIMITATION],
    }
    result["attack_pattern_analysis_complete"] = True

    print("=" * 70)
    print(
        f"Module 7 complete: "
        f"{len(analyses)} attack-pattern finding(s) analysed."
    )
    print("Runtime execution is NOT claimed.")
    print("Data-flow propagation is NOT claimed.")
    print("Mitigation coverage is reported by Module 8.")
    print("=" * 70)
    return result
