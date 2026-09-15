"""
Module 6: Composition Analysis
"""

def run(input_data):
    """
    Main entry point for Module 6: Composition Analysis

    Args:
        input_data: Input data from previous module

    Returns:
        Processed output data
    """"""
Module 6: Composition Analysis (attack-pattern-database driven)

Matches each server's capability configuration against literature-backed
attack patterns stored in the attack_patterns table (seeded by Module 5).

Level-1 / potential composition ONLY:
- The ordered capability_sequence comes from the LITERATURE, not from any
  observed execution. Repeats are preserved (e.g. ["C4","C4","C4"]).
- Module 6 does NOT claim any tool's output reaches another tool's input,
  and does NOT manufacture tool invocation order from tool names, row
  order, alphabetical order, or any other arbitrary ordering.
- A detection means only: "the server contains a capability configuration
  consistent with a literature-backed attack pattern."

Input:  Module 5 output (tools with C1-C6 mappings, DB already seeded)
Output: same data plus 'composition_analysis' with per-pattern detections.
Evidence levels (Module 6 provides A + B, never C):
  A. Literature evidence: the paper documents the ordered capability
     structure (e.g. P1 = C1 -> C2 -> C3).
  B. Static capability evidence: the server exposes the capabilities the
     pattern requires (capability presence only).
  C. Runtime evidence: tools actually executed in order with data
     propagation between calls. OUT OF SCOPE for Module 6.

Side effect: persists matched composition findings into chains /
chain_steps (table names kept for schema compatibility; rows are matched
composition findings, NOT observed execution chains).
Row meaning: one chains row per (server, matched pattern);
chain_steps rows list, per ordered pattern step, ALL candidate tools that
provide that step's capability. Rows sharing a step_index are ALTERNATIVES,
not an executed sequence.
"""

import json
import sqlite3
from collections import Counter
from pathlib import Path

DB_PATH = Path(__file__).parent / "capability_ontology.db"

FIDELITY = "Level-1 / potential composition"

LIMITATION = (
    "Level-1 static analysis establishes capability presence only. It does "
    "not establish tool invocation order, inter-tool data flow, I/O "
    "compatibility, or runtime attack execution. This finding is therefore "
    "a potential composition and not a confirmed attack path.")

BASIS = ("static capability-presence match against a literature-backed "
         "attack pattern (order from literature, not observed)")

CIA_LIMITATION = (
    "CIA impact is derived from literature-demonstrated consequences; it is "
    "not attack probability, exploitability, or runtime execution evidence.")

CIA_DISCLAIMER = (
    "CIA scores are project-derived impact classifications based on "
    "consequences demonstrated in the literature. They do not represent "
    "attack probability, exploitability, or proof of runtime execution.")

# How every field and table in Module 6 results must be interpreted.
INTERPRETATION = {
    "question_answered": (
        "Does this server's static capability configuration resemble a "
        "documented attack pattern? NOT: can/did the attack execute, will "
        "one tool feed another, or did tools run in order."),
    "capability_sequence": (
        "Ordered capability sequence from the literature; the order is the "
        "literature-defined structure, never observed tool execution "
        "order."),
    "contributing_tools": (
        "Candidate tools for the required capability at each position: "
        "alternatives, not execution steps, attack steps, or an observed "
        "chain."),
    "severity": (
        "Project-defined severity (project risk ranking), not assigned by "
        "the cited papers."),
    "confidence": (
        "Confidence in the literature-to-capability mapping, not the "
        "probability that the attack will occur or succeed."),
    "evidence_type": (
        "DIRECT = literature directly supports the capability pattern; "
        "PARTIAL = synthesized from related evidence, never a claim that "
        "the exact ordered pattern was directly demonstrated."),
    "chains_table": (
        "Rows are matched composition findings: the server has a "
        "capability configuration consistent with a literature-backed "
        "pattern. NOT observed execution chains."),
    "chain_steps_table": (
        "Rows sharing a step_index are alternative candidate tools for "
        "that capability position in the literature-defined pattern, NOT "
        "sequential executions."),
    "impact_assessment": CIA_DISCLAIMER,
    "cia_total": (
        "CIA IMPACT TOTAL (C+I+A of literature-demonstrated impact); not a "
        "risk score and not a probability."),
}

# numeric mirror of the pattern's literature confidence (for chains column)
_CONF_NUM = {"High": 1.0, "Medium": 0.7, "Low": 0.4}


def run(input_data):
    print("=" * 70)
    print("Module 6: Composition Analysis (attack-pattern database)")
    print("=" * 70)
    return process(input_data)


def _tool_caps(tool):
    """capability_id -> best numeric mapper confidence for one tool."""
    out = {}
    for m in tool.get("mapping", {}).get("mappings", []):
        cap = m.get("capability_id")
        conf = m.get("confidence") or 0.0
        if cap and conf > out.get(cap, 0.0):
            out[cap] = conf
    return out


def _load_eligible_patterns(conn):
    """Read attack patterns from the DB. Only ELIGIBLE and
    ELIGIBLE_SYNTHESIZED patterns are used for matching; NOT_ELIGIBLE
    (e.g. P7) stays in the DB as evidence but is excluded here."""
    rows = conn.execute(
        """SELECT pattern_id, pattern_name, capability_sequence, attack_goal,
                  supporting_papers, evidence_type, confidence,
                  module_6_eligibility, severity, confidentiality_impact,
                  integrity_impact, availability_impact, cia_total,
                  cia_evidence_type, cia_rationale
           FROM attack_patterns
           WHERE module_6_eligibility IN ('ELIGIBLE', 'ELIGIBLE_SYNTHESIZED')
           ORDER BY pattern_id"""
    ).fetchall()
    patterns = []
    for r in rows:
        seq = json.loads(r[2]) if r[2] else None
        if not seq:
            continue  # defensive: never match a pattern with no sequence
        patterns.append({
            "pattern_id": r[0], "pattern_name": r[1], "capability_sequence": seq,
            "attack_goal": r[3], "supporting_papers": r[4],
            "evidence_type": r[5], "confidence": r[6],
            "module_6_eligibility": r[7], "severity": r[8],
            "confidentiality_impact": r[9], "integrity_impact": r[10],
            "availability_impact": r[11], "cia_total": r[12],
            "cia_evidence_type": r[13], "cia_rationale": r[14],
        })
    return patterns


def process(data):
    if not data:
        return None

    tools = data.get("tools", [])
    source_file = data.get("source_file") or "unknown"

    # capability -> sorted candidate tool names (alternatives, NOT ordered)
    cap_index = {}
    tool_cap_sets = {}
    for tool in tools:
        caps = set(_tool_caps(tool))
        tool_cap_sets[tool.get("tool")] = caps
        for cap in caps:
            cap_index.setdefault(cap, set()).add(tool.get("tool"))
    cap_index = {c: sorted(n) for c, n in cap_index.items()}

    print(f"\nServer capability profile: {sorted(cap_index) or 'none'}")
    print(f"Fidelity: {FIDELITY}")
    print(f"Limitation: {LIMITATION}\n")

    if not DB_PATH.exists():
        print("  [x] capability_ontology.db not found - run Module 5 first.")
        result = dict(data)
        result["composition_analysis"] = {"error": "attack_patterns unavailable"}
        return result

    conn = sqlite3.connect(DB_PATH)
    try:
        try:
            patterns = _load_eligible_patterns(conn)
        except sqlite3.OperationalError:
            print("  [x] attack_patterns table missing - re-run Module 5.")
            result = dict(data)
            result["composition_analysis"] = {"error": "attack_patterns unavailable"}
            return result
        excluded = [r[0] for r in conn.execute(
            """SELECT pattern_id FROM attack_patterns
               WHERE module_6_eligibility = 'NOT_ELIGIBLE'
               ORDER BY pattern_id""")]
        print(f"Loaded {len(patterns)} eligible patterns from attack_patterns; "
              f"excluded (evidence only): {excluded or 'none'}\n")

        detections = []
        for p in patterns:
            seq = p["capability_sequence"]
            label = " -> ".join(seq)
            missing = sorted({c for c in seq if c not in cap_index})
            if missing:
                print(f"  [ ] {p['pattern_id']} {p['pattern_name']} ({label}): "
                      f"configuration not present (missing {'+'.join(missing)})")
                continue

            # Repeated-capability handling (e.g. P2 = C4,C4,C4): capability
            # presence alone does NOT prove the repeated sequence exists.
            # Report (1) capability presence, (2) distinct-candidate-tool
            # sufficiency (informational only), and state explicitly that
            # (3) the actual repeated execution sequence CANNOT be
            # established by Level-1 static analysis. No order is invented.
            repeated = {c: n for c, n in Counter(seq).items() if n > 1}
            rep_analysis = [
                {"capability": c,
                 "required_occurrences": n,
                 "capability_present": True,
                 "distinct_candidate_tools": len(cap_index[c]),
                 "sufficient_distinct_candidate_tools": len(cap_index[c]) >= n,
                 "note": ("Informational only: the pattern could also be "
                          "realized by repeated invocation of a single "
                          "tool; distinct-tool sufficiency is NOT evidence "
                          "that any execution sequence occurred.")}
                for c, n in sorted(repeated.items())
            ] or None
            seq_note = None
            if repeated:
                seq_note = (
                    f"The literature specifies a {len(seq)}-step "
                    f"repeated-capability sequence ({label}). Module 6 "
                    "identifies capability availability/relevance only: it "
                    "does not claim these actions occurred, that distinct "
                    "tools are required, or that any tool was invoked "
                    "repeatedly. The required repeated execution sequence "
                    "cannot be confirmed statically and is not claimed.")

            # Ordered steps come from the LITERATURE sequence; each step
            # lists ALL candidate tools (alternatives). No tool execution
            # order is manufactured. Repeats (e.g. C4,C4,C4) are preserved.
            contributing = [
                {"step_index": i, "capability": cap,
                 "candidate_tools": cap_index[cap]}
                for i, cap in enumerate(seq)
            ]
            distinct_caps = set(seq)
            single = sorted(t for t, caps in tool_cap_sets.items()
                            if distinct_caps <= caps)
            all_candidates = sorted({t for s in contributing
                                     for t in s["candidate_tools"]})

            # Project-derived CIA impact (literature-demonstrated impact
            # only; never probability, exploitability, or runtime evidence).
            # EXCLUDED patterns (P7) never reach here and get no assessment.
            impact = None
            if p.get("cia_evidence_type") not in (None, "EXCLUDED"):
                impact = {
                    "confidentiality": p["confidentiality_impact"],
                    "integrity": p["integrity_impact"],
                    "availability": p["availability_impact"],
                    "total": p["cia_total"],
                    "evidence_type": p["cia_evidence_type"],
                    "rationale": p["cia_rationale"],
                    "limitation": CIA_LIMITATION,
                }

            detection = {
                "pattern_id": p["pattern_id"],
                "pattern_name": p["pattern_name"],
                "capability_sequence": seq,
                "severity": p["severity"],
                "supporting_papers": p["supporting_papers"],
                "evidence_type": p["evidence_type"],
                "confidence": p["confidence"],
                "module_6_eligibility": p["module_6_eligibility"],
                "attack_goal": p["attack_goal"],
                "impact_assessment": impact,
                "contributing_tools": contributing,
                "single_tool_coverage": single,
                "distinct_candidate_tool_count": len(all_candidates),
                "fidelity": FIDELITY,
                "basis": BASIS,
                "limitation": LIMITATION,
                "repeated_capability_analysis": rep_analysis,
                "sequence_limitation": seq_note,
                "finding_type": ("Level-1 relevance finding "
                                 "(sequence not statically confirmable)"
                                 if repeated
                                 else "Level-1 potential composition"),
                "finding": (
                    (f"Server contains {'/'.join(sorted(repeated))} "
                     "capability relevant to literature-backed pattern "
                     f"{p['pattern_id']}. The required repeated execution "
                     "sequence cannot be confirmed statically and is not "
                     "claimed.") if repeated else
                    ("Server contains a capability configuration "
                     "consistent with literature-backed pattern "
                     f"{p['pattern_id']}. No execution order or data flow "
                     "is claimed.")),
            }
            detections.append(detection)

            kind = ("relevance finding" if repeated
                    else "potential composition")
            print(f"  [!] {p['pattern_id']} {p['pattern_name']} "
                  f"[project severity: {p['severity']}] "
                  f"(literature-defined sequence: {label}) - {kind}")
            for s in contributing:
                print(f"        step {s['step_index']} {s['capability']}: "
                      f"candidates = {', '.join(s['candidate_tools'])}")
            for ra in (rep_analysis or []):
                print(f"        repeated {ra['capability']} x"
                      f"{ra['required_occurrences']}: "
                      f"{ra['distinct_candidate_tools']} distinct candidate "
                      "tool(s) (informational); repeated sequential "
                      "execution NOT statically confirmable")
            if impact:
                print(f"        CIA impact ({impact['evidence_type']}): "
                      f"C={impact['confidentiality']} "
                      f"I={impact['integrity']} "
                      f"A={impact['availability']} "
                      f"total={impact['total']}")

        persisted = _persist(conn, source_file, detections)
        conn.commit()
    finally:
        conn.close()

    result = dict(data)
    result["composition_analysis"] = {
        "fidelity": FIDELITY,
        "limitation": LIMITATION,
        "patterns_source": "attack_patterns table (capability_ontology.db)",
        "eligible_patterns_evaluated": len(patterns),
        "excluded_patterns": excluded,
        "detections": detections,
        "matched_compositions_persisted": persisted,
        "interpretation": INTERPRETATION,
    }
    result["composition_analysis_complete"] = True
    print(f"\n[OK] {len(detections)} matched composition finding(s); "
          f"{persisted} row(s) recorded in the chains table (matched "
          "composition findings, not observed execution chains) "
          f"for {source_file}")
    return result


def _tool_id(conn, name, source_file):
    """Best-effort tool_id lookup; None if the tool is not stored."""
    row = conn.execute(
        "SELECT tool_id FROM tools WHERE name = ? AND server_source = ?",
        (name, source_file)).fetchone()
    if row:
        return row[0]
    row = conn.execute(
        "SELECT tool_id FROM tools WHERE name = ? LIMIT 1", (name,)).fetchone()
    return row[0] if row else None


def _persist(conn, source_file, detections):
    """Persist matched composition findings into the EXISTING chains /
    chain_steps schema
    (unchanged DDL). Row meaning is repurposed:
      chains      = one row per (server, matched pattern). signature holds the
                    literature capability_sequence JSON; is NOT an executed
                    path. combined_confidence mirrors the pattern's literature
                    confidence (High=1.0/Medium=0.7).
      chain_steps = one row per (ordered pattern step, candidate tool). Rows
                    that share a step_index are ALTERNATIVE tools for that
                    capability slot, NOT an executed tool-to-tool sequence.
    Idempotent per server: prior rows for this server are recomputed."""
    _ensure_chain_tables(conn)
    _reset_server(conn, source_file)
    persisted = 0
    for d in detections:
        cur = conn.execute(
            """INSERT INTO chains
               (server_source, pattern_id, pattern_name, severity, basis,
                fidelity, signature, length, distinct_tool_count,
                is_single_tool, combined_confidence)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (source_file, d["pattern_id"], d["pattern_name"], d["severity"],
             BASIS, FIDELITY, json.dumps(d["capability_sequence"]),
             len(d["capability_sequence"]),
             d["distinct_candidate_tool_count"],
             1 if d["single_tool_coverage"] else 0,
             _CONF_NUM.get(d["confidence"], 0.4)))
        chain_id = cur.lastrowid
        persisted += 1
        for step in d["contributing_tools"]:
            for name in step["candidate_tools"]:
                conn.execute(
                    """INSERT INTO chain_steps
                       (chain_id, step_index, tool_id, tool_name, capability_id)
                       VALUES (?, ?, ?, ?, ?)""",
                    (chain_id, step["step_index"], _tool_id(conn, name, source_file),
                     name, step["capability"]))
    return persisted


def _ensure_chain_tables(conn):
    """Create chains / chain_steps if absent, using the EXACT pre-existing
    schema (Module 6 has always owned these tables). No redesign."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS chains (
            chain_id      INTEGER PRIMARY KEY AUTOINCREMENT,
            server_source TEXT NOT NULL,
            pattern_id    TEXT NOT NULL,
            pattern_name  TEXT NOT NULL,
            severity      TEXT NOT NULL,
            basis         TEXT,
            fidelity      TEXT NOT NULL,
            signature     TEXT NOT NULL,
            length        INTEGER NOT NULL,
            distinct_tool_count INTEGER NOT NULL,
            is_single_tool INTEGER NOT NULL,
            combined_confidence REAL,
            UNIQUE (server_source, pattern_id, signature)
        );
        CREATE TABLE IF NOT EXISTS chain_steps (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            chain_id      INTEGER NOT NULL REFERENCES chains(chain_id),
            step_index    INTEGER NOT NULL,
            tool_id       INTEGER REFERENCES tools(tool_id),
            tool_name     TEXT NOT NULL,
            capability_id TEXT NOT NULL REFERENCES capabilities(capability_id)
        );
    """)


def _reset_server(conn, source_file):
    """Recompute this server's rows idempotently (schema untouched)."""
    old = [r[0] for r in conn.execute(
        "SELECT chain_id FROM chains WHERE server_source = ?", (source_file,))]
    if old:
        marks = ",".join("?" * len(old))
        conn.execute(f"DELETE FROM chain_steps WHERE chain_id IN ({marks})", old)
        conn.execute("DELETE FROM chains WHERE server_source = ?", (source_file,))


