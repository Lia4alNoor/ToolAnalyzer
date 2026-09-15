"""
Module 8: Pre-Deployment Risk Assessment (Mitigation Coverage)

Owns the mitigation knowledge base in capability_ontology.db:
  - mitigations         : literature-backed mitigations (LM-1..LM-10)
  - project_mitigations : project-derived mitigations (PDM-1..PDM-3)

For each Module 6 matched literature-backed capability composition, reports
applicable literature-backed mitigations, relevant project-derived
mitigations, evidence type, effectiveness evidence, limitations, coverage
status, and open mitigation gaps.

SEMANTICS: a Module 6 match is a matched literature-backed capability
composition (Level-1 static finding: capability presence only). It is NOT
an executed attack, a confirmed attack chain, or an observed execution.
"""
import json
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "capability_ontology.db"

MATCH_SEMANTICS = (
    "Findings refer to matched literature-backed capability compositions "
    "(Level-1 static findings). They are not executed attacks, confirmed "
    "attack chains, or observed executions."
)

APPLICABILITY_RULE = (
    "A mitigation applying to a capability does not mean the source paper "
    "evaluated it against every attack pattern containing that capability. "
    "'explicitly_addressed' and 'potentially_applicable' are kept distinct; "
    "potential applicability is never reported as empirical validation."
)

PDM_EVIDENCE_STATUS = (
    "PROJECT-DERIVED \u2014 not directly evaluated by the cited literature"
)

P5_WARNING = (
    "No literature-supported mitigation was identified for this specific "
    "C1\u2192C4\u2192C5 composition in the selected papers."
)

COVERAGE_RULES = {
    "P1": "Literature-supported",
    "P2": "Literature-supported but incomplete",
    "P3": "Literature-supported",
    "P4": "Literature-supported",
    "P5": "Literature mitigation gap",
    "P6": "Literature-supported",
    "P7": "Literature-supported",
    "P8": "Literature-supported",
    "P9": "Literature-supported",
}

COVERAGE_NOTES = {
    "P2": ("The only literature defenses evaluated against STAC (LM-3, "
           "LM-4) leave high residual ASR (58.6% / 79.3% at the first "
           "attack turn, as reported by the source), so no literature "
           "mitigation fully addresses the stateful repeated-C4 sequence; "
           "PDM-1 is a project-derived proposal for that residual gap."),
    "P5": ("Literature mitigation gap; PDM-3 is a project-derived proposal "
           "addressing this identified gap."),
    "P7": ("Literature-supported, but P7 remains outside the ordered C1-C6 "
           "composition analysis (NOT_ELIGIBLE for Module 6 matching)."),
}

MIT_COLS = [
    "mitigation_id", "mitigation_name", "target_patterns",
    "target_capabilities", "control_layer", "control_type", "timing",
    "mechanism", "evidence_type", "effectiveness_evidence", "limitations",
    "supporting_papers", "confidence",
]


def _tp(explicit, potential):
    return json.dumps({"explicitly_addressed": explicit,
                       "potentially_applicable": potential})


MITIGATION_SEED = [
    ("LM-1", "Mandatory Access Control (MAC)",
     _tp(["P1", "P4", "P6", "P8", "P9"], ["P3"]),
     json.dumps(["C2", "C3", "C4", "C6"]),
     "Host / OS enforcement", "Mandatory Access Control",
     "Runtime / Pre-execution policy",
     "OS/agent-level mandatory policies constrain which files, devices and "
     "state-changing operations agent tool calls may perform, independent "
     "of model output.",
     "DIRECT",
     "Source reports 0% ASR (100% of benchmarked attacks blocked) on the "
     "InjecAgent and AgentDojo benchmarks, versus up to 80% ASR for "
     "unprotected agents.",
     "Requires correct policy authoring; does not detect prompt-level "
     "manipulation; coarse policies may block benign behaviour.",
     "SEAgent", "High"),
    ("LM-2", "Least-Privilege ILP Solver",
     _tp(["P8"], ["P1", "P4", "P9"]),
     json.dumps(["C1", "C2", "C3", "C4"]),
     "Tool/permission provisioning", "Least-Privilege Scoping",
     "Pre-execution (deployment-time)",
     "Solves an integer linear program to grant each agent task the minimal "
     "tool/permission set required, shrinking the reachable capability "
     "surface.",
     "DIRECT",
     "Source reports optimal least-privilege scoping (versus LLM-based "
     "solvers with overprivilege ratios of 1.04-2.19) at 1-7% "
     "execution-latency overhead; no ASR-reduction value is reported.",
     "Cannot prevent misuse of capabilities that remain granted; "
     "security/utility trade-off.",
     "MiniScope", "Medium"),
    ("LM-3", "Harm-Benefit Reasoning",
     _tp(["P2"], []), json.dumps(["C4"]),
     "Model reasoning", "Pre-action harm assessment",
     "Pre-execution (per action)",
     "Prompts the agent to reason explicitly about harm versus benefit of a "
     "candidate tool action before executing it.",
     "DIRECT",
     "Source reports STAC ASR reduced from 87.4% to 58.6% at the first "
     "attack execution turn.",
     "Residual ASR remains high (58.6%); prompted defenses can be "
     "bypassed; effectiveness varies by model.",
     "STAC", "Medium"),
    ("LM-4", "Summarization Guardrail",
     _tp(["P2"], []), json.dumps(["C1", "C4"]),
     "Input processing", "Content sanitization",
     "Pre-execution (on ingestion)",
     "Summarizes untrusted ingested content before it enters the agent "
     "context, stripping embedded instructions.",
     "DIRECT",
     "Source reports STAC ASR lowered only to 79.3% at turn T (84.7% at "
     "T+1, 87.0% at T+2) versus 87.4% / 92.5% / 93.4% with no defense.",
     "Largely ineffective against multi-turn stateful sequences; may "
     "discard task-relevant detail; injected instructions can survive "
     "summarization.",
     "STAC", "Medium"),
    ("LM-5", "Reactive Self-Correction",
     _tp(["P7"], []), json.dumps([]),
     "Model reasoning", "Post-hoc detection and correction",
     "Runtime (after execution of a poisoned tool)",
     "The model re-inspects planned or executed steps and autonomously "
     "aborts/corrects when it recognises a tool over-executed or acted "
     "maliciously.",
     "DIRECT",
     "No quantitative value reported; the source documents the behaviour "
     "qualitatively (models autonomously restoring deleted configurations "
     "after tool over-execution) against tool description poisoning.",
     "Qualitative behavioural observation only; unreliable under adaptive "
     "attacks; correction may come after side effects.",
     "When the Manual Lies", "Low"),
    ("LM-6", "Pre-Execution Tool Filtering",
     _tp(["P1", "P9"], ["P3", "P6", "P8"]), json.dumps([]),
     "Tool exposure control", "Pre-planning tool filtering",
     "Pre-execution (before tool exposure)",
     "Restricts the set of tools exposed to the agent for a task before "
     "execution, so injected instructions cannot invoke out-of-scope "
     "tools.",
     "DIRECT",
     "Source reports targeted IPI ASR reduced from 57.69% to 6.84% on "
     "GPT-4o while maintaining 73.13% benign utility.",
     "Requires task-appropriate tool scoping; less effective when the "
     "attack only uses in-scope tools.",
     "AgentDojo", "High"),
    ("LM-7", "Safety Fine-Tuning",
     _tp(["P1", "P6", "P8"], ["P3", "P9"]), json.dumps([]),
     "Model training", "Training-time hardening",
     "Pre-deployment (training-time)",
     "Fine-tunes the model to refuse or resist injected instructions and "
     "unsafe tool use.",
     "DIRECT",
     "Source reports fine-tuned GPT-4 ASR of 7.1% versus 47.0% for "
     "prompted ReAct GPT-4 (GPT-3.5: 8.4% versus 39.8%).",
     "Generalization to unseen attacks is not guaranteed; requires "
     "training access.",
     "InjecAgent", "High"),
    ("LM-8", "Auxiliary ML Injection Detector",
     _tp(["P1", "P9"], ["P3", "P6", "P8"]), json.dumps(["C1"]),
     "Input processing", "ML-based detection",
     "Pre-execution (on ingestion)",
     "An auxiliary classifier screens ingested content and tool responses "
     "for prompt-injection payloads before the agent consumes them.",
     "DIRECT",
     "Source reports targeted IPI ASR lowered from 57.69% to 7.95%, but "
     "benign task utility degraded from 69.0% to 41.49% due to false "
     "positives.",
     "High false-positive cost to benign utility; adaptive attacks may "
     "evade the detector.",
     "AgentDojo", "Medium"),
    ("LM-9", "Data Delimiting / Spotlighting",
     _tp(["P1", "P9"], ["P3", "P6", "P8"]), json.dumps(["C1"]),
     "Input processing", "Data/instruction separation",
     "Pre-execution (on ingestion)",
     "Marks untrusted data with delimiters, encodings or provenance tags "
     "so the model can distinguish data from instructions.",
     "DIRECT",
     "AgentDojo reports delimiting lowering targeted IPI ASR to 41.65% "
     "(benign utility 72.66%); STAC reports spotlighting had negligible "
     "effect against STAC (ASR 85.3% at turn T versus 87.4% with no "
     "defense).",
     "Models do not perfectly honour delimiters; evaluated against STAC "
     "with negligible effect, so it is not listed as a P2 mitigation.",
     "AgentDojo; STAC", "Medium"),
    ("LM-10", "Security-Enhanced Memory (SEMemory)",
     _tp([], []), json.dumps(["C2", "C4"]),
     "Agent memory", "Memory integrity protection",
     "Runtime (memory read/write)",
     "Security-enhanced memory design that isolates and validates agent "
     "memory writes to prevent persistent contamination of stored "
     "context.",
     "PARTIAL / THEORETICAL",
     "No security/ASR evaluation reported; the source omits empirical "
     "attack testing for this vector, providing a formal security "
     "reduction proof and utility-only results (e.g. 77.78% correctness "
     "on API-Bank).",
     "Design proposal with formal proof only; omitted from empirical "
     "attack/defense benchmarking; no pattern-level coverage is assigned "
     "in this project.",
     "SEAgent", "Low"),
]

PROJECT_MITIGATION_SEED = [
    ("PDM-1", "Contextual State Transaction Auditing", "P2",
     "STAC + SEAgent",
     "Stateful Access Control / Sequence Monitoring",
     "Runtime / Pre-execution",
     "STAC demonstrates that individually benign state changes can become "
     "destructive when combined across turns. SEAgent demonstrates runtime "
     "policy enforcement. The project therefore proposes maintaining "
     "resource-level state history and requiring confirmation when "
     "cumulative operations produce a dangerous state transition.",
     PDM_EVIDENCE_STATUS),
    ("PDM-2", "Dynamic Outbound Argument Sandboxing", "P1",
     "MiniScope + SEAgent + literature exfiltration evidence",
     "Argument-Level Access Control",
     "Runtime / Pre-execution",
     "Restricts sensitive outbound arguments such as recipients, "
     "destinations, domains, or paths when untrusted C1 content is "
     "present, synthesizing least privilege with argument-level policy "
     "enforcement.",
     PDM_EVIDENCE_STATUS),
    ("PDM-3", "Sensitive-Data Execution Isolation", "P5",
     "capability composition gap + least-privilege / execution-isolation "
     "principles",
     "Execution Isolation / Data-Execution Separation",
     "Runtime / Pre-execution",
     "P5 has no literature-supported mitigation identified in the selected "
     "papers. This mitigation is a project-derived proposal addressing "
     "that identified mitigation gap. It prevents retrieved or persisted "
     "context content from being directly interpreted as executable C5 "
     "input unless explicitly authorized by the user or policy.",
     PDM_EVIDENCE_STATUS),
]

DDL = """
CREATE TABLE IF NOT EXISTS mitigations (
    mitigation_id TEXT PRIMARY KEY,
    mitigation_name TEXT NOT NULL,
    target_patterns TEXT,
    target_capabilities TEXT,
    control_layer TEXT,
    control_type TEXT,
    timing TEXT,
    mechanism TEXT,
    evidence_type TEXT,
    effectiveness_evidence TEXT,
    limitations TEXT,
    supporting_papers TEXT,
    confidence TEXT
);

CREATE TABLE IF NOT EXISTS project_mitigations (
    mitigation_id TEXT PRIMARY KEY,
    mitigation_name TEXT NOT NULL,
    target_pattern TEXT,
    derived_from TEXT,
    control_type TEXT,
    timing TEXT,
    project_rationale TEXT,
    evidence_status TEXT NOT NULL
);
"""


def _ensure_and_seed(conn):
    conn.executescript(DDL)
    ph = ",".join("?" * len(MIT_COLS))
    conn.executemany(
        "INSERT OR REPLACE INTO mitigations (" + ",".join(MIT_COLS) +
        ") VALUES (" + ph + ")", MITIGATION_SEED)
    conn.executemany(
        "INSERT OR REPLACE INTO project_mitigations (mitigation_id, "
        "mitigation_name, target_pattern, derived_from, control_type, "
        "timing, project_rationale, evidence_status) "
        "VALUES (?,?,?,?,?,?,?,?)", PROJECT_MITIGATION_SEED)
    conn.commit()


PROJ_COLS = [
    "mitigation_id", "mitigation_name", "target_pattern", "derived_from",
    "control_type", "timing", "project_rationale", "evidence_status",
]


def _load_mitigations(conn):
    lit = {}
    for row in conn.execute("SELECT " + ",".join(MIT_COLS) +
                            " FROM mitigations ORDER BY mitigation_id"):
        rec = dict(zip(MIT_COLS, row))
        rec["target_patterns"] = json.loads(rec["target_patterns"] or "{}")
        rec["target_capabilities"] = json.loads(
            rec["target_capabilities"] or "[]")
        lit[rec["mitigation_id"]] = rec
    proj = {}
    for row in conn.execute("SELECT " + ",".join(PROJ_COLS) +
                            " FROM project_mitigations ORDER BY mitigation_id"):
        rec = dict(zip(PROJ_COLS, row))
        proj[rec["mitigation_id"]] = rec
    return lit, proj


def _lit_for_pattern(lit, pid):
    out = []
    for rec in lit.values():
        tp = rec["target_patterns"]
        if pid in tp.get("explicitly_addressed", []):
            appl = "explicitly evaluated/addressed by the source"
        elif pid in tp.get("potentially_applicable", []):
            appl = ("potentially applicable (not empirically validated for "
                    "this pattern)")
        else:
            continue
        out.append({
            "mitigation_id": rec["mitigation_id"],
            "mitigation_name": rec["mitigation_name"],
            "applicability": appl,
            "control_layer": rec["control_layer"],
            "control_type": rec["control_type"],
            "timing": rec["timing"],
            "evidence_type": rec["evidence_type"],
            "effectiveness_evidence": rec["effectiveness_evidence"],
            "limitations": rec["limitations"],
            "supporting_papers": rec["supporting_papers"],
            "confidence": rec["confidence"],
        })
    return out


def _proj_for_pattern(proj, pid):
    return [dict(p) for p in proj.values() if p["target_pattern"] == pid]


def _coverage_entry(pid, lit, proj):
    lit_m = _lit_for_pattern(lit, pid)
    proj_m = _proj_for_pattern(proj, pid)
    status = COVERAGE_RULES.get(pid)
    if status is None:
        if lit_m:
            status = "Literature-supported"
        elif proj_m:
            status = "Project-derived only"
        else:
            status = "No mitigation identified"
    entry = {
        "pattern_id": pid,
        "literature_mitigations": lit_m,
        "project_mitigations": proj_m,
        "coverage_status": status,
    }
    if pid in COVERAGE_NOTES:
        entry["note"] = COVERAGE_NOTES[pid]
    if pid == "P5":
        entry["warning"] = P5_WARNING
        entry["open_gap"] = True
    return entry


def run(input_data):
    print("Running Module 8: Pre-Deployment Risk Assessment")
    return process(input_data)


def process(data):
    conn = sqlite3.connect(DB_PATH)
    try:
        _ensure_and_seed(conn)
        lit, proj = _load_mitigations(conn)
    finally:
        conn.close()

    if _lit_for_pattern(lit, "P5"):
        raise ValueError("P5 must have no literature-supported mitigation")
    p5_proj = [m["mitigation_id"] for m in _proj_for_pattern(proj, "P5")]
    if p5_proj != ["PDM-3"]:
        raise ValueError("P5 project mitigation must be exactly PDM-3")

    comp = data.get("composition_analysis", {}) if isinstance(data, dict) else {}
    detections = comp.get("detections", [])

    assessments = []
    open_gaps = []
    for det in detections:
        pid = det.get("pattern_id")
        entry = _coverage_entry(pid, lit, proj)
        entry["pattern_name"] = det.get("pattern_name")
        entry["capability_sequence"] = det.get("capability_sequence")
        entry["finding_basis"] = (
            "matched literature-backed capability composition")
        assessments.append(entry)
        if entry.get("open_gap"):
            open_gaps.append({
                "pattern_id": pid,
                "gap": "Literature mitigation gap",
                "project_proposals": [m["mitigation_id"]
                                      for m in entry["project_mitigations"]],
                "warning": P5_WARNING,
            })
        lit_ids = [m["mitigation_id"] for m in entry["literature_mitigations"]]
        proj_ids = [m["mitigation_id"] for m in entry["project_mitigations"]]
        print("  [MITIGATION] " + str(pid) + " " +
              str(det.get("pattern_name")) + ": " +
              entry["coverage_status"] + " | literature: " +
              (", ".join(lit_ids) or "-") + " | project: " +
              (", ".join(proj_ids) or "-"))

    coverage_reference = [_coverage_entry("P" + str(i), lit, proj)
                          for i in range(1, 10)]

    data["mitigation_assessment"] = {
        "semantics": MATCH_SEMANTICS,
        "applicability_rule": APPLICABILITY_RULE,
        "matched_composition_assessments": assessments,
        "pattern_coverage_reference": coverage_reference,
        "open_mitigation_gaps": open_gaps,
        "mitigations_source": (
            "capability_ontology.db (mitigations, project_mitigations)"),
    }
    print("[OK] Module 8: mitigation coverage assessed for " +
          str(len(assessments)) + " matched composition(s); " +
          str(len(open_gaps)) + " open mitigation gap(s).")
    return data
