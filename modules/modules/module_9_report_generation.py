"""
Module 9: Report / Decision

Prints the final pre-deployment assessment report combining the capability
profile (Modules 1-5), matched literature-backed capability compositions
and CIA impact (Module 6), and mitigation coverage (Module 8). Also writes
the report next to the input file as <source>_final_report.txt.

The report never describes a Module 6 match as an executed attack,
confirmed attack chain, or observed execution.
"""
from pathlib import Path

W = 74


def _hdr(title):
    return ["=" * W, title, "=" * W]


def run(input_data):
    print("Running Module 9: Report / Decision")
    return process(input_data)


def process(data):
    if not isinstance(data, dict):
        print("[WARN] Module 9: no structured pipeline data to report on")
        return data
    src = data.get("source_file", "unknown_source")
    tools = data.get("tools", [])
    comp = data.get("composition_analysis", {})
    mit = data.get("mitigation_assessment", {})

    caps = {}
    for t in tools:
        for m in t.get("mapping", {}).get("mappings", []):
            cid = m.get("capability_id")
            if cid:
                caps.setdefault(cid, set()).add(t.get("tool"))

    lines = []
    lines += _hdr("AGENT PRE-DEPLOYMENT ASSESSMENT REPORT")
    lines.append("Server source        : " + str(src))
    lines.append("Tools analysed       : " + str(len(tools)))
    cap_txt = ", ".join(c + " (" + str(len(ts)) + " tool(s))"
                        for c, ts in sorted(caps.items()))
    lines.append("Capabilities present : " + (cap_txt or "none"))
    lines.append("")
    lines += _hdr("1. MATCHED LITERATURE-BACKED CAPABILITY COMPOSITIONS "
                  "(MODULE 6)")
    dets = comp.get("detections", [])
    if not dets:
        lines.append("No literature-backed capability composition matched "
                     "(Level-1).")
    for d in dets:
        lines.append("")
        lines.append(str(d.get("pattern_id")) + " - " +
                     str(d.get("pattern_name")) +
                     " [project severity: " + str(d.get("severity")) + "]")
        seq = d.get("capability_sequence") or []
        lines.append("  Literature-defined sequence : " + " -> ".join(seq))
        lines.append("  Finding type                : " +
                     str(d.get("finding_type")))
        lines.append("  Mapping confidence          : " +
                     str(d.get("confidence")) +
                     " (literature-mapping confidence)")
        ia = d.get("impact_assessment")
        if ia:
            lines.append("  CIA impact (C/I/A/Total)    : " +
                         str(ia.get("confidentiality")) + "/" +
                         str(ia.get("integrity")) + "/" +
                         str(ia.get("availability")) + "/" +
                         str(ia.get("total")) + " [" +
                         str(ia.get("evidence_type")) + "]")
            lines.append("  CIA rationale               : " +
                         str(ia.get("rationale")))
    lines.append("")
    if comp.get("excluded_patterns"):
        lines.append("Patterns excluded from composition matching: " +
                     ", ".join(comp["excluded_patterns"]) +
                     " (NOT_ELIGIBLE; stored for evidence only).")
        lines.append("")
    lines += _hdr("2. MITIGATION COVERAGE FOR MATCHED COMPOSITIONS "
                  "(MODULE 8)")
    for a in mit.get("matched_composition_assessments", []):
        lines.append("")
        lines.append(str(a["pattern_id"]) + " - " +
                     str(a.get("pattern_name")))
        lines.append("  Coverage status : " + a["coverage_status"])
        if a.get("note"):
            lines.append("  Note            : " + a["note"])
        if a["literature_mitigations"]:
            lines.append("  Literature mitigations:")
            for m in a["literature_mitigations"]:
                lines.append("    - " + m["mitigation_id"] + " " +
                             m["mitigation_name"] + " [" +
                             m["evidence_type"] + "] (" +
                             m["applicability"] + ")")
                lines.append("      papers: " + m["supporting_papers"] +
                             " | timing: " + m["timing"])
                lines.append("      effectiveness: " +
                             m["effectiveness_evidence"])
                lines.append("      limitations: " + m["limitations"])
        else:
            lines.append("  Literature mitigations: []")
        if a["project_mitigations"]:
            lines.append("  Project-derived mitigations:")
            for m in a["project_mitigations"]:
                lines.append("    - " + m["mitigation_id"] + " " +
                             m["mitigation_name"] + " (" +
                             m["control_type"] + "; " + m["timing"] + ")")
                lines.append("      evidence status: " +
                             m["evidence_status"])
                lines.append("      rationale: " + m["project_rationale"])
        if a.get("warning"):
            lines.append("  WARNING: " + a["warning"])
    lines.append("")
    lines += _hdr("3. PATTERN COVERAGE REFERENCE (P1-P9)")
    for c in mit.get("pattern_coverage_reference", []):
        lit_ids = ", ".join(m["mitigation_id"]
                            for m in c["literature_mitigations"]) or "-"
        proj_ids = ", ".join(m["mitigation_id"]
                             for m in c["project_mitigations"]) or "-"
        lines.append(c["pattern_id"] + ": " + c["coverage_status"] +
                     " (literature: " + lit_ids +
                     " | project: " + proj_ids + ")")
        if c.get("note"):
            lines.append("    note: " + c["note"])
    lines.append("")
    lines += _hdr("4. OPEN MITIGATION GAPS")
    gaps = mit.get("open_mitigation_gaps", [])
    if gaps:
        for g in gaps:
            lines.append("- " + g["pattern_id"] + ": " + g["gap"] +
                         " | project proposal(s): " +
                         (", ".join(g.get("project_proposals", [])) or
                          "none"))
            lines.append("  " + g.get("warning", ""))
    else:
        lines.append("No open mitigation gaps among matched compositions.")
    lines.append("")
    lines += _hdr("5. INTERPRETATION LIMITS AND DISCLAIMERS")
    if comp.get("limitation"):
        lines.append("- " + comp["limitation"])
    interp = comp.get("interpretation", {})
    if interp.get("impact_assessment"):
        lines.append("- " + interp["impact_assessment"])
    if mit.get("semantics"):
        lines.append("- " + mit["semantics"])
    if mit.get("applicability_rule"):
        lines.append("- " + mit["applicability_rule"])
    lines.append("- CIA totals are CIA IMPACT TOTALS only; they are not "
                 "converted into a risk score at this stage.")

    report = "\n".join(lines)
    print(report)

    out_name = Path(str(src)).name
    if out_name.endswith(".json"):
        out_name = out_name[:-5] + "_final_report.txt"
    else:
        out_name = out_name + "_final_report.txt"
    out_path = Path(__file__).parent / out_name
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(report + "\n")
    data["final_report_path"] = str(out_path)
    print("[OK] Module 9: final report written to " + str(out_path))
    return data
