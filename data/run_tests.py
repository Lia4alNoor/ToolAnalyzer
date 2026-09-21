#!/usr/bin/env python3
"""Run the evaluation corpora against the Capability Ontology Mapper.

Usage, from the repository root (the folder holding app.py and modules/):

    python run_tests.py                       run every test_*.json beside this script
    python run_tests.py test_1_*.json         run one file
    python run_tests.py --dir path/to/corpora run every test file in a folder
    python run_tests.py --generated out.json  supply generator output for test 4

Each corpus file carries its own answers under the "evaluation" key, so no
separate answer file is needed. The script decides which harness to use from
the test name recorded inside the file.

Nothing here writes to the database or to any report file. It only reads the
corpora, calls the analysis code, and prints results.
"""

import argparse
import glob
import json
import os
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
CAPS = ["C1", "C2", "C3", "C4", "C5", "C6"]
HINTS = ["readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"]


# ---------------------------------------------------------------------------
# Locating the project code
# ---------------------------------------------------------------------------

def add_repo_to_path():
    """Put the repository root on sys.path.

    Tries the current directory first, then walks up from this script, so the
    corpora can live in a subfolder of the repository or anywhere else.
    """
    candidates = [os.getcwd(), HERE]
    probe = HERE
    for _ in range(4):
        probe = os.path.dirname(probe)
        candidates.append(probe)
    for root in candidates:
        if os.path.isdir(os.path.join(root, "modules", "modules")):
            if root not in sys.path:
                sys.path.insert(0, root)
            return root
    return None


REPO = add_repo_to_path()


def load_normalizer():
    """Import normalize_tool and adapt to whichever call shape it exposes."""
    try:
        from modules.modules.capability_normalizer import normalize_tool
    except Exception as exc:  # pragma: no cover - environment dependent
        return None, "could not import normalize_tool: {}".format(exc)

    def call(tool):
        try:
            return normalize_tool(tool)
        except TypeError:
            return normalize_tool(tool.get("tool"), tool.get("description"))

    return call, None


def load_scanner():
    """Import the TDP scanner and adapt to whichever entry point it exposes."""
    try:
        from modules import module_tdp_scanner as scanner
    except Exception as exc:  # pragma: no cover - environment dependent
        return None, "could not import module_tdp_scanner: {}".format(exc)

    for attr in ("run", "process", "scan"):
        fn = getattr(scanner, attr, None)
        if callable(fn):
            return fn, None
    return None, "module_tdp_scanner exposes no run, process or scan function"


# ---------------------------------------------------------------------------
# Scoring helpers
# ---------------------------------------------------------------------------

def predicted_set(result):
    """Pull the predicted capability set out of a normalizer result."""
    if not isinstance(result, dict):
        return set()
    caps = result.get("all_capabilities")
    if caps:
        return {c for c in caps if c in CAPS}
    one = result.get("primary_capability")
    return {one} if one in CAPS else set()


def set_scores(pairs):
    """Per capability set precision, set recall and their harmonic mean.

    pairs is a list of (predicted set, hand labelled set).
    """
    tp = Counter()
    fp = Counter()
    fn = Counter()
    for pred, truth in pairs:
        for c in CAPS:
            if c in pred and c in truth:
                tp[c] += 1
            elif c in pred:
                fp[c] += 1
            elif c in truth:
                fn[c] += 1
    rows = []
    for c in CAPS:
        p = tp[c] / (tp[c] + fp[c]) if (tp[c] + fp[c]) else 0.0
        r = tp[c] / (tp[c] + fn[c]) if (tp[c] + fn[c]) else 0.0
        f = 2 * p * r / (p + r) if (p + r) else 0.0
        rows.append((c, tp[c], fp[c], fn[c], p, r, f))
    return rows


def print_set_scores(rows):
    print("\n  {:4s} {:>4s} {:>4s} {:>4s} {:>8s} {:>8s} {:>8s}".format(
        "cap", "tp", "fp", "fn", "prec", "rec", "f1"))
    macro = []
    for c, tp, fp, fn, p, r, f in rows:
        print("  {:4s} {:4d} {:4d} {:4d} {:8.3f} {:8.3f} {:8.3f}".format(
            c, tp, fp, fn, p, r, f))
        macro.append(f)
    tp = sum(row[1] for row in rows)
    fp = sum(row[2] for row in rows)
    fn = sum(row[3] for row in rows)
    mp = tp / (tp + fp) if (tp + fp) else 0.0
    mr = tp / (tp + fn) if (tp + fn) else 0.0
    mf = 2 * mp * mr / (mp + mr) if (mp + mr) else 0.0
    print("  {:4s} {:4d} {:4d} {:4d} {:8.3f} {:8.3f} {:8.3f}".format(
        "all", tp, fp, fn, mp, mr, mf))
    print("  macro f1 {:.3f}   micro f1 {:.3f}".format(
        sum(macro) / len(macro) if macro else 0.0, mf))


def fmt_set(values):
    return ",".join(sorted(values)) if values else "none"


# ---------------------------------------------------------------------------
# Test 1, capability classifier
# ---------------------------------------------------------------------------

def run_capability(records, label="Test 1, capability classifier"):
    call, err = load_normalizer()
    if err:
        print("  SKIPPED. " + err)
        return

    pairs = []
    exact = 0
    unmapped = []
    rows = []
    by_provenance = defaultdict(lambda: [0, 0])

    for rec in records:
        truth = set(rec["evaluation"]["hand_labelled_capabilities"])
        tool = {k: v for k, v in rec.items() if k != "evaluation"}
        try:
            result = call(tool)
        except Exception as exc:
            print("  ERROR on {}: {}".format(rec.get("tool"), exc))
            continue
        pred = predicted_set(result)
        pairs.append((pred, truth))
        hit = pred == truth
        exact += 1 if hit else 0
        if not pred:
            unmapped.append(rec["tool"])
        prov = rec.get("provenance", "unknown")
        by_provenance[prov][1] += 1
        by_provenance[prov][0] += 1 if hit else 0
        rows.append((rec["tool"], pred, truth, hit,
                     result.get("confidence_score"),
                     result.get("primary_capability")))

    print("\n  {:34s} {:16s} {:16s} {:>6s} {:>6s}".format(
        "tool", "predicted", "hand labelled", "match", "score"))
    for tool, pred, truth, hit, score, _ in rows:
        print("  {:34s} {:16s} {:16s} {:>6s} {:>6}".format(
            tool[:34], fmt_set(pred)[:16], fmt_set(truth)[:16],
            "yes" if hit else "NO",
            "{:.2f}".format(score) if isinstance(score, (int, float)) else "-"))

    total = len(rows)
    print("\n  exact set match {}/{} = {:.1%}".format(
        exact, total, exact / total if total else 0))
    if unmapped:
        print("  produced no capability at all: {} ({})".format(
            len(unmapped), ", ".join(unmapped)))
    for prov, (ok, n) in sorted(by_provenance.items()):
        print("  exact match by provenance, {:10s} {}/{}".format(prov, ok, n))
    print_set_scores(set_scores(pairs))
    print("\n  Note: exact set match is strict. A tool labelled C6 and C4 counts")
    print("  as a miss if only C6 is predicted, but still earns credit for C6 in")
    print("  the per capability table above.")


# ---------------------------------------------------------------------------
# Test 2, hint detection
# ---------------------------------------------------------------------------

def strip_hints(tool):
    out = dict(tool)
    for h in HINTS:
        out[h] = None
    return out


def run_hints(records):
    call, err = load_normalizer()
    if err:
        print("  SKIPPED. " + err)
        return

    print("\n  {:22s} {:14s} {:10s} {:>7s} {:>7s} {:>6s}".format(
        "tool", "predicted", "channel", "score", "noHints", "moved"))

    moved = 0
    for rec in records:
        tool = {k: v for k, v in rec.items() if k != "evaluation"}
        with_hints = call(tool)
        without = call(strip_hints(tool))

        pred = fmt_set(predicted_set(with_hints))
        s1 = with_hints.get("confidence_score")
        s0 = without.get("confidence_score")
        channel = ""
        matches = with_hints.get("normalized_matches") or []
        if matches:
            channel = str(matches[0].get("source", ""))
        if with_hints.get("suppressed_matches"):
            channel = channel or "suppressed"
        changed = (predicted_set(with_hints) != predicted_set(without)) or (s1 != s0)
        moved += 1 if changed else 0

        def num(v):
            return "{:.2f}".format(v) if isinstance(v, (int, float)) else "-"

        print("  {:22s} {:14s} {:10s} {:>7s} {:>7s} {:>6s}".format(
            rec["tool"][:22], pred[:14], channel[:10], num(s1), num(s0),
            "yes" if changed else "no"))

        note = rec["evaluation"].get("auditor_note")
        if note:
            print("      expected: " + note)

    print("\n  cases where declared hints changed the result: {}/{}".format(
        moved, len(records)))
    print("  The earlier ablation produced byte identical reports. Any count")
    print("  above zero here is the evidence that the metadata channel is live.")


# ---------------------------------------------------------------------------
# Test 3, tool description poisoning
# ---------------------------------------------------------------------------

def run_tdp(records, clean_records=None):
    fn, err = load_scanner()
    if err:
        print("  SKIPPED. " + err)
        return

    def scan(tools):
        payload = {"tools": tools}
        try:
            out = fn(payload)
        except Exception as exc:
            print("  ERROR calling the scanner: {}".format(exc))
            return None
        return out if isinstance(out, dict) else payload

    tools = []
    for rec in records:
        tools.append({
            "tool": rec["tool_name"],
            "description": rec["tool_content"],
            "source": rec.get("tool_address"),
        })

    out = scan(tools)
    if out is None:
        return
    flagged = {t.get("tool") for t in out.get("tools", [])
               if t.get("tdp_flagged")}

    print("\n  {:22s} {:8s} {:s}".format("tool", "flagged", "attack shape"))
    for rec in records:
        name = rec["tool_name"]
        hit = name in flagged
        print("  {:22s} {:8s} {:s}".format(
            name[:22], "yes" if hit else "MISS",
            rec["evaluation"]["attack_shape"][:52]))

    recall = len(flagged) / len(records) if records else 0
    print("\n  recall {}/{} = {:.1%}".format(len(flagged), len(records), recall))

    if clean_records:
        clean = [{"tool": r["tool"], "description": r["description"]}
                 for r in clean_records if r.get("provenance") == "verbatim"]
        cout = scan(clean)
        if cout is not None:
            fps = [t.get("tool") for t in cout.get("tools", [])
                   if t.get("tdp_flagged")]
            print("  false positives over {} verbatim clean descriptions: {}".format(
                len(clean), len(fps)))
            for name in fps:
                print("     flagged in error: {}".format(name))


# ---------------------------------------------------------------------------
# Test 4, description and metadata generator
# ---------------------------------------------------------------------------

def run_generator(records, generated_path=None):
    """Compare generator output against the published declarations.

    Without --generated this reports the ceiling instead: it runs the published
    descriptions through the classifier, which is the best any generator could
    do on this corpus. Treat that as the upper bound, not as a result.
    """
    call, err = load_normalizer()
    if err:
        print("  SKIPPED. " + err)
        return

    produced = {}
    if generated_path:
        with open(generated_path, encoding="utf-8") as fh:
            for row in json.load(fh):
                produced[row.get("tool")] = row

    mode = "generated output" if produced else "published ceiling"
    print("\n  mode: {}".format(mode))
    if not produced:
        print("  No generator output supplied. Pass --generated FILE with rows of")
        print("  {tool, description, readOnlyHint, destructiveHint, idempotentHint,")
        print("  openWorldHint} to score the generator itself.")

    pairs = []
    hint_exact = hint_wrong = hint_null = 0

    print("\n  {:22s} {:14s} {:14s} {:>6s}  {:s}".format(
        "tool", "recovered", "hand labelled", "match", "hints vs published"))

    for rec in records:
        name = rec["tool"]
        ev = rec["evaluation"]
        truth = set(ev["hand_labelled_capabilities"])
        row = produced.get(name)

        desc = (row or {}).get("description") or ev.get("published_description") or ""
        tool = {"tool": name, "description": desc}
        for h in HINTS:
            key = "published_" + h
            tool[h] = (row or {}).get(h) if row else ev.get(key)

        result = call(tool)
        pred = predicted_set(result)
        pairs.append((pred, truth))

        detail = []
        if row:
            for h in HINTS:
                want = ev.get("published_" + h)
                got = row.get(h)
                if want is None:
                    continue
                if got is None:
                    hint_null += 1
                    detail.append(h[:-4] + " unset")
                elif got == want:
                    hint_exact += 1
                else:
                    hint_wrong += 1
                    detail.append("{}={} want {}".format(h[:-4], got, want))

        print("  {:22s} {:14s} {:14s} {:>6s}  {:s}".format(
            name[:22], fmt_set(pred)[:14], fmt_set(truth)[:14],
            "yes" if pred == truth else "NO",
            ", ".join(detail) if detail else ("ok" if row else "-")))

    if produced:
        total = hint_exact + hint_wrong + hint_null
        if total:
            print("\n  hint values, exact {} wrong {} left unset {} of {}".format(
                hint_exact, hint_wrong, hint_null, total))
            print("  A wrong value is worse than an unset one. Unset forfeits the")
            print("  metadata weight; wrong can force the contradiction override.")
    print_set_scores(set_scores(pairs))


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

RUNNERS = {
    "capability_classifier": "capability",
    "hint_detection": "hints",
    "tdp_detection": "tdp",
    "generator": "generator",
}


def test_kind(records):
    for rec in records:
        ev = rec.get("evaluation") or {}
        if ev.get("test") in RUNNERS:
            return ev["test"]
    if records and "tool_content" in records[0]:
        return "tdp_detection"
    if records and "signature" in records[0]:
        return "generator"
    return "capability_classifier"


def banner(text):
    print("\n" + "=" * 78)
    print(text)
    print("=" * 78)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("files", nargs="*", help="corpus files to run")
    ap.add_argument("--dir", help="folder holding the corpus files")
    ap.add_argument("--generated", help="generator output for test 4")
    args = ap.parse_args()

    paths = list(args.files)
    if args.dir:
        paths += sorted(glob.glob(os.path.join(args.dir, "test_*.json")))
    if not paths:
        paths = sorted(glob.glob(os.path.join(HERE, "test_*.json")))
    if not paths:
        print("No corpus files found. Pass file paths or use --dir.")
        return 1

    print("repository root: {}".format(REPO or "NOT FOUND"))
    if not REPO:
        print("Run this from the folder holding app.py and modules/, or the")
        print("imports below will fail and every test will report SKIPPED.")

    loaded = {}
    for path in paths:
        with open(path, encoding="utf-8") as fh:
            loaded[path] = json.load(fh)

    clean = None
    for records in loaded.values():
        if test_kind(records) == "capability_classifier":
            clean = records
            break

    for path, records in loaded.items():
        kind = test_kind(records)
        banner("{}  [{}, {} records]".format(
            os.path.basename(path), kind, len(records)))
        if kind == "capability_classifier":
            run_capability(records)
        elif kind == "hint_detection":
            run_hints(records)
        elif kind == "tdp_detection":
            run_tdp(records, clean_records=clean)
        elif kind == "generator":
            run_generator(records, generated_path=args.generated)

    print("\ndone")
    return 0


if __name__ == "__main__":
    sys.exit(main())
