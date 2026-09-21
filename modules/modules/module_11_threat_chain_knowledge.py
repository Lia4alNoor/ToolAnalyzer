"""Module 11: Threat Chain Knowledge Acquisition & Human Curation.

MITRE ATLAS -> filter -> LLM candidate synthesis -> PENDING -> human review.

C1-C6 ontology is never modified. P1-P9 patterns are preserved.
Human approval is mandatory before anything enters attack_patterns.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

MODULE_NAME = "Module 11: Threat Chain Knowledge Acquisition & Human Curation"

ATLAS_LATEST_POINTER_URL = (
    "https://raw.githubusercontent.com/"
    "mitre-atlas/atlas-data/main/dist/v6/ATLAS-latest.yaml"
)
ATLAS_VERSION_BASE_URL = (
    "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/v6/")
ATLAS_WEB_URL = "https://atlas.mitre.org/"

# Fixed ontology. DO NOT modify.
CANONICAL_CONCEPTS = {
    "C1": "External Data Ingestion",
    "C2": "Sensitive Data Access",
    "C3": "External Communication",
    "C4": "State Modification",
    "C5": "System Execution",
    "C6": "Physical Actuation",
}
VALID_CAPABILITIES = set(CANONICAL_CONCEPTS)

DEFAULT_CHAIN_THEMES = [
    "collection-to-staging",
    "encoding-and-transfer",
    "legitimate-channel exfiltration",
    "covert transfer path",
    "permission-composition exfiltration",
]

RELEVANT_TACTICS = {
    "Collection", "AI Attack Staging", "Command and Control", "Exfiltration",
    "Impact", "Execution", "Discovery", "Credential Access",
    "Privilege Escalation",
}

DEFAULT_OPENAI_MODEL = "gpt-4o-mini"
DEFAULT_OLLAMA_MODEL = "qwen3:14b"
DEFAULT_OLLAMA_URL = "http://localhost:11434"

REQUEST_TIMEOUT = 30           # ATLAS download
OLLAMA_CONNECT_TIMEOUT = 10    # connect to Ollama
OLLAMA_READ_TIMEOUT = 300      # local generation can be slow
DEFAULT_MAX_TECHNIQUES = 10

# ---------------------------------------------------------------- debug

_CAP_RE = re.compile(r"\bC[1-6]\b")
_TECH_ID_RE = re.compile(r"^AML\.T\d{4}(\.\d{3})?$")
_TACTIC_ID_RE = re.compile(r"^AML\.TA\d{4}$")

# Inspectable after every generation run (shown in the UI diagnostics
# expander). Holds prompt, raw LLM response, and per-candidate drop reasons.
LAST_GENERATION_DEBUG: Dict[str, Any] = {}

# Inspectable after every acquisition run. Holds ATLAS parser statistics so
# an empty or tiny technique set is immediately visible.
LAST_ACQUISITION_DEBUG: Dict[str, Any] = {}


def _normalize_capability(step: Any) -> Optional[str]:
    """Accept 'C1', 'c1', 'C1 (External Data Ingestion)', etc."""
    match = _CAP_RE.search(str(step).upper())
    return match.group(0) if match else None


def _match_source_id(raw_id: Any, valid_ids: set) -> Optional[str]:
    """Tolerate case/whitespace noise and sub-technique IDs."""
    cleaned = str(raw_id).strip().rstrip("/").upper()
    for valid_id in valid_ids:
        upper_valid = str(valid_id).upper()
        if (
            cleaned == upper_valid
            or cleaned.startswith(upper_valid + ".")
            or upper_valid.startswith(cleaned + ".")
        ):
            return valid_id
    return None


# ---------------------------------------------------------------- utilities


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


def _safe_json_loads(value: str) -> Any:
    """Parse LLM JSON, tolerating markdown fences."""
    text = value.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    return json.loads(text)


# ---------------------------------------------------------------- database


def _ensure_tables(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS threat_sources (
            source_id TEXT PRIMARY KEY, source_name TEXT NOT NULL,
            source_type TEXT NOT NULL, source_url TEXT NOT NULL,
            source_version TEXT, retrieved_at TEXT NOT NULL,
            content_hash TEXT, notes TEXT
        );
        CREATE TABLE IF NOT EXISTS source_techniques (
            source_technique_id TEXT PRIMARY KEY, source_id TEXT NOT NULL,
            technique_name TEXT NOT NULL, description TEXT, tactic TEXT,
            platforms TEXT, maturity TEXT, source_url TEXT,
            raw_reference TEXT,
            FOREIGN KEY(source_id) REFERENCES threat_sources(source_id)
        );
        CREATE TABLE IF NOT EXISTS candidate_patterns (
            candidate_id TEXT PRIMARY KEY, candidate_name TEXT NOT NULL,
            capability_sequence TEXT, attack_goal TEXT,
            source_type TEXT NOT NULL, source_technique_ids TEXT,
            evidence_summary TEXT, llm_provider TEXT, llm_model TEXT,
            llm_confidence REAL, llm_rationale TEXT,
            status TEXT NOT NULL DEFAULT 'PENDING', reviewer TEXT,
            review_timestamp TEXT, review_comment TEXT,
            merged_into_pattern_id TEXT, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS candidate_pattern_evidence (
            candidate_id TEXT NOT NULL, source_technique_id TEXT NOT NULL,
            evidence_role TEXT,
            PRIMARY KEY (candidate_id, source_technique_id)
        );
        CREATE INDEX IF NOT EXISTS idx_candidate_status
            ON candidate_patterns(status);
    """)
    row = conn.execute(
        "SELECT name FROM sqlite_master "
        "WHERE type='table' AND name='attack_patterns'"
    ).fetchone()
    if row is None:
        raise RuntimeError(
            "attack_patterns table does not exist. "
            "Run Module 5 before Module 11."
        )


def _next_pattern_id(conn: sqlite3.Connection) -> str:
    """Generate P10, P11, ... without disturbing existing P1-P9."""
    rows = conn.execute(
        "SELECT pattern_id FROM attack_patterns WHERE pattern_id LIKE 'P%'"
    ).fetchall()
    highest = 9
    for (pattern_id,) in rows:
        try:
            highest = max(highest, int(str(pattern_id)[1:]))
        except ValueError:
            continue
    return f"P{highest + 1}"


# ---------------------------------------------------------------- ATLAS fetch


def _http_get(url: str) -> bytes:
    request = urllib.request.Request(
        url, headers={"User-Agent": "AgentPreDeployer/1.0", "Accept": "*/*"}
    )
    with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
        return response.read()


def _resolve_atlas_latest_url() -> Tuple[str, str]:
    pointer = _http_get(ATLAS_LATEST_POINTER_URL).decode("utf-8").strip()
    if pointer.startswith("format-version:"):
        return ATLAS_LATEST_POINTER_URL, "unknown"
    filename = pointer.splitlines()[0].strip()
    if not filename.endswith(".yaml"):
        raise RuntimeError(f"Unexpected ATLAS latest pointer: {filename}")
    version = filename.replace("ATLAS-", "").replace(".yaml", "")
    return ATLAS_VERSION_BASE_URL + filename, version


def fetch_atlas() -> Dict[str, Any]:
    try:
        import yaml
    except ImportError as exc:
        raise RuntimeError("PyYAML is required: pip install pyyaml") from exc

    url, version = _resolve_atlas_latest_url()
    raw = _http_get(url)
    # DEBUG FIX: dist files can contain multiple YAML documents;
    # yaml.safe_load would silently return only the first one.
    documents = [
        doc for doc in yaml.safe_load_all(raw)
        if isinstance(doc, (dict, list))
    ]
    if not documents:
        raise RuntimeError("MITRE ATLAS data did not parse as YAML.")
    data: Dict[str, Any] = (
        documents[0]
        if len(documents) == 1 and isinstance(documents[0], dict)
        else {"documents": documents}
    )
    data["_module11_metadata"] = {
        "url": url,
        "version": version,
        "retrieved_at": _utc_now(),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    return data


# ---------------------------------------------------------------- ATLAS parse


def _walk_atlas(
    node: Any,
    techniques: Dict[str, Dict[str, Any]],
    tactic_names: Dict[str, str],
) -> None:
    """DEBUG FIX: recursively collect techniques (AML.T*) and tactics
    (AML.TA*) anywhere in the document. The ATLAS dist YAML nests both
    under matrices[*], which the old top-level-only lookup missed."""
    if isinstance(node, dict):
        node_id = str(node.get("id", ""))
        if _TACTIC_ID_RE.match(node_id):
            tactic_names[node_id] = str(node.get("name", node_id))
        elif _TECH_ID_RE.match(node_id):
            existing = techniques.get(node_id)
            # Prefer entries that carry a description (full definitions)
            # over bare references found in case studies.
            if existing is None or (
                not existing.get("description")
                and node.get("description")
            ):
                item = dict(node)
                item["id"] = node_id
                techniques[node_id] = item
        for value in node.values():
            _walk_atlas(value, techniques, tactic_names)
    elif isinstance(node, list):
        for value in node:
            _walk_atlas(value, techniques, tactic_names)


def _extract_techniques(atlas_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    techniques: Dict[str, Dict[str, Any]] = {}
    tactic_names: Dict[str, str] = {}
    _walk_atlas(atlas_data, techniques, tactic_names)
    return list(techniques.values())


def _extract_tactic_names(atlas_data: Dict[str, Any]) -> Dict[str, str]:
    techniques: Dict[str, Dict[str, Any]] = {}
    tactic_names: Dict[str, str] = {}
    _walk_atlas(atlas_data, techniques, tactic_names)
    return tactic_names


def _technique_tactics(
    technique: Dict[str, Any], tactic_names: Dict[str, str]
) -> List[str]:
    result: List[str] = []
    raw = technique.get("tactics")
    if isinstance(raw, list):
        for value in raw:
            if isinstance(value, str):
                result.append(tactic_names.get(value, value))
            elif isinstance(value, dict):
                result.append(
                    value.get("name")
                    or tactic_names.get(value.get("id"), value.get("id"))
                    or str(value)
                )
    for phase in technique.get("kill_chain_phases") or []:
        if isinstance(phase, dict):
            name = phase.get("name") or phase.get("phase_name")
            if name:
                result.append(name)
    if isinstance(technique.get("tactic"), str):
        result.append(technique["tactic"])
    seen: set = set()
    return [x for x in result if not (x in seen or seen.add(x))]


def filter_relevant_techniques(
    atlas_data: Dict[str, Any], include_agentic: bool = True
) -> List[Dict[str, Any]]:
    """Deterministic filtering. Happens BEFORE the LLM."""
    tactic_names = _extract_tactic_names(atlas_data)
    keywords = (
        "exfiltration", "data", "staging", "tool invocation", "agent",
        "communication", "transfer", "collection", "context",
    )
    all_techniques = _extract_techniques(atlas_data)
    technique_index = {str(t.get("id")): t for t in all_techniques}
    relevant = []
    for technique in all_techniques:
        tactics = _technique_tactics(technique, tactic_names)
        if not tactics:
            # DEBUG FIX: sub-techniques omit tactics; inherit the parent's.
            technique_id = str(technique.get("id", ""))
            parent_ref = technique.get("subtechnique-of")
            if isinstance(parent_ref, dict):
                parent_ref = parent_ref.get("id")
            if not parent_ref and technique_id.count(".") == 2:
                parent_ref = technique_id.rsplit(".", 1)[0]
            parent = technique_index.get(str(parent_ref))
            if parent is not None:
                tactics = _technique_tactics(parent, tactic_names)
        platforms = technique.get("platforms", [])
        if isinstance(platforms, str):
            platforms = [platforms]
        text = (
            str(technique.get("name", ""))
            + " "
            + str(technique.get("description", ""))
        ).lower()
        if (
            any(t in RELEVANT_TACTICS for t in tactics)
            or (include_agentic and "Agentic AI" in platforms)
            or any(k in text for k in keywords)
        ):
            item = dict(technique)
            item["_tactics"] = tactics
            item["platforms"] = platforms
            relevant.append(item)
    return relevant


# ---------------------------------------------------------------- storage


def store_atlas_source(
    db_path: str | Path,
    atlas_data: Dict[str, Any],
    techniques: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    """Store source metadata and techniques. Does NOT create attack patterns."""
    metadata = atlas_data.get("_module11_metadata", {})
    version = metadata.get("version", "unknown")
    source_id = f"MITRE-ATLAS-{version}"

    conn = sqlite3.connect(str(db_path))
    try:
        _ensure_tables(conn)
        conn.execute(
            "INSERT OR REPLACE INTO threat_sources VALUES (?,?,?,?,?,?,?,?)",
            (
                source_id, "MITRE ATLAS", "THREAT_CATALOG",
                metadata.get("url", ATLAS_WEB_URL), version,
                metadata.get("retrieved_at", _utc_now()),
                metadata.get("sha256"),
                "Authoritative threat knowledge source. Technique catalogue; "
                "not itself a project-defined attack-chain taxonomy.",
            ),
        )
        for technique in techniques:
            technique_id = str(technique.get("id"))
            technique_url = (
                "https://atlas.mitre.org/techniques/" + technique_id + "/"
            )
            conn.execute(
                "INSERT OR REPLACE INTO source_techniques "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    technique_id, source_id,
                    technique.get("name", technique_id),
                    technique.get("description", ""),
                    _json(technique.get("_tactics", [])),
                    _json(technique.get("platforms", [])),
                    technique.get("maturity"),
                    technique_url,
                    _json(technique),
                ),
            )
        conn.commit()
    finally:
        conn.close()

    return {
        "source_id": source_id,
        "source_name": "MITRE ATLAS",
        "source_version": version,
        "technique_count": len(techniques),
        "retrieved_at": metadata.get("retrieved_at", _utc_now()),
        "source_url": metadata.get("url", ATLAS_WEB_URL),
    }


# ---------------------------------------------------------------- LLM


def build_llm_prompt(
    techniques: Sequence[Dict[str, Any]],
    chain_themes: Sequence[str] = DEFAULT_CHAIN_THEMES,
) -> str:
    payload = [
        {
            "id": t.get("id"),
            "name": t.get("name"),
            "description": t.get("description", ""),
            "tactics": t.get("_tactics", []),
            "platforms": t.get("platforms", []),
            "maturity": t.get("maturity"),
        }
        for t in techniques
    ]
    ontology = "\n".join(
        f"{cid}: {name}" for cid, name in CANONICAL_CONCEPTS.items()
    )
    return f"""
You are assisting with a defensive pre-deployment security framework for
agentic AI systems.

The framework has a FIXED capability ontology:
{ontology}

You MUST NOT create, rename, split, merge, or modify C1-C6.

The source material below comes from MITRE ATLAS. It contains documented
techniques and threat knowledge. It does NOT necessarily define the project's
named compositional attack chains.

Propose CANDIDATE compositional attack patterns representable with the fixed
C1-C6 ontology. A human will review them before database entry.

Optional research themes, for inspiration ONLY:
{json.dumps(list(chain_themes), indent=2)}

Do NOT force one candidate per theme. Do NOT use theme names as candidate
names. Propose only patterns the evidence supports, even if that means zero
candidates.

SOURCE TECHNIQUES:
{json.dumps(payload, indent=2, ensure_ascii=False)}

RULES:
1. Use only C1-C6 in capability_sequence.
2. Do not invent MITRE technique IDs; every ID must occur in the source
   material above.
3. A technique is evidence, not automatically a capability. Never invent
   C7, C8, etc.
4. Only propose a sequence if the evidence provides a reasonable basis.
   If insufficient, mark it INSUFFICIENT_EVIDENCE instead of inventing.
5. Do not claim MITRE explicitly defines the chain unless the material
   establishes that.
6. Return JSON only. No markdown.

Return:
{{
  "candidates": [
    {{
      "candidate_name": "...",
      "capability_sequence": ["C2", "C4", "C3"],
      "attack_goal": "...",
      "source_technique_ids": ["AML.Txxxx"],
      "evidence_summary": "...",
      "confidence": 0.0,
      "rationale": "...",
      "evidence_status": "SUPPORTED|PARTIAL|INSUFFICIENT_EVIDENCE"
    }}
  ]
}}
""".strip()


def generate_with_openai(
    prompt: str, model: Optional[str] = None
) -> Tuple[str, str]:
    try:
        from openai import OpenAI
    except ImportError as exc:
        raise RuntimeError("Install openai: pip install openai") from exc

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is not configured.")

    selected_model = model or os.getenv("OPENAI_MODEL", DEFAULT_OPENAI_MODEL)
    response = OpenAI(api_key=api_key).chat.completions.create(
        model=selected_model,
        temperature=0,
        response_format={"type": "json_object"},
        messages=[
            {
                "role": "system",
                "content": (
                    "You produce strictly structured JSON for a defensive "
                    "security research system."
                ),
            },
            {"role": "user", "content": prompt},
        ],
    )
    content = response.choices[0].message.content
    if not content:
        raise RuntimeError("OpenAI returned an empty response.")
    return content, selected_model


def generate_with_ollama(
    prompt: str,
    model: Optional[str] = None,
    base_url: Optional[str] = None,
) -> Tuple[str, str]:
    import requests

    selected_model = model or os.getenv("OLLAMA_MODEL", DEFAULT_OLLAMA_MODEL)
    selected_url = base_url or os.getenv("OLLAMA_BASE_URL", DEFAULT_OLLAMA_URL)
    endpoint = selected_url.rstrip("/") + "/api/generate"

    try:
        response = requests.post(
            endpoint,
            json={
                "model": selected_model,
                "prompt": prompt,
                "stream": False,
                "format": "json",
                "think": False,  # DEBUG FIX: qwen3 thinking eats num_predict
                "keep_alive": "10m",
                "options": {"temperature": 0, "num_predict": 4096},
            },
            timeout=(OLLAMA_CONNECT_TIMEOUT, OLLAMA_READ_TIMEOUT),
        )
    except requests.exceptions.ReadTimeout as exc:
        raise RuntimeError(
            f"Ollama model '{selected_model}' did not finish within "
            f"{OLLAMA_READ_TIMEOUT}s. Reduce max techniques or check "
            "system memory."
        ) from exc
    except requests.exceptions.ConnectionError as exc:
        raise RuntimeError(
            f"Could not reach Ollama at {endpoint}. Make sure Ollama "
            "is running."
        ) from exc

    response.raise_for_status()
    content = response.json().get("response")
    if not content:
        raise RuntimeError("Ollama returned an empty response.")
    return content, selected_model


def generate_candidates(
    techniques: Sequence[Dict[str, Any]],
    provider: str = "openai",
    model: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Ask the LLM for candidate chains. Validated before DB write."""
    global LAST_GENERATION_DEBUG

    prompt = build_llm_prompt(techniques)

    # DEBUG: display the exact prompt sent to the LLM
    print("\n" + "=" * 80)
    print("MODULE 11 - EXACT PROMPT SENT TO LLM")
    print("=" * 80)
    print(prompt)
    print("=" * 80)
    print()

    provider = provider.lower().strip()
    if provider == "openai":
        raw, selected_model = generate_with_openai(prompt, model)
    elif provider == "ollama":
        raw, selected_model = generate_with_ollama(prompt, model)
    else:
        raise ValueError("provider must be 'openai' or 'ollama'.")

    # DEBUG: display the exact raw response from the LLM
    print("\n" + "=" * 80)
    print("MODULE 10 \u2014 RAW LLM RESPONSE")
    print("=" * 80)
    print(raw)
    print("=" * 80)
    print()

    debug: Dict[str, Any] = {
        "provider": provider,
        "model": selected_model,
        "prompt": prompt,
        "raw_response": raw,
        "raw_candidate_count": 0,
        "validated_count": 0,
        "dropped": [],  # list of {name, reason}
    }
    LAST_GENERATION_DEBUG = debug

    parsed = _safe_json_loads(raw)
    if not isinstance(parsed, dict):
        raise RuntimeError("LLM output was not a JSON object.")
    candidates = parsed.get("candidates", [])
    if not isinstance(candidates, list):
        raise RuntimeError("LLM output does not contain a candidates list.")
    debug["raw_candidate_count"] = len(candidates)

    valid_ids = {str(t.get("id")) for t in techniques}
    validated = []
    for candidate in candidates:
        if not isinstance(candidate, dict):
            debug["dropped"].append(
                {"name": repr(candidate)[:60], "reason": "not a JSON object"}
            )
            continue
        name = str(candidate.get("candidate_name", "")).strip()
        raw_sequence = candidate.get("capability_sequence", [])
        raw_source_ids = candidate.get("source_technique_ids", [])

        if not name or not isinstance(raw_sequence, list) or not raw_sequence:
            debug["dropped"].append(
                {"name": name or "(unnamed)",
                 "reason": "missing name or empty capability_sequence"}
            )
            continue

        # Tolerant normalization: extract C1-C6 from noisy step labels.
        # A step with no extractable C1-C6 still drops (fixed ontology only).
        sequence = [_normalize_capability(c) for c in raw_sequence]
        if any(c is None for c in sequence):
            debug["dropped"].append(
                {"name": name,
                 "reason": f"unmappable capability step(s): {raw_sequence}"}
            )
            continue

        if len(sequence) < 2:
            debug["dropped"].append(
                {"name": name,
                 "reason": "single-step sequence is not compositional"}
            )
            continue

        evidence_status = str(
            candidate.get("evidence_status", "PARTIAL")
        ).upper().strip()
        if evidence_status == "INSUFFICIENT_EVIDENCE":
            debug["dropped"].append(
                {"name": name,
                 "reason": "evidence_status INSUFFICIENT_EVIDENCE "
                           "(self-declared by the LLM)"}
            )
            continue

        if not isinstance(raw_source_ids, list) or not raw_source_ids:
            debug["dropped"].append(
                {"name": name, "reason": "missing source_technique_ids"}
            )
            continue

        # Tolerant matching: case/whitespace noise and sub-technique IDs.
        # Invented IDs still drop (no fabricated provenance).
        source_ids = [_match_source_id(s, valid_ids) for s in raw_source_ids]
        if any(s is None for s in source_ids):
            debug["dropped"].append(
                {"name": name,
                 "reason": f"unknown technique ID(s): {raw_source_ids}"}
            )
            continue

        try:
            confidence = max(
                0.0, min(1.0, float(candidate.get("confidence", 0)))
            )
        except (TypeError, ValueError):
            confidence = 0.0

        validated.append({
            "candidate_name": name,
            "capability_sequence": sequence,
            "attack_goal": str(candidate.get("attack_goal", "")),
            "source_technique_ids": source_ids,
            "evidence_summary": str(candidate.get("evidence_summary", "")),
            "llm_confidence": confidence,
            "llm_rationale": str(candidate.get("rationale", "")),
            "evidence_status": evidence_status,
            "llm_provider": provider,
            "llm_model": selected_model,
        })

    debug["validated_count"] = len(validated)

    # DEBUG: summary + drop reasons to terminal
    print(
        f"candidates: {debug['raw_candidate_count']} raw, "
        f"{len(validated)} validated, {len(debug['dropped'])} dropped"
    )
    for item in debug["dropped"]:
        print(f"  DROPPED: {item['name']} \u2014 {item['reason']}")

    return validated


def _candidate_id(candidate: Dict[str, Any]) -> str:
    canonical = json.dumps(
        {
            "name": candidate.get("candidate_name"),
            "sequence": candidate.get("capability_sequence"),
            "source_ids": sorted(candidate.get("source_technique_ids", [])),
        },
        sort_keys=True,
    )
    return "TC-" + hashlib.sha256(canonical.encode()).hexdigest()[:12]


def store_candidates(
    db_path: str | Path, candidates: Sequence[Dict[str, Any]]
) -> List[str]:
    """Insert candidates as PENDING. Deterministic IDs prevent duplicates."""
    conn = sqlite3.connect(str(db_path))
    inserted: List[str] = []
    try:
        _ensure_tables(conn)
        for candidate in candidates:
            candidate_id = _candidate_id(candidate)
            conn.execute(
                "INSERT OR IGNORE INTO candidate_patterns "
                "(candidate_id, candidate_name, capability_sequence, "
                " attack_goal, source_type, source_technique_ids, "
                " evidence_summary, llm_provider, llm_model, llm_confidence, "
                " llm_rationale, status, created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,'PENDING',?)",
                (
                    candidate_id,
                    candidate["candidate_name"],
                    _json(candidate["capability_sequence"]),
                    candidate.get("attack_goal", ""),
                    "MITRE_DERIVED",
                    _json(candidate["source_technique_ids"]),
                    candidate.get("evidence_summary", ""),
                    candidate.get("llm_provider", ""),
                    candidate.get("llm_model", ""),
                    candidate.get("llm_confidence", 0.0),
                    candidate.get("llm_rationale", ""),
                    _utc_now(),
                ),
            )
            for technique_id in candidate["source_technique_ids"]:
                conn.execute(
                    "INSERT OR IGNORE INTO candidate_pattern_evidence "
                    "VALUES (?,?,?)",
                    (candidate_id, technique_id, "SOURCE_EVIDENCE"),
                )
            inserted.append(candidate_id)
        conn.commit()
    finally:
        conn.close()
    return inserted


# ---------------------------------------------------------------- review


def get_pending_candidates(db_path: str | Path) -> List[Dict[str, Any]]:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        _ensure_tables(conn)
        rows = conn.execute(
            "SELECT * FROM candidate_patterns WHERE status='PENDING' "
            "ORDER BY created_at DESC"
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def review_candidate(
    db_path: str | Path,
    candidate_id: str,
    decision: str,
    reviewer: str,
    review_comment: str = "",
    severity: str = "Unrated",
) -> Dict[str, Any]:
    """Human review gate. ACCEPT promotes; REJECT/MERGE never do."""
    decision = decision.upper().strip()
    if decision not in {"ACCEPT", "REJECT", "MERGE"}:
        raise ValueError("decision must be ACCEPT, REJECT, or MERGE.")
    if not reviewer.strip():
        raise ValueError("Reviewer name is required.")

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        _ensure_tables(conn)
        candidate = conn.execute(
            "SELECT * FROM candidate_patterns WHERE candidate_id=?",
            (candidate_id,),
        ).fetchone()
        if candidate is None:
            raise KeyError(f"Candidate not found: {candidate_id}")
        if candidate["status"] != "PENDING":
            raise RuntimeError(
                f"Candidate {candidate_id} is already {candidate['status']}."
            )

        now = _utc_now()

        if decision in {"REJECT", "MERGE"}:
            status = "REJECTED" if decision == "REJECT" else "MERGED"
            conn.execute(
                "UPDATE candidate_patterns SET status=?, reviewer=?, "
                "review_timestamp=?, review_comment=? WHERE candidate_id=?",
                (status, reviewer, now, review_comment, candidate_id),
            )
            conn.commit()
            return {"status": status, "candidate_id": candidate_id}

        # ACCEPT: promote to attack_patterns.
        # CIA fields are intentionally left NULL; classify via the existing
        # risk-analysis workflow, not from LLM output.
        pattern_id = _next_pattern_id(conn)
        source_ids = json.loads(candidate["source_technique_ids"])
        llm_confidence = float(candidate["llm_confidence"] or 0)
        confidence_label = (
            "High" if llm_confidence >= 0.80
            else "Medium" if llm_confidence >= 0.60
            else "Low"
        )
        conn.execute(
            "INSERT INTO attack_patterns "
            "(pattern_id, pattern_name, capability_sequence, attack_goal, "
            " supporting_papers, evidence_type, confidence, "
            " evidence_summary, module_6_eligibility, severity) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                pattern_id,
                candidate["candidate_name"],
                candidate["capability_sequence"],
                candidate["attack_goal"],
                "MITRE ATLAS: " + ", ".join(source_ids),
                "PARTIAL",
                confidence_label,
                (
                    "MITRE-derived candidate synthesized by "
                    f"{candidate['llm_provider']} "
                    f"({candidate['llm_model']}). "
                    "Human-approved. " + candidate["evidence_summary"]
                ),
                "ELIGIBLE_SYNTHESIZED",
                severity,
            ),
        )
        conn.execute(
            "UPDATE candidate_patterns SET status='ACCEPTED', reviewer=?, "
            "review_timestamp=?, review_comment=? WHERE candidate_id=?",
            (reviewer, now, review_comment, candidate_id),
        )
        conn.commit()
        return {
            "status": "ACCEPTED",
            "candidate_id": candidate_id,
            "pattern_id": pattern_id,
        }
    finally:
        conn.close()


# ---------------------------------------------------------------- pipeline


def run(
    db_path: str | Path = "capability_ontology.db",
    provider: str = "openai",
    model: Optional[str] = None,
    max_techniques: int = DEFAULT_MAX_TECHNIQUES,
) -> Dict[str, Any]:
    """Acquire + synthesize. Never auto-promotes; use review_candidate()."""
    db_path = Path(db_path)
    if not db_path.exists():
        raise FileNotFoundError(f"Database not found: {db_path}")

    global LAST_ACQUISITION_DEBUG

    atlas_data = fetch_atlas()
    all_extracted = _extract_techniques(atlas_data)
    tactic_names = _extract_tactic_names(atlas_data)
    techniques = filter_relevant_techniques(atlas_data)
    filtered_count = len(techniques)
    techniques = sorted(
        techniques,
        key=lambda t: (
            "Agentic AI" not in t.get("platforms", []),
            not any(x in RELEVANT_TACTICS for x in t.get("_tactics", [])),
        ),
    )[:max_techniques]

    # DEBUG: acquisition statistics
    tactic_distribution: Dict[str, int] = {}
    for t in techniques:
        for tac in (t.get("_tactics") or ["(no tactic)"]):
            tactic_distribution[tac] = tactic_distribution.get(tac, 0) + 1
    LAST_ACQUISITION_DEBUG = {
        "techniques_extracted_total": len(all_extracted),
        "tactic_names_found": len(tactic_names),
        "techniques_after_filter": filtered_count,
        "techniques_sent_count": len(techniques),
        "techniques_sent_ids": [str(t.get("id")) for t in techniques],
        "tactic_distribution": tactic_distribution,
    }
    print(
        f"MODULE 10 \u2014 ATLAS parse: {len(all_extracted)} techniques "
        f"extracted, {len(tactic_names)} tactic names resolved, "
        f"{filtered_count} after filter, {len(techniques)} sent to LLM"
    )
    print(f"  Sent IDs: {LAST_ACQUISITION_DEBUG['techniques_sent_ids']}")

    source_info = store_atlas_source(db_path, atlas_data, techniques)
    candidates = generate_candidates(techniques, provider, model)
    candidate_ids = store_candidates(db_path, candidates)

    return {
        "module": MODULE_NAME,
        "source": source_info,
        "techniques_retrieved": len(techniques),
        "candidates_generated": len(candidates),
        "candidate_ids": candidate_ids,
        "human_review_required": True,
        "attack_patterns_promoted": 0,
        "message": (
            "Candidates stored as PENDING. No candidate was automatically "
            "promoted to attack_patterns."
        ),
    }


# ---------------------------------------------------------------- UI


def render(db_path: str | Path = "capability_ontology.db") -> None:
    """Render the Module 10 Streamlit tab."""
    import streamlit as st

    st.header("Module 10 \u2014 Threat Chain Knowledge Curation")
    st.write(
        "Retrieve MITRE ATLAS threat knowledge, generate candidate "
        "compositional attack patterns using an LLM, and require human "
        "approval before updating the attack-pattern database."
    )
    st.info(
        "MITRE techniques are evidence. The C1-C6 chain is a framework-level "
        "synthesis and is never treated as a MITRE-defined attack chain."
    )

    # Flash message surviving the post-review rerun
    flash = st.session_state.pop("m11_flash", None)
    if flash:
        kind, text = flash
        (st.success if kind == "success" else st.error)(text)

    # 1. Source + settings
    st.subheader("1. Threat Knowledge Source")
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("**Source:** MITRE ATLAS")
        st.caption("Official MITRE threat knowledge for AI systems.")
        st.markdown(f"[Open MITRE ATLAS]({ATLAS_WEB_URL})")
    with col2:
        provider = st.selectbox(
            "LLM Provider", ["OpenAI", "Ollama"], key="m10_provider"
        )
        if provider == "OpenAI":
            model = st.text_input(
                "OpenAI model",
                value=os.getenv("OPENAI_MODEL", DEFAULT_OPENAI_MODEL),
                key="m10_openai_model",
            )
        else:
            model = st.text_input(
                "Ollama model",
                value=os.getenv("OLLAMA_MODEL", DEFAULT_OLLAMA_MODEL),
                key="m10_ollama_model",
            )
    max_techniques = st.slider(
        "Max MITRE techniques sent to the LLM",
        min_value=1, max_value=30, value=DEFAULT_MAX_TECHNIQUES,
        key="m10_max_techniques",
        help="Lower values keep local Ollama generation fast.",
    )

    # 2. Acquisition
    st.subheader("2. Retrieve Threat Knowledge")
    if st.button(
        "Fetch MITRE ATLAS + Generate Candidates",
        type="primary",
        use_container_width=True,
        key="m10_fetch",
    ):
        provider_key = "openai" if provider == "OpenAI" else "ollama"
        try:
            with st.status("Running Module 10...", expanded=True) as status:
                st.write("Fetching official MITRE ATLAS data...")
                result = run(
                    db_path=db_path,
                    provider=provider_key,
                    model=model,
                    max_techniques=int(max_techniques),
                )
                st.write("Relevant threat techniques stored.")
                st.write(
                    f"Generated {result['candidates_generated']} "
                    "candidate pattern(s)."
                )
                st.write("Candidates remain PENDING until human review.")
                status.update(
                    label="Module 10 acquisition complete", state="complete"
                )
            st.success("Threat knowledge acquired and candidates staged.")

            # DEBUG: generation diagnostics (raw output + drop reasons)
            debug = LAST_GENERATION_DEBUG
            if debug:
                with st.expander(
                    "\U0001f50d LLM generation diagnostics", expanded=True
                ):
                    acq = LAST_ACQUISITION_DEBUG
                    if acq:
                        st.write(
                            f"ATLAS techniques extracted: "
                            f"**{acq.get('techniques_extracted_total', '?')}**"
                            f" \u00b7 Tactic names resolved: "
                            f"**{acq.get('tactic_names_found', '?')}** \u00b7 "
                            f"After filter: "
                            f"**{acq.get('techniques_after_filter', '?')}** "
                            f"\u00b7 Sent to LLM: "
                            f"**{acq.get('techniques_sent_count', '?')}**"
                        )
                        if acq.get("techniques_sent_ids"):
                            st.caption(
                                "Sent: "
                                + ", ".join(acq["techniques_sent_ids"])
                            )
                        if acq.get("tactic_distribution"):
                            st.caption(
                                f"Tactic mix: {acq['tactic_distribution']}"
                            )
                    st.write(
                        f"**Provider:** {debug.get('provider')} \u00b7 "
                        f"**Model:** {debug.get('model')}"
                    )
                    st.write(
                        f"Raw candidates returned: "
                        f"**{debug.get('raw_candidate_count', 0)}** \u00b7 "
                        f"Passed validation: "
                        f"**{debug.get('validated_count', 0)}** \u00b7 "
                        f"Dropped: **{len(debug.get('dropped', []))}**"
                    )
                    if debug.get("dropped"):
                        st.markdown("**Dropped candidates:**")
                        for item in debug["dropped"]:
                            st.write(
                                f"\u2022 {item['name']} \u2014 "
                                f"{item['reason']}"
                            )
                    if (
                        debug.get("raw_candidate_count", 0) > 0
                        and debug.get("validated_count", 0) > 0
                        and result["candidates_generated"] > 0
                        and not get_pending_candidates(db_path)
                    ):
                        st.info(
                            "Candidates were generated but none are "
                            "PENDING \u2014 identical candidates were "
                            "already reviewed earlier (deterministic "
                            "dedup keeps their existing status)."
                        )
                    st.markdown("**Raw LLM response:**")
                    st.code(
                        str(debug.get("raw_response", ""))[:4000],
                        language="json",
                    )
        except Exception as exc:
            st.error(f"Module 10 failed: {exc}")
            st.exception(exc)
            # DEBUG: show whatever was captured before the failure
            debug = LAST_GENERATION_DEBUG
            if debug:
                with st.expander(
                    "\U0001f50d LLM generation diagnostics (at failure)"
                ):
                    st.markdown("**Raw LLM response:**")
                    st.code(
                        str(debug.get("raw_response", ""))[:4000],
                        language="json",
                    )

    # 3. Human review queue
    st.divider()
    st.subheader("3. Human Review Queue")
    try:
        pending = get_pending_candidates(db_path)
    except Exception as exc:
        st.error(f"Could not load review queue: {exc}")
        return

    if not pending:
        st.success("No pending candidates require review.")
    else:
        st.warning(f"{len(pending)} candidate(s) require human review.")

    for candidate in pending:
        candidate_id = candidate["candidate_id"]
        sequence = json.loads(candidate["capability_sequence"])
        source_ids = json.loads(candidate["source_technique_ids"])

        with st.expander(f"{candidate_id} \u2014 {candidate['candidate_name']}"):
            st.markdown("**Proposed capability composition:**")
            st.code(" \u2192 ".join(sequence))
            st.markdown("**Attack goal:**")
            st.write(candidate["attack_goal"])

            c1, c2, c3 = st.columns(3)
            c1.metric(
                "LLM confidence",
                f"{float(candidate['llm_confidence'] or 0):.2f}",
            )
            c2.metric("Provider", candidate["llm_provider"])
            c3.metric("Model", candidate["llm_model"])

            st.markdown("**MITRE source techniques:**")
            for technique_id in source_ids:
                st.markdown(
                    f"- [{technique_id}]"
                    "(https://atlas.mitre.org/techniques/"
                    + technique_id + "/)"
                )

            st.markdown("**Evidence summary:**")
            st.write(candidate["evidence_summary"])
            st.markdown("**LLM rationale:**")
            st.write(candidate["llm_rationale"])
            st.caption(
                "The LLM rationale is advisory evidence, not authoritative "
                "ground truth."
            )

            st.markdown("### Human Decision")
            # st.form batches all inputs: typing/selecting no longer
            # triggers app reruns. Only the submit button does.
            with st.form(key=f"review_form_{candidate_id}"):
                reviewer = st.text_input(
                    "Reviewer", key=f"reviewer_{candidate_id}"
                )
                decision = st.radio(
                    "Decision", ["ACCEPT", "REJECT", "MERGE"],
                    horizontal=True, key=f"decision_{candidate_id}",
                )
                severity = st.selectbox(
                    "Project severity",
                    ["Unrated", "Low", "Medium", "High"],
                    key=f"severity_{candidate_id}",
                )
                review_comment = st.text_area(
                    "Review comment", key=f"comment_{candidate_id}"
                )
                st.caption(
                    "ACCEPT creates a new pattern in attack_patterns with "
                    "the C1-C6 sequence and MITRE provenance. REJECT and "
                    "MERGE never promote."
                )
                submitted = st.form_submit_button(
                    "Submit decision", type="primary"
                )

            if submitted:
                try:
                    result = review_candidate(
                        db_path=db_path,
                        candidate_id=candidate_id,
                        decision=decision,
                        reviewer=reviewer,
                        review_comment=review_comment,
                        severity=severity,
                    )
                    if result["status"] == "ACCEPTED":
                        message = (
                            f"Candidate {candidate_id} approved and "
                            f"promoted as {result['pattern_id']}."
                        )
                    else:
                        message = (
                            f"Candidate {candidate_id} marked "
                            f"{result['status']}."
                        )
                    st.session_state["m10_flash"] = ("success", message)
                    st.rerun()
                except Exception as exc:
                    st.error(f"Review failed: {exc}")

    # 4. Provenance
    st.divider()
    st.subheader("4. Database Provenance")
    conn = sqlite3.connect(str(db_path))
    try:
        rows = conn.execute(
            "SELECT pattern_id, pattern_name, capability_sequence, "
            "evidence_type, confidence, severity FROM attack_patterns "
            "ORDER BY pattern_id"
        ).fetchall()
    finally:
        conn.close()

    if rows:
        display_rows = []
        for row in rows:
            try:
                seq_text = " \u2192 ".join(json.loads(row[2]))
            except Exception:
                seq_text = str(row[2])
            display_rows.append({
                "Pattern": row[0],
                "Name": row[1],
                "Capability Sequence": seq_text,
                "Evidence Type": row[3],
                "Confidence": row[4],
                "Severity": row[5],
            })
        st.dataframe(display_rows, use_container_width=True)
        st.caption(
            "MITRE-derived patterns remain distinguishable from the "
            "project's original literature-backed patterns through their "
            "evidence and provenance fields."
        )