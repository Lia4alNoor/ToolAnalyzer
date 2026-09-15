"""
Module 3: Capability Normalization & Mapping
(combined former Module 3 + former Module 4)

Step A (former Module 3):
    Normalizes tool names and descriptions into canonical concepts
    using the canon_normalizer vocabulary.

Step B (former Module 4):
    Maps the normalized concepts onto the fixed C1-C6 ontology.

Output contract:
    The union of the former Module 3 and Module 4 outputs. Each tool
    carries BOTH 'normalized' and 'mapping', and the top-level result
    carries both sets of completion flags, so Module 5 and all later
    modules require no changes.
"""

from modules.modules.capability_normalizer import normalize_tool

# ---------------------------------------------------------------------------
# FIXED C1-C6 ONTOLOGY
# Do NOT modify this
# ---------------------------------------------------------------------------
CAPABILITY_ONTOLOGY = {
    "C1": {
        "id": "C1",
        "canonical": "External Data Ingestion",
        "definition": "Ability to retrieve or ingest data/content from external or potentially untrusted sources into the agent's context."
    },
    "C2": {
        "id": "C2",
        "canonical": "Sensitive Data Access",
        "definition": "Ability to read or retrieve private, sensitive, local, or user-specific data."
    },
    "C3": {
        "id": "C3",
        "canonical": "External Communication",
        "definition": "Ability to transmit, send, publish, or communicate data to an external service, endpoint, or recipient."
    },
    "C4": {
        "id": "C4",
        "canonical": "State Modification",
        "definition": "Ability to create, modify, update, or delete persistent system/application/environment state."
    },
    "C5": {
        "id": "C5",
        "canonical": "System Execution",
        "definition": "Ability to execute commands, scripts, programs, or code on the underlying system/environment."
    },
    "C6": {
        "id": "C6",
        "canonical": "Physical Actuation",
        "definition": "Ability to control hardware, IoT devices, or physical systems causing real-world changes."
    }
}


def run(input_data):
    """
    Main entry point for the combined Module 3+4.

    Args:
        input_data (dict): Output from Module 2 (tools with
            assumed_capability and capability_features).

    Returns:
        dict: Tools with normalized canonical capabilities AND
              C1-C6 ontology mappings.
    """
    print("=" * 70)
    print("Module 3: Capability Normalization & Mapping (combined 3+4)")
    print("=" * 70)
    return process(input_data)
def process(data):
    """
    Normalize all tools, then map them to C1-C6, in one pass per tool.
    """
    if not data:
        return None

    tools = data.get('tools', [])

    print(f"\nNormalizing and mapping {len(tools)} tools "
          f"(canon_normalizer -> C1-C6)...\n")

    processed_tools = []
    for tool in tools:
        normalized_tool = normalize_tool_complete(tool)
        mapped_tool = map_tool_to_ontology(normalized_tool)
        processed_tools.append(mapped_tool)

        primary = mapped_tool.get('mapping', {}).get('primary_capability') or 'UNMAPPED'
        all_caps = mapped_tool.get('mapping', {}).get('all_capabilities', [])
        print(f"  [+] {tool['tool']:<30} \u2192 Primary: {primary}, Mapped: {all_caps}")

    result = {
        'tools': processed_tools,
        'tool_count': len(processed_tools),
        'source_file': data.get('source_file'),
        # Former Module 3 flags
        'normalization_complete': True,
        'normalizer_vocab': 'canon_normalizer',
        # Former Module 4 flags
        'mapping_complete': True,
        'ontology': 'C1-C6',
        'ontology_size': len(CAPABILITY_ONTOLOGY),
    }

    print(f"\n\u2713 Normalization + mapping complete: "
          f"{len(processed_tools)} tools mapped to C1-C6")

    return result


def normalize_tool_complete(tool):
    """
    Normalize a tool using the canon_normalizer vocabulary
    (former Module 3 logic, unchanged).
    """
    norm_result = normalize_tool(tool)

    normalized = {
        'primary_capability': norm_result.get('primary_capability'),
        'all_capabilities': norm_result.get('all_capabilities') or [],
        'matched_expressions': [m['matched_expression'] for m in norm_result.get('normalized_matches', [])],
        'normalized_concepts': [m['canonical'] for m in norm_result.get('normalized_matches', [])],
        'confidence': norm_result.get('confidence_score', 0.0),
        'matches': norm_result.get('normalized_matches', []),
        'evidence': norm_result.get('evidence', '')
    }

    result = dict(tool)
    result['normalized'] = normalized
    result['assumed_capability'] = tool.get('assumed_capability', '')

    return result


def map_tool_to_ontology(tool):
    """
    Map a normalized tool to the C1-C6 ontology
    (former Module 4 logic, unchanged).
    """
    result = dict(tool)

    normalized = tool.get('normalized', {})
    primary_capability = normalized.get('primary_capability')
    all_capabilities = normalized.get('all_capabilities') or []
    matches = normalized.get('matches', [])

    mapping = {
        'primary_capability': primary_capability,
        'all_capabilities': all_capabilities,
        'mappings': []
    }

    if primary_capability and primary_capability in CAPABILITY_ONTOLOGY:
        mapping['primary_definition'] = CAPABILITY_ONTOLOGY[primary_capability]['definition']
    else:
        mapping['primary_definition'] = 'UNMAPPED - No matching canonical capability'

    for cap_id in all_capabilities:
        if cap_id in CAPABILITY_ONTOLOGY:
            ontology_entry = CAPABILITY_ONTOLOGY[cap_id]

            matched_expr = None
            confidence = 0.0
            for match in matches:
                if match['capability_id'] == cap_id:
                    matched_expr = match['matched_expression']
                    confidence = match['confidence']
                    break

            mapping['mappings'].append({
                'capability_id': cap_id,
                'canonical': ontology_entry['canonical'],
                'definition': ontology_entry['definition'],
                'normalized_match': matched_expr,
                'confidence': confidence,
                'reason': f"Normalized expression '{matched_expr}' matches {cap_id} {ontology_entry['canonical']}"
            })

    if primary_capability:
        evidence = normalized.get('evidence', '')
        matched_exprs = ', '.join(normalized.get('matched_expressions', []))
        mapping['mapping_reason'] = f"Tool matches: {matched_exprs}. Evidence: {evidence}"
        mapping['is_ambiguous'] = len(all_capabilities) > 1
    else:
        mapping['mapping_reason'] = 'No normalized capabilities found - UNMAPPED'
        mapping['is_ambiguous'] = False

    result['mapping'] = mapping

    return result


def get_capability_definition(capability_id):
    """Get the definition for a specific capability (C1-C6)."""
    return CAPABILITY_ONTOLOGY.get(capability_id)


def get_all_capabilities():
    """Get the complete C1-C6 ontology."""
    return CAPABILITY_ONTOLOGY


def is_valid_capability(capability_id):
    """Check if a capability ID is valid (C1-C6)."""
    return capability_id in CAPABILITY_ONTOLOGY