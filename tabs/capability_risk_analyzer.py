import os
import sqlite3
import tempfile

import pandas as pd
import streamlit as st

from modules.modules import (
    module_1_server_selection,
    module_2_capability_extraction,
    module_3_capability_normalization,
    module_5_ontology_database,
    module_6_composition_analysis,
    module_7_attack_pattern_analysis,
    module_8_risk_assessment,
    module_9_report_generation
)

# New in this revision. The TDP scanner and the MCP metadata retriever are
# deliberately kept outside the capability pipeline package: capability
# identification (Modules 1-3) is unchanged by them.
from modules import (
    mcp_toolinfo_Retriever,
    module_tdp_scanner,
    tool_source_locator,
)
from modules.capability_lexicon_loader import LexiconError

from pathlib import Path

# Resolved relative to the project so the preloaded dataset works on any
# machine (the previous absolute Windows path only existed on one laptop).
DEFAULT_FILE = (
    Path(__file__).resolve().parent.parent
    / "data"
    / "created_toolsc1_c6.json"
)

INPUT_MODE_UPLOAD = "Upload JSON"
INPUT_MODE_MCP = "Connect to MCP Server"
CAPABILITY_SEED = module_5_ontology_database.CAPABILITY_SEED


CAPABILITY_INFO = {
    cap_id: {
        "name": name,
        "definition": definition,
        "example_risk": example_risk,
    }
    for cap_id, name, definition, example_risk in CAPABILITY_SEED
}


def describe_capability(cap_id):
    """Format capability ID with name. E.g., 'C4 (State Modification)'."""
    info = CAPABILITY_INFO.get(cap_id)

    return (
        f"{cap_id} ({info['name']})"
        if info
        else str(cap_id)
    )


def describe_sequence(cap_sequence):
    """Format capability sequence with arrows. E.g., 'C1 → C2 → C3'."""
    if not isinstance(cap_sequence, list):
        return str(cap_sequence)

    return " → ".join(
        describe_capability(step)
        for step in cap_sequence
    )

def render_tool_metadata_and_classification(tool):
    """
    Renders, for one tool: the metadata it was defined with, and the
    reasoning behind each C1-C6 verdict it received. Call inside an
    st.expander() for that tool.
    """
    col_meta, col_class = st.columns(2)

    with col_meta:
        st.markdown("**Metadata provided**")

        st.caption(tool.get("description") or "No description provided.")

        render_hint_badges(tool)

    with col_class:
        st.markdown("**Why this classification**")

        mapping = tool.get("mapping", {}) or {}
        mappings_list = mapping.get("mappings", [])

        if mappings_list:
            for entry in mappings_list:
                cap_label = describe_capability(entry.get("capability_id"))
                confidence_label = module_5_ontology_database._numeric_to_level(
                    entry.get("confidence")
                )

                st.markdown(f"**{cap_label}**")
                st.write(
                    f"Confidence: {confidence_label} "
                    f"({entry.get('confidence', 0):.2f})"
                )

                if entry.get("normalized_match"):
                    st.write(f"Matched expression: \"{entry['normalized_match']}\"")

                st.caption(entry.get("reason", "No reason recorded."))

            if mapping.get("is_ambiguous"):
                st.warning(
                    "Matched more than one capability — treated as ambiguous."
                )
        else:
            st.info(
                mapping.get(
                    "mapping_reason",
                    "No normalized capabilities found - UNMAPPED",
                )
            )
# =========================================================
# CAPABILITY RISK ANALYZER
# =========================================================


def render():

    # =========================================================
    # SESSION STATE
    # =========================================================

    if "analysis_result" not in st.session_state:
        st.session_state.analysis_result = None

    if "report_text" not in st.session_state:
        st.session_state.report_text = None

    if "show_curation" not in st.session_state:
        st.session_state.show_curation = False



    # =========================================================
    # FILE UPLOAD
    # =========================================================

    st.header("Capability Risk Analyzer")

    st.caption(
        "Upload MCP tool metadata to analyse tool capabilities, "
        "capability composition, CIA impact, and mitigation coverage."
    )
    input_mode = st.radio(
        "Input source for Module 1",
        options=[INPUT_MODE_UPLOAD, INPUT_MODE_MCP],
        horizontal=True,
        key="input_mode",
        help=(
            "The two options are mutually exclusive and both feed the same "
            "Module 1 - Module 2 - Module 3 pipeline. Connecting to a server "
            "reads declared metadata only; no tool is executed."
        ),
    )

    uploaded_file = None

    if input_mode == INPUT_MODE_UPLOAD:
        uploaded_file = render_upload_input()
    else:
        render_mcp_input()

    mcp_retrieval = st.session_state.get("mcp_retrieval")

    can_run = True

    if input_mode == INPUT_MODE_MCP and not mcp_retrieval:
        st.info(
            "Retrieve tool metadata from an MCP server above, then run the "
            "analysis."
        )
        can_run = False

    # =========================================================
    # RUN PIPELINE
    # =========================================================

    if st.button(
            "Run Security Analysis",
            type="primary",
            use_container_width=True,
            disabled=not can_run,
    ):

        with tempfile.TemporaryDirectory() as temp_dir:

            # ---------------------------------------------------------
            #Module 1 receives the same kind of input whether
            # the tools came from an upload or from a live MCP server.
            # ---------------------------------------------------------

            try:

                input_path, input_source = prepare_pipeline_input(
                    temp_dir,
                    input_mode,
                    uploaded_file,
                    st.session_state.get("mcp_retrieval"),
                )

            except Exception as preparation_error:

                st.error(
                    f"Could not prepare the pipeline input: "
                    f"{preparation_error}"
                )

                return

            st.caption(f"Input source: {input_source}")

            try:

                with st.status(
                    "Running AgentPreDeployer...",
                    expanded=True,
                ) as status:

                    st.write(
                        "Module 1 — Server discovery"
                    )

                    result_1 = (
                        module_1_server_selection.run(
                            input_path
                        )
                    )


                    st.write(
                        "Module 2 — Capability extraction"
                    )

                    result_2 = (
                        module_2_capability_extraction.run(
                            result_1
                        )
                    )


                    st.write(
                        "Module 3 — Capability normalization"
                    )

                    result_3 = (
                        module_3_capability_normalization.run(
                            result_2
                        )
                    )


                    st.write(
                        "Module 5 — Ontology database"
                    )

                    result_5 = (
                        module_5_ontology_database.run(
                            result_3
                        )
                    )


                    st.write(
                        "Module 6 — Composition analysis"
                    )

                    result_6 = (
                        module_6_composition_analysis.run(
                            result_5
                        )
                    )


                    st.write(
                        "Module 7 — Attack pattern analysis"
                    )

                    result_7 = (
                        module_7_attack_pattern_analysis.run(
                            result_6
                        )
                    )


                    st.write(
                        "Module 8 — Risk assessment"
                    )

                    result_8 = (
                        module_8_risk_assessment.run(
                            result_7
                        )
                    )


                    st.write(
                        "Module 9 — Report generation"
                    )

                    result_9 = (
                        module_9_report_generation.run(
                            result_8
                        )
                    )


                    status.update(
                        label="Analysis complete",
                        state="complete",
                    )


                st.session_state.analysis_result = result_9


                generated_report_path = (
                    result_9.get(
                        "final_report_path"
                    )
                )


                if generated_report_path:

                    report_path = Path(
                        generated_report_path
                    )

                    if report_path.exists():

                        st.session_state.report_text = (
                            report_path.read_text(
                                encoding="utf-8"
                            )
                        )


                st.success(
                    "Security assessment completed successfully."
                )


            except LexiconError as lexicon_error:

                st.error(
                    "Capability identification could not run because the "
                    "capability lexicon could not be loaded."
                )

                st.code(str(lexicon_error))

                st.info(
                    "Fix the affected file in capability_lexicon/ (or repair "
                    "it in Edit Database - Capability lexicon) and run the "
                    "analysis again. No hardcoded fallback rules are used."
                )

            except Exception as e:

                st.error(
                    f"Analysis failed: {e}"
                )

                st.exception(e)


    # =========================================================
    # RESULTS
    # =========================================================

    analysis_result = (
        st.session_state.analysis_result
    )

    if analysis_result is None:

        st.info(
            "Run the security analysis above to view results."
        )

        return


    # =========================================================
    # EXTRACT MODULE OUTPUTS
    # =========================================================

    all_tools = analysis_result.get(
        "tools",
        []
    )


    composition_analysis_data = (
        analysis_result.get(
            "composition_analysis",
            {}
        )
    )


    mitigation_assessment_data = (
        analysis_result.get(
            "mitigation_assessment",
            {}
        )
    )


    # =========================================================
    # EXTRACT ALL TOOL NAMES
    # =========================================================

    all_tool_names = {
        tool.get(
            "tool",
            "Unknown tool"
        )
        for tool in all_tools
        if isinstance(tool, dict)
    }

    #Tool LookUP Feature
    tool_lookup = {}
    for tool in all_tools:
        if isinstance(tool, dict):
            tool_lookup.setdefault(tool.get("tool", "Unknown tool"), tool)



    # =========================================================
    # BUILD CAPABILITY PROFILE
    # =========================================================

    capability_to_tools = {}


    for tool in all_tools:

        if not isinstance(tool, dict):
            continue


        tool_name = tool.get(
            "tool",
            "Unknown tool"
        )


        tool_mapping = tool.get(
            "mapping",
            {}
        )


        tool_mappings_list = (
            tool_mapping.get(
                "mappings",
                []
            )
        )


        if not isinstance(
            tool_mappings_list,
            list,
        ):
            continue


        for mapping_entry in tool_mappings_list:

            if not isinstance(
                mapping_entry,
                dict,
            ):
                continue


            cap_id = mapping_entry.get(
                "capability_id"
            )


            if cap_id:

                capability_to_tools.setdefault(
                    cap_id,
                    set(),
                ).add(
                    tool_name
                )


    # =========================================================
    # EXTRACT DETECTIONS & GAPS
    # =========================================================

    matched_compositions = (
        composition_analysis_data.get(
            "detections",
            []
        )
    )


    if not isinstance(
        matched_compositions,
        list,
    ):
        matched_compositions = []


    matched_mitigations = (
        mitigation_assessment_data.get(
            "matched_composition_assessments",
            []
        )
    )


    if not isinstance(
        matched_mitigations,
        list,
    ):
        matched_mitigations = []


    open_mitigation_gaps = (
        mitigation_assessment_data.get(
            "open_mitigation_gaps",
            []
        )
    )


    if not isinstance(
        open_mitigation_gaps,
        list,
    ):
        open_mitigation_gaps = []


    # =========================================================
    # OVERVIEW METRICS
    # =========================================================

    st.header(
        "Assessment Overview"
    )


    metric_col1, metric_col2, metric_col3, metric_col4 = (
        st.columns(4)
    )


    with metric_col1:

        st.metric(
            "Tools Analysed",
            len(all_tools),
        )


    with metric_col2:

        st.metric(
            "Capabilities Found",
            len(capability_to_tools),
        )


    with metric_col3:

        st.metric(
            "Matched Compositions",
            len(matched_compositions),
        )


    with metric_col4:

        st.metric(
            "Open Gaps",
            len(open_mitigation_gaps),
        )


    # =========================================================
    # RESULTS TABS
    # =========================================================

    result_tab_1, result_tab_2, result_tab_3, result_tab_4, result_tab_5 = (
        st.tabs(
            [
                "Tools & Capabilities",
                "Composition Analysis & CIA Risk",
                "Mitigations",
                "Interpretation Limits",
                "Final Report",
            ]
        )
    )


    # =========================================================
    # TAB 1: TOOLS & CAPABILITIES
    # =========================================================

    with result_tab_1:

        # =====================================================
        # IDENTIFIED TOOLS
        # =====================================================

        st.header(
            "Identified Tools with"
        )


        st.caption(
            f"Total: {len(all_tool_names)} tool(s) analysed"
        )

        if all_tool_names:

            for tool_name in sorted(all_tool_names):

                tool = tool_lookup.get(tool_name, {})

                # ---------------------------------------------------------
                # Determine main capability
                # ---------------------------------------------------------

                mappings = (
                    tool.get("mapping", {})
                    .get("mappings", [])
                )

                valid_mappings = [
                    m for m in mappings
                    if isinstance(m, dict)
                       and m.get("capability_id")
                ]

                if valid_mappings:

                    # Main capability = highest-confidence mapping
                    main_mapping = max(
                        valid_mappings,
                        key=lambda m: float(
                            m.get("confidence", 0)
                        ),
                    )

                    main_capability_id = main_mapping.get(
                        "capability_id"
                    )

                    main_capability_name = CAPABILITY_INFO.get(
                        main_capability_id,
                        {}
                    ).get(
                        "name",
                        "Unknown"
                    )

                else:

                    main_capability_id = None
                    main_capability_name = "Unmapped"

                # ---------------------------------------------------------
                # Tool header
                # ---------------------------------------------------------

                if main_capability_id:

                    st.markdown(
                        f"""
                        <div class="tool-header">
                            <span class="tool-name">{tool_name}</span>
                            <span class="capability-badge">
                                {main_capability_id} · {main_capability_name}
                            </span>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

                else:

                    st.markdown(
                        f"""
                        <div class="tool-header">
                            <span class="tool-name">{tool_name}</span>
                            <span class="capability-badge capability-unmapped">
                                Unmapped
                            </span>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

                # ---------------------------------------------------------
                # Tool details
                # ---------------------------------------------------------

                with st.expander("View metadata & classification"):

                    render_tool_metadata_and_classification(tool)

                with st.expander(
                    "Implementation source & TDP scan"
                ):

                    render_tool_source_and_tdp(tool)

        else:

            st.info("No tools identified.")


        # =====================================================
        # ANALYSIS: CAPABILITY & TOOL MAPPING
        # =====================================================

        st.header(
            "Capability Analysis"
        )


        st.caption(
            "Which capabilities each tool implements"
        )


        mapped_tool_names = (
            set().union(
                *capability_to_tools.values()
            )
            if capability_to_tools
            else set()
        )


        unmapped_tool_names = sorted(
            all_tool_names
            - mapped_tool_names
        )


        # Capability Profile

        if capability_to_tools:

            for cap_id, tool_set in sorted(
                capability_to_tools.items()
            ):

                tool_count = len(
                    tool_set
                )


                cap_label = describe_capability(
                    cap_id
                )


                st.markdown(
                    f'<span class="capability">'
                    f'{cap_label} — {tool_count} tool(s)'
                    f'</span>',
                    unsafe_allow_html=True,
                )


                with st.expander(
                    f"{cap_label} - {tool_count} tool(s)"
                ):

                    cap_definition = (
                        CAPABILITY_INFO
                        .get(
                            cap_id,
                            {}
                        )
                        .get(
                            "definition"
                        )
                    )


                    if cap_definition:

                        st.caption(
                            cap_definition
                        )


                    for tool_name in sorted(
                        tool_set
                    ):

                        st.write(
                            f"• {tool_name}"
                        )


        else:

            st.info(
                "No capability information available."
            )


        # Unmapped Tools

        if unmapped_tool_names:

            st.divider()


            st.subheader(
                "Unmapped Tools"
            )


            st.caption(
                "These tools matched none of the C1–C6 capabilities. "
                "Worth a manual check."
            )


            unmapped_col1, unmapped_col2, unmapped_col3 = (
                st.columns(3)
            )


            unmapped_per_col = (
                len(unmapped_tool_names) + 2
            ) // 3


            with unmapped_col1:

                for tool in unmapped_tool_names[
                    :unmapped_per_col
                ]:

                    st.write(
                        f"• {tool}"
                    )


            with unmapped_col2:

                for tool in unmapped_tool_names[
                    unmapped_per_col:
                    2 * unmapped_per_col
                ]:

                    st.write(
                        f"• {tool}"
                    )


            with unmapped_col3:

                for tool in unmapped_tool_names[
                    2 * unmapped_per_col:
                ]:

                    st.write(
                        f"• {tool}"
                    )


        st.divider()


        st.markdown(
            "### 📚 Reference Materials"
        )


        st.caption(
            "The following section contains reference material only — "
            "not analysis results."
        )


        st.divider()


        # =====================================================
        # REFERENCE: CAPABILITY TAXONOMY
        # =====================================================

        with st.expander(
            "📚 **REFERENCE: Capability Taxonomy (C1–C6)**",
            expanded=False,
        ):

            st.caption(
                "Fixed ontology definitions. These are reference material only."
            )


            ref_col1, ref_col2 = st.columns(
                2,
                gap="large",
            )


            cap_list = list(
                CAPABILITY_SEED
            )


            mid = len(
                cap_list
            ) // 2


            with ref_col1:

                for (
                    cap_id,
                    cap_name,
                    cap_definition,
                    cap_risk,
                ) in cap_list[:mid]:

                    with st.expander(
                        f"{cap_id} — {cap_name}"
                    ):

                        st.write(
                            cap_definition
                        )


                        if cap_risk:

                            st.caption(
                                f"Example risk: {cap_risk}"
                            )


            with ref_col2:

                for (
                    cap_id,
                    cap_name,
                    cap_definition,
                    cap_risk,
                ) in cap_list[mid:]:

                    with st.expander(
                        f"{cap_id} — {cap_name}"
                    ):

                        st.write(
                            cap_definition
                        )


                        if cap_risk:

                            st.caption(
                                f"Example risk: {cap_risk}"
                            )


    # =========================================================
    # TAB 2: COMPOSITION ANALYSIS
    # =========================================================

    with result_tab_2:

        st.header(
            "Matched Literature-Backed Capability Compositions"
        )


        st.caption(
            "Composition matches indicate required capabilities are present. "
            "A match does not establish that an attack was executed."
        )


        if not matched_compositions:

            st.success(
                "No literature-backed capability compositions matched."
            )


        else:

            for detection in matched_compositions:

                if not isinstance(
                    detection,
                    dict,
                ):

                    st.write(
                        detection
                    )

                    continue


                pattern_id = detection.get(
                    "pattern_id",
                    "Unknown"
                )


                pattern_name = detection.get(
                    "pattern_name",
                    "Unknown pattern"
                )


                severity = detection.get(
                    "severity",
                    "Unknown"
                )


                finding_type = detection.get(
                    "finding_type",
                    "Unknown"
                )


                confidence = detection.get(
                    "confidence",
                    "Unknown"
                )


                cap_sequence = detection.get(
                    "capability_sequence",
                    []
                )


                sequence_text = (
                    describe_sequence(
                        cap_sequence
                    )
                )


                severity_class = {
                    "high": "severity-high",
                    "medium": "severity-medium",
                }.get(
                    str(severity).lower(),
                    "severity-low",
                )

                composition_html = (
                    '<div class="composition-card">'
                    '<div class="composition-header">'
                    '<div>'
                    f'<div class="pattern-id">{pattern_id}</div>'
                    f'<div class="pattern-name">{pattern_name}</div>'
                    '</div>'
                    f'<span class="status-badge {severity_class}">{severity}</span>'
                    '</div>'
                    f'<div class="sequence">{sequence_text}</div>'
                    '</div>'
                )

                st.markdown(composition_html, unsafe_allow_html=True)

                col_left, col_right = st.columns(2)


                with col_left:

                    st.markdown(
                        "**Sequence**"
                    )


                    st.code(
                        sequence_text,
                        language="text",
                    )


                with col_right:

                    st.markdown(
                        "**Finding**"
                    )


                    st.write(
                        finding_type
                    )


                    st.markdown(
                        "**Confidence**"
                    )


                    st.write(
                        f"{confidence} (literature-mapping)"
                    )


                impact_data = detection.get(
                    "impact_assessment"
                )


                if impact_data:

                    st.markdown(
                        "#### CIA Impact"
                    )


                    cia_col1, cia_col2, cia_col3, cia_col4 = (
                        st.columns(4)
                    )


                    with cia_col1:

                        st.metric(
                            "Confidentiality",
                            impact_data.get(
                                "confidentiality",
                                "-"
                            ),
                        )


                    with cia_col2:

                        st.metric(
                            "Integrity",
                            impact_data.get(
                                "integrity",
                                "-"
                            ),
                        )


                    with cia_col3:

                        st.metric(
                            "Availability",
                            impact_data.get(
                                "availability",
                                "-"
                            ),
                        )


                    with cia_col4:

                        st.metric(
                            "Total",
                            impact_data.get(
                                "total",
                                "-"
                            ),
                        )


                    if impact_data.get(
                        "rationale"
                    ):

                        st.markdown(
                            "**Rationale**"
                        )


                        st.write(
                            impact_data.get(
                                "rationale"
                            )
                        )


                st.divider()


        st.divider()





    # =========================================================
    # TAB 3: CIA RISK & MITIGATIONS
    # =========================================================

    with result_tab_3:

        st.header(
            "Mitigation Coverage for Matched Compositions"
        )


        if not matched_mitigations:

            if matched_compositions:

                st.warning(
                    "Matched compositions found, but no mitigation "
                    "assessments available."
                )

            else:

                st.info(
                    "No matched compositions require mitigation coverage."
                )


        else:

            for assessment in matched_mitigations:

                if not isinstance(
                    assessment,
                    dict,
                ):

                    continue


                pattern_id = assessment.get(
                    "pattern_id",
                    "Unknown"
                )


                pattern_name = assessment.get(
                    "pattern_name",
                    "Unknown pattern"
                )


                coverage_status = assessment.get(
                    "coverage_status",
                    "Unknown"
                )


                st.markdown(
                    f"### {pattern_id} — {pattern_name}"
                )


                st.markdown(
                    f"**Coverage:** `{coverage_status}`"
                )


                if assessment.get(
                    "note"
                ):

                    st.info(
                        assessment.get(
                            "note"
                        )
                    )


                lit_mitigations = assessment.get(
                    "literature_mitigations",
                    []
                )


                if lit_mitigations:

                    st.markdown(
                        "#### Literature-backed Mitigations"
                    )


                    for mitigation in lit_mitigations:

                        m_id = mitigation.get(
                            "mitigation_id",
                            "Unknown"
                        )


                        m_name = mitigation.get(
                            "mitigation_name",
                            "Unknown"
                        )


                        with st.expander(
                            f"{m_id} — {m_name}"
                        ):

                            st.write(
                                f"**Type:** "
                                f"{mitigation.get('evidence_type', '-')}"
                            )


                            st.write(
                                f"**Applicable:** "
                                f"{mitigation.get('applicability', '-')}"
                            )


                            if mitigation.get(
                                "supporting_papers"
                            ):

                                st.write(
                                    f"**Papers:** "
                                    f"{mitigation.get('supporting_papers')}"
                                )


                            if mitigation.get(
                                "timing"
                            ):

                                st.write(
                                    f"**Timing:** "
                                    f"{mitigation.get('timing')}"
                                )


                            if mitigation.get(
                                "effectiveness_evidence"
                            ):

                                st.write(
                                    f"**Evidence:** "
                                    f"{mitigation.get('effectiveness_evidence')}"
                                )


                            if mitigation.get(
                                "limitations"
                            ):

                                st.write(
                                    f"**Limits:** "
                                    f"{mitigation.get('limitations')}"
                                )


                proj_mitigations = assessment.get(
                    "project_mitigations",
                    []
                )


                if proj_mitigations:

                    st.markdown(
                        "#### Project-derived Mitigations"
                    )


                    for mitigation in proj_mitigations:

                        m_id = mitigation.get(
                            "mitigation_id",
                            "Unknown"
                        )


                        m_name = mitigation.get(
                            "mitigation_name",
                            "Unknown"
                        )


                        with st.expander(
                            f"{m_id} — {m_name}"
                        ):

                            st.write(
                                f"**Type:** "
                                f"{mitigation.get('control_type', '-')}"
                            )


                            st.write(
                                f"**Timing:** "
                                f"{mitigation.get('timing', '-')}"
                            )


                            st.write(
                                f"**Status:** "
                                f"{mitigation.get('evidence_status', '-')}"
                            )


                            st.write(
                                f"**Rationale:** "
                                f"{mitigation.get('project_rationale', '')}"
                            )


                if assessment.get(
                    "warning"
                ):

                    st.warning(
                        assessment.get(
                            "warning"
                        )
                    )


                st.divider()


        # Open gaps

        st.header(
            "Open Mitigation Gaps"
        )


        if not open_mitigation_gaps:

            st.success(
                "No open mitigation gaps."
            )


        else:

            for gap in open_mitigation_gaps:

                if not isinstance(
                    gap,
                    dict,
                ):

                    continue


                pattern_id = gap.get(
                    "pattern_id",
                    "Unknown"
                )


                gap_text = gap.get(
                    "gap",
                    "No description."
                )


                proposals = gap.get(
                    "project_proposals",
                    []
                )


                gap_html = (
                    f'<div class="finding risk-high">'
                    f'<strong>{pattern_id}</strong><br>'
                    f'{gap_text}'
                    f'</div>'
                )

                st.markdown(gap_html, unsafe_allow_html=True)


                if proposals:

                    st.markdown(
                        "**Proposals**"
                    )


                    for proposal in proposals:

                        st.write(
                            f"• {proposal}"
                        )


                if gap.get(
                    "warning"
                ):

                    st.warning(
                        gap.get(
                            "warning"
                        )
                    )


    # =========================================================
    # TAB 4: INTERPRETATION LIMITS & DISCLAIMERS
    # =========================================================

    with result_tab_4:

        st.header(
            "Interpretation Limits and Disclaimers"
        )


        limitation = (
            composition_analysis_data.get(
                "limitation"
            )
        )


        if limitation:

            st.warning(
                limitation
            )


        interpretation_data = (
            composition_analysis_data.get(
                "interpretation",
                {}
            )
        )


        if interpretation_data.get(
            "impact_assessment"
        ):

            st.info(
                interpretation_data.get(
                    "impact_assessment"
                )
            )


        mitigation_semantics = (
            mitigation_assessment_data.get(
                "semantics"
            )
        )


        if mitigation_semantics:

            st.info(
                mitigation_semantics
            )


        applicability_rule = (
            mitigation_assessment_data.get(
                "applicability_rule"
            )
        )


        if applicability_rule:

            st.info(
                applicability_rule
            )


        st.caption(
            "CIA totals represent CIA impact only, "
            "not converted to risk scores at this stage."
        )


        st.divider()


        st.markdown(
            "### 📚 Reference Materials"
        )


        st.caption(
            "The following sections contain reference material only — "
            "not analysis results."
        )


        st.divider()


        # =====================================================
        # REFERENCE: PATTERN COVERAGE (P1–P9)
        # =====================================================

        pattern_coverage = (
            mitigation_assessment_data.get(
                "pattern_coverage_reference",
                []
            )
        )


        if pattern_coverage:

            with st.expander(
                "📚 **REFERENCE: Pattern Coverage (P1–P9)**",
                expanded=False,
            ):

                st.caption(
                    "Reference mapping of patterns to mitigations. "
                    "Use for cross-reference only."
                )


                for coverage in pattern_coverage:

                    if not isinstance(
                        coverage,
                        dict,
                    ):

                        continue


                    pattern_id = coverage.get(
                        "pattern_id",
                        "Unknown"
                    )


                    coverage_status = coverage.get(
                        "coverage_status",
                        "Unknown"
                    )


                    lit_ids = [
                        m.get(
                            "mitigation_id",
                            "Unknown"
                        )
                        for m in coverage.get(
                            "literature_mitigations",
                            []
                        )
                        if isinstance(
                            m,
                            dict,
                        )
                    ]


                    proj_ids = [
                        m.get(
                            "mitigation_id",
                            "Unknown"
                        )
                        for m in coverage.get(
                            "project_mitigations",
                            []
                        )
                        if isinstance(
                            m,
                            dict,
                        )
                    ]


                    lit_text = (
                        ", ".join(
                            lit_ids
                        )
                        if lit_ids
                        else "-"
                    )


                    proj_text = (
                        ", ".join(
                            proj_ids
                        )
                        if proj_ids
                        else "-"
                    )


                    st.markdown(
                        f"**{pattern_id}:** `{coverage_status}`"
                    )


                    st.caption(
                        f"Literature: {lit_text} | "
                        f"Project: {proj_text}"
                    )


                    if coverage.get(
                        "note"
                    ):

                        st.write(
                            coverage.get(
                                "note"
                            )
                        )


        # =====================================================
        # REFERENCE: MANUAL VALIDATION
        # =====================================================

        with st.expander(
            "📚 **REFERENCE: Manual Validation (Mapper Calibration)**",
            expanded=False,
        ):

            st.caption(
                "Fixed, human-labelled reference tools used to calibrate "
                "the C1–C6 mapper. For reference only."
            )


            try:

                validation_conn = sqlite3.connect(
                    module_5_ontology_database.DB_PATH
                )


                try:

                    mapper_rows = validation_conn.execute(
                        """
                        SELECT tools.name,
                               tool_capabilities.capability_id
                        FROM tool_capabilities
                        JOIN tools
                            ON tools.tool_id =
                               tool_capabilities.tool_id
                        WHERE tool_capabilities.source = 'mapper'
                        """
                    ).fetchall()


                finally:

                    validation_conn.close()


            except sqlite3.Error as db_error:

                mapper_rows = []

                st.warning(
                    f"Could not read ontology database: {db_error}"
                )


            mapper_ids_by_name = {}


            for tool_name, capability_id in mapper_rows:

                mapper_ids_by_name.setdefault(
                    tool_name,
                    set(),
                ).add(
                    capability_id
                )


            for (
                ref_name,
                ref_description,
                ref_labels,
            ) in module_5_ontology_database.MANUAL_VALIDATION_SET:

                manual_ids = {
                    cap_id
                    for cap_id, _confidence, _reason
                    in ref_labels
                }


                with st.expander(
                    f"{ref_name} — {ref_description}"
                ):

                    if ref_labels:

                        for (
                            cap_id,
                            confidence,
                            reason,
                        ) in ref_labels:

                            st.write(
                                f"• Manual: "
                                f"{describe_capability(cap_id)} "
                                f"({confidence}) — {reason}"
                            )

                    else:

                        st.write(
                            "• Manual: intentionally unmapped"
                        )


                    mapper_ids = (
                        mapper_ids_by_name.get(
                            ref_name
                        )
                    )


                    if mapper_ids is None:

                        st.caption(
                            "No mapper verdict for same-named "
                            "tool in this run."
                        )


                    elif mapper_ids == manual_ids:

                        st.success(
                            "Mapper agrees: "
                            + (
                                ", ".join(
                                    sorted(
                                        describe_capability(c)
                                        for c in mapper_ids
                                    )
                                )
                                or "none"
                            )
                        )


                    else:

                        st.error(
                            "Mapper disagrees — mapper: "
                            + (
                                ", ".join(
                                    sorted(
                                        describe_capability(c)
                                        for c in mapper_ids
                                    )
                                )
                                or "none"
                            )
                            + " · manual: "
                            + (
                                ", ".join(
                                    sorted(
                                        describe_capability(c)
                                        for c in manual_ids
                                    )
                                )
                                or "none"
                            )
                        )


    # =========================================================
    # TAB 5: FINAL REPORT
    # =========================================================

    with result_tab_5:

        st.header(
            "Final Report"
        )


        report_text = (
            st.session_state.report_text
        )


        if report_text:

            st.download_button(
                label="Download Full Report",
                data=report_text,
                file_name="agent_pre_deployer_report.txt",
                mime="text/plain",
                use_container_width=True,
            )


            with st.expander(
                "View full report",
                expanded=False,
            ):

                st.text(
                    report_text
                )


        else:

            st.warning(
                "The analysis completed, but the generated "
                "report could not be loaded."
            )


            final_report_path = (
                analysis_result.get(
                    "final_report_path"
                )
            )


            if final_report_path:

                st.caption(
                    "Expected report path:"
                )


                st.code(
                    str(final_report_path)
                )

# =============================================================
# INPUT HELPERS (added in this revision)
#
# Two mutually exclusive input options feed the *same* Module 1 entry
# point: an uploaded tool JSON, or metadata discovered from a live MCP
# server. Modules 1-3 are untouched.
# =============================================================

def render_upload_input():
    """Existing upload workflow, unchanged in behaviour."""

    with st.expander("Accepted file format", expanded=False):

        st.markdown(
            "**Normalized MCP tool format** - a JSON list of objects with "
            "`tool` and `description`, optionally `readOnlyHint`, "
            "`destructiveHint`, `idempotentHint`, `openWorldHint`, "
            "`input_schema` and `source`."
        )

        st.markdown(
            "**MCPTox format** - a JSON list of objects with `tool_name`, "
            "`tool_content`, `server_name` and related fields."
        )

    uploaded_file = st.file_uploader(
        "Upload MCP tool JSON",
        type=["json"],
        key="tool_json_upload",
    )

    if uploaded_file is None:

        st.caption(
            f"No file selected - the preloaded dataset "
            f"({DEFAULT_FILE.name}) will be used."
        )

    return uploaded_file


def render_mcp_input():
    """Collect MCP stdio connection details and retrieve declared metadata."""

    st.markdown("**Connect to an MCP server (metadata / discovery only)**")

    st.caption(
        "Launches a local MCP server using the stdio transport and reads its "
        "`initialize` response and `tools/list` declarations: server info, "
        "protocol version, server capabilities, tool names, descriptions, "
        "input schemas and annotations. No tool is executed, and no "
        "implementation code is retrieved."
    )

    command = st.text_input(
        "Server command",
        key="mcp_command",
        value=mcp_toolinfo_Retriever.DEMO_SERVER_COMMAND,
        help=(
            "The command that starts the MCP server process. It must be "
            "installed on this machine: npx-based servers require Node.js, "
            "uvx-based servers require uv."
        ),
    )

    with st.expander("Example server commands"):

        st.markdown(
            "**Bundled demonstration server** — no installation needed, "
            "exposes illustrative tool declarations only:"
        )

        st.code(
            mcp_toolinfo_Retriever.DEMO_SERVER_COMMAND,
            language="bash",
        )

        st.markdown(
            "**Reference servers** — these need Node.js (`npx`) or "
            "uv (`uvx`) installed and on PATH:"
        )

        st.code(
            "npx -y @modelcontextprotocol/server-filesystem "
            "C:\\path\\to\\folder\n"
            "npx -y @modelcontextprotocol/server-memory\n"
            "uvx mcp-server-git --repository C:\\path\\to\\repo",
            language="bash",
        )

        st.caption(
            "On Windows, use `python` rather than `python3` if `python3` "
            "is not on PATH."
        )

    timeout = st.number_input(
        "Timeout (seconds)",
        min_value=5,
        max_value=180,
        value=30,
        step=5,
        key="mcp_timeout",
    )

    if st.button(
        "Retrieve tool metadata",
        key="mcp_retrieve_button",
    ):

        with st.spinner("Contacting the MCP server..."):

            try:

                retrieval = (
                    mcp_toolinfo_Retriever.retrieve_tool_metadata(
                        transport="stdio",
                        command=command,
                        url=None,
                        headers=None,
                        timeout=int(timeout),
                    )
                )

            except mcp_toolinfo_Retriever.McpRetrievalError as retrieval_error:

                st.session_state.pop("mcp_retrieval", None)

                st.error(
                    f"MCP retrieval failed: {retrieval_error}"
                )

                return

            except Exception as unexpected_error:

                st.session_state.pop("mcp_retrieval", None)

                st.error(
                    "Unexpected error while contacting the MCP server: "
                    f"{unexpected_error}"
                )

                return

        if not retrieval.get("tools"):

            st.session_state.pop("mcp_retrieval", None)

            st.warning(
                "The server responded but did not declare any tools. "
                "There is nothing for Module 1 to analyse."
            )

            return

        st.session_state["mcp_retrieval"] = retrieval

        st.success(
            f"Retrieved metadata for {retrieval['tool_count']} tool(s)."
        )

    retrieval = st.session_state.get("mcp_retrieval")

    if retrieval:
        render_mcp_retrieval_summary(retrieval)


def render_mcp_retrieval_summary(retrieval):
    """Show what the server declared about itself and its tools."""

    server_info = retrieval.get("server_info") or {}

    st.divider()

    st.markdown("**Server information (as declared by the server)**")

    left, right = st.columns(2)

    with left:
        st.write(f"- **Name:** {server_info.get('name', 'not provided')}")
        st.write(
            f"- **Version:** {server_info.get('version', 'not provided')}"
        )

    with right:
        st.write(
            f"- **Protocol version:** "
            f"{retrieval.get('protocol_version') or 'not provided'}"
        )
        st.write(f"- **Transport:** {retrieval.get('transport')}")

    capabilities = retrieval.get("server_capabilities") or {}

    if capabilities:
        st.write(
            "- **Declared server capabilities:** "
            + ", ".join(sorted(capabilities.keys()))
        )

    if retrieval.get("instructions"):
        with st.expander("Server instructions text"):
            st.code(str(retrieval["instructions"]))

    st.markdown("**Discovered tools**")

    rows = []

    for tool in retrieval.get("tools", []):

        description = str(tool.get("description") or "")

        declared_hints = [
            key
            for key, origin in (tool.get("hint_provenance") or {}).items()
            if origin == "declared_by_server"
        ]

        rows.append(
            {
                "Tool": tool.get("tool"),
                "Description": (
                    description[:90] + "..."
                    if len(description) > 90
                    else description
                ),
                "Input schema": (
                    "yes" if tool.get("input_schema") else "no"
                ),
                "Hints declared": (
                    ", ".join(sorted(declared_hints))
                    if declared_hints
                    else "none"
                ),
            }
        )

    if rows:
        st.dataframe(
            pd.DataFrame(rows),
            use_container_width=True,
            hide_index=True,
        )

    st.caption(retrieval.get("retrieval_scope", ""))


def prepare_pipeline_input(temp_dir, input_mode, uploaded_file, mcp_retrieval):
    """Write the selected input to a JSON file for Module 1.

    Returns:
        tuple[str, str]: (path passed to Module 1, human-readable source)
    """

    if input_mode == INPUT_MODE_MCP:

        if not mcp_retrieval or not mcp_retrieval.get("tools"):
            raise ValueError(
                "No MCP metadata has been retrieved yet."
            )

        input_path = os.path.join(temp_dir, "mcp_retrieved_tools.json")

        mcp_toolinfo_Retriever.write_normalized_json(
            mcp_retrieval["tools"],
            input_path,
        )

        return (
            input_path,
            f"MCP server metadata ({mcp_retrieval.get('source')})",
        )

    if uploaded_file is not None:

        input_path = os.path.join(temp_dir, uploaded_file.name)

        with open(input_path, "wb") as handle:
            handle.write(uploaded_file.getbuffer())

        return input_path, f"uploaded file ({uploaded_file.name})"

    if not DEFAULT_FILE.exists():
        raise FileNotFoundError(
            f"The preloaded dataset was not found at {DEFAULT_FILE}. "
            f"Upload a tool JSON file instead."
        )

    input_path = os.path.join(temp_dir, DEFAULT_FILE.name)

    with open(input_path, "wb") as handle:
        handle.write(DEFAULT_FILE.read_bytes())

    return input_path, f"preloaded dataset ({DEFAULT_FILE.name})"


# =============================================================
# MCP HINT BADGES
#
# A hint is a claim made by the tool author. It is never treated as
# evidence of what the implementation actually does.
# =============================================================

HINT_DEFINITIONS = [
    ("readOnlyHint", "Read-only", "is_read_only"),
    ("destructiveHint", "Destructive", "is_destructive"),
    ("idempotentHint", "Idempotent", None),
    ("openWorldHint", "Open-world", "accesses_external"),
]


def _hint_origin(tool, hint_key):
    """Classify where a hint value came from."""

    provenance = (tool.get("hint_provenance") or {}).get(hint_key)
    value = tool.get(hint_key)

    if isinstance(value, bool):

        if provenance == "declared_by_server":
            return "declared_by_server", value

        return "declared_in_input", value

    return "unavailable", None


def render_hint_badges(tool):
    """Render the four MCP hints as labelled indicators with provenance."""

    st.markdown("**MCP hints**")

    features = tool.get("capability_features") or {}

    for hint_key, label, feature_key in HINT_DEFINITIONS:

        origin, value = _hint_origin(tool, hint_key)

        if origin == "unavailable":

            inferred = features.get(feature_key) if feature_key else None

            if isinstance(inferred, bool):

                st.markdown(
                    f"- ⚪ **{label}** - `information unavailable` "
                    f"| framework inference from declared text: "
                    f"**{str(inferred).lower()}**"
                )

            else:

                st.markdown(
                    f"- ⚪ **{label}** - `information unavailable`"
                )

            continue

        marker = "✅" if value else "⬛"

        origin_label = (
            "declared by MCP server"
            if origin == "declared_by_server"
            else "declared in supplied metadata"
        )

        st.markdown(
            f"- {marker} **{label} = {str(value).lower()}** "
            f"| {origin_label}"
        )

    st.write(f"- **Source:** {tool.get('source') or 'not provided'}")

    st.caption(
        "Hints are declarations made by the tool author. They are not "
        "proof of the tool's actual implementation behaviour. Values "
        "marked as a framework inference are derived by Module 2 from the "
        "declared name and description only."
    )

    if tool.get("input_schema"):
        with st.expander("Declared input schema"):
            st.json(tool["input_schema"])


# =============================================================
# IMPLEMENTATION SOURCE + ON-DEMAND TDP SCAN
# =============================================================

def render_tool_source_and_tdp(tool):
    """Show real implementation source if available, plus a TDP scan button."""

    tool_name = tool.get("tool") or tool.get("tool_name") or "unknown_tool"

    st.markdown("**Implementation source**")

    availability = tool_source_locator.describe_availability(tool)
    source = availability.get("source")

    if source:

        st.caption(
            f"Found in project file `{source.get('file')}` "
            f"(match: {source.get('match_kind')}, "
            f"line {source.get('line')})."
        )

        st.code(
            source.get("snippet", ""),
            language=source.get("language", "text"),
        )

        if source.get("truncated"):
            st.caption(
                "Snippet truncated. Open the file above to read the rest."
            )

        st.caption(
            "This is source held in the supplied project files. It is not "
            "retrieved from the MCP server and may differ from the code a "
            "live server is running."
        )

    else:

        st.warning("Implementation source not available.")

        st.caption(availability.get("message", ""))

    st.divider()

    st.markdown("**Tool Description Poisoning (TDP) scan**")

    st.caption(
        "Runs only when you press the button. The scanner inspects the "
        "declared tool name and description (pattern P7). It is separate "
        "from capability identification and never changes the C1-C6 "
        "classification."
    )

    scan_key = f"tdp_scan_result_{tool_name}"

    if st.button(
            "Run TDP Scan",
            key=f"tdp_scan_button_{tool_name}",
    ):

        try:

            findings = module_tdp_scanner.scan_tool(tool)

            st.session_state[scan_key] = {
                "findings": findings,
                "source_file": source.get("file") if source else None,
            }

        except Exception as scan_error:

            st.session_state[scan_key] = {"error": str(scan_error)}

    stored = st.session_state.get(scan_key)

    if stored is None:
        return

    if stored.get("error"):

        st.error(f"TDP scan failed: {stored['error']}")

        return

    findings = stored.get("findings") or []

    if findings:

        st.error(
            f"{len(findings)} TDP indicator(s) matched in the declared text."
        )

        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "Indicator": finding.get("id"),
                        "Severity": finding.get("severity"),
                        "Matched": finding.get("matched"),
                        "Reason": finding.get("reason"),
                    }
                    for finding in findings
                ]
            ),
            use_container_width=True,
            hide_index=True,
        )

    else:

        st.success("No TDP indicators matched in the declared text.")

    if stored.get("source_file"):
        st.caption(
            f"Implementation source available for manual review: "
            f"`{stored['source_file']}`. The scanner did not analyse it."
        )
    else:
        st.caption(
            "No implementation source was available for this tool, so only "
            "declared text was scanned."
        )

    st.caption(module_tdp_scanner.SCANNER_SCOPE)

    st.caption(
        "Heuristic only. A match is not confirmation of an exploit, and the "
        "absence of a match is not evidence the description is clean."
    )
