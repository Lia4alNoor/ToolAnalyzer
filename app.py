import streamlit as st
from pathlib import Path

from tabs import (
    capability_risk_analyzer,
    threat_curation_chain,
    edit_database,
)


st.set_page_config(
    page_title="AgentPreDeployer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)


def load_css():
    css_path = Path(__file__).parent / "styles1.css"

    if css_path.exists():
        with open(css_path, "r", encoding="utf-8") as f:
            st.markdown(
                f"<style>{f.read()}</style>",
                unsafe_allow_html=True,
            )


load_css()



# APPLICATION HEADER
st.markdown(
    """
    <div class="app-header">
        <div class="main-title">AgentPreDeployer</div>
        <div class="subtitle">
            Pre-deployment security assessment for agent tool permissions
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)


# MAIN APPLICATION TABS

tab1, tab2, tab3 = st.tabs(
    [
        "Capability Risk Analyzer",
        "Ontology Suggestions (Ollama)",
        "Edit Database",
    ]
)


# TAB 1 — CAPABILITY RISK ANALYZER

with tab1:
    capability_risk_analyzer.render()


# TAB 2 — THREAT CURATION CHAIN

with tab2:
    threat_curation_chain.render()


# TAB 3 — EDIT DATABASE

with tab3:
    edit_database.render()