import sqlite3
from pathlib import Path

import pandas as pd
import streamlit as st

from modules.capability_lexicon_loader import (
    LEXICON_FILES,
    VALID_CONFIDENCE,
    LexiconError,
    lexicon_path,
    load_capability_file,
    save_capability_rules,
)


# ============================================================
# DATABASE
# ============================================================

# Database location:
# agent_pre_deployer/modules/capability_ontology.db

DB_PATH = Path(__file__).parent.parent / "modules" / "capability_ontology.db"

TABLE_NAME = "attack_patterns"

CIA_COLUMNS = [
    "confidentiality_impact",
    "integrity_impact",
    "availability_impact",
]

# These columns are controlled by the application rather than
# directly edited by the user.
IDENTITY_COLUMN = "pattern_id"
DERIVED_COLUMN = "cia_total"


# ============================================================
# DATABASE HELPERS
# ============================================================

def get_connection():
    """Open the AgentPreDeployer ontology database."""

    if not DB_PATH.exists():
        raise FileNotFoundError(
            f"Database not found: {DB_PATH}"
        )

    return sqlite3.connect(str(DB_PATH))


def load_patterns():
    """Load all attack patterns from the ontology database."""

    with get_connection() as conn:
        return pd.read_sql_query(
            f"SELECT * FROM {TABLE_NAME}",
            conn,
        )


def get_database_columns():
    """Return the actual columns in the attack_patterns table."""

    with get_connection() as conn:

        rows = conn.execute(
            f"PRAGMA table_info({TABLE_NAME})"
        ).fetchall()

    return [row[1] for row in rows]


def normalise_cia_value(value):
    """
    Convert a CIA impact value to an integer between 0 and 5.
    """

    value = pd.to_numeric(
        value,
        errors="coerce",
    )

    if pd.isna(value):
        return 0

    return max(
        0,
        min(5, int(value)),
    )


def calculate_cia_total(row):
    """Calculate CIA total from the three CIA components."""

    return (
        normalise_cia_value(row["confidentiality_impact"])
        +
        normalise_cia_value(row["integrity_impact"])
        +
        normalise_cia_value(row["availability_impact"])
    )


def save_patterns(table, deleted_pattern_ids):
    """
    Save all editable database fields and delete selected rows.

    pattern_id:
        Used as the stable row identifier and is not edited.

    cia_total:
        Derived automatically from the three CIA components.

    deleted_pattern_ids:
        Rows selected using the Delete checkbox.
    """

    database_columns = get_database_columns()

    if IDENTITY_COLUMN not in database_columns:
        raise ValueError(
            f"Required identity column '{IDENTITY_COLUMN}' "
            "does not exist in the database."
        )

    # --------------------------------------------------------
    # Determine which columns may actually be updated.
    # --------------------------------------------------------

    editable_columns = [
        column
        for column in database_columns
        if column not in {
            IDENTITY_COLUMN,
            DERIVED_COLUMN,
        }
    ]

    # --------------------------------------------------------
    # Validate the incoming dataframe.
    # --------------------------------------------------------

    missing_columns = [
        column
        for column in database_columns
        if column not in table.columns
    ]

    if missing_columns:
        raise ValueError(
            "The editor is missing database columns: "
            + ", ".join(missing_columns)
        )

    with get_connection() as conn:

        # ====================================================
        # DELETE SELECTED ROWS
        # ====================================================

        for pattern_id in deleted_pattern_ids:

            conn.execute(
                f"""
                DELETE FROM {TABLE_NAME}
                WHERE {IDENTITY_COLUMN} = ?
                """,
                (pattern_id,),
            )

        # ====================================================
        # UPDATE REMAINING ROWS
        # ====================================================

        for _, row in table.iterrows():

            pattern_id = row[IDENTITY_COLUMN]

            # Skip rows that were selected for deletion.
            if pattern_id in deleted_pattern_ids:
                continue

            values = []

            for column in editable_columns:

                value = row[column]

                # ------------------------------------------------
                # CIA fields
                # ------------------------------------------------

                if column in CIA_COLUMNS:

                    value = normalise_cia_value(value)

                # ------------------------------------------------
                # Pandas NaN -> SQLite NULL
                # ------------------------------------------------

                elif pd.isna(value):

                    value = None

                # ------------------------------------------------
                # Pandas/numpy scalar -> normal Python scalar
                # ------------------------------------------------

                elif hasattr(value, "item"):

                    try:
                        value = value.item()
                    except Exception:
                        pass

                values.append(value)

            # ----------------------------------------------------
            # Recalculate CIA total.
            # ----------------------------------------------------

            cia_total = calculate_cia_total(row)

            # ----------------------------------------------------
            # Build UPDATE statement dynamically.
            #
            # Column names come directly from PRAGMA table_info,
            # not user input, so they are trusted database names.
            # Values remain parameterised.
            # ----------------------------------------------------

            set_clause = ", ".join(
                f"{column} = ?"
                for column in editable_columns
            )

            update_values = values + [
                cia_total,
                pattern_id,
            ]

            # cia_total is updated separately because it is derived.
            update_sql = f"""
                UPDATE {TABLE_NAME}
                SET
                    {set_clause},
                    {DERIVED_COLUMN} = ?
                WHERE {IDENTITY_COLUMN} = ?
            """

            conn.execute(
                update_sql,
                update_values,
            )

        # ====================================================
        # COMMIT EVERYTHING AT ONCE
        # ====================================================

        conn.commit()


# ============================================================
# COLUMN CONFIGURATION
# ============================================================

def get_column_config(database_columns):
    """
    Make all database columns editable except:

        pattern_id -> stable row identifier
        cia_total  -> automatically calculated

    A temporary Delete column is added separately.
    """

    config = {}

    for column in database_columns:

        # ----------------------------------------------------
        # Pattern ID
        # ----------------------------------------------------

        if column == IDENTITY_COLUMN:

            config[column] = st.column_config.TextColumn(
                "Pattern ID",
                disabled=True,
                help=(
                    "Stable database identifier. "
                    "It cannot be edited because it is used "
                    "to identify the database row."
                ),
            )

        # ----------------------------------------------------
        # CIA fields
        # ----------------------------------------------------

        elif column in CIA_COLUMNS:

            pretty_name = {
                "confidentiality_impact": "Confidentiality",
                "integrity_impact": "Integrity",
                "availability_impact": "Availability",
            }[column]

            config[column] = st.column_config.NumberColumn(
                pretty_name,
                min_value=0,
                max_value=5,
                step=1,
            )

        # ----------------------------------------------------
        # CIA Total
        # ----------------------------------------------------

        elif column == DERIVED_COLUMN:

            config[column] = st.column_config.NumberColumn(
                "CIA Total",
                disabled=True,
                help=(
                    "Automatically calculated as "
                    "Confidentiality + Integrity + Availability."
                ),
            )

        # ----------------------------------------------------
        # All other columns
        # ----------------------------------------------------

        else:

            config[column] = st.column_config.TextColumn(
                column.replace("_", " ").title(),
            )

    # --------------------------------------------------------
    # Temporary UI-only Delete column
    # --------------------------------------------------------

    config["_delete"] = st.column_config.CheckboxColumn(
        "Delete",
        default=False,
        help=(
            "Tick this row if you want to delete it "
            "when Save Changes is clicked."
        ),
    )

    return config


# ============================================================
# UI
# ============================================================

def render_attack_patterns():

    st.header("Edit Database")

    st.caption(
        "Edit attack-pattern records directly. "
        "Changes are written to the SQLite database when "
        "you click Save Changes."
    )

    # --------------------------------------------------------
    # LOAD DATABASE
    # --------------------------------------------------------

    try:

        table = load_patterns()

    except Exception as error:

        st.error(
            f"Could not load the {TABLE_NAME} table."
        )

        st.code(str(error))

        st.info(
            f"Database expected at:\n{DB_PATH}"
        )

        return

    # --------------------------------------------------------
    # EMPTY DATABASE
    # --------------------------------------------------------

    if table.empty:

        st.info(
            "No attack patterns found in the database."
        )

        return

    # --------------------------------------------------------
    # GET DATABASE COLUMNS
    # --------------------------------------------------------

    database_columns = list(table.columns)

    # --------------------------------------------------------
    # VALIDATE REQUIRED COLUMNS
    # --------------------------------------------------------

    required_columns = [
        IDENTITY_COLUMN,
        *CIA_COLUMNS,
    ]

    missing_columns = [
        column
        for column in required_columns
        if column not in database_columns
    ]

    if missing_columns:

        st.error(
            "The attack_patterns table is missing required "
            f"columns: {', '.join(missing_columns)}"
        )

        return

    # --------------------------------------------------------
    # NORMALISE CIA VALUES
    # --------------------------------------------------------

    for column in CIA_COLUMNS:

        table[column] = (
            pd.to_numeric(
                table[column],
                errors="coerce",
            )
            .fillna(0)
            .astype(int)
            .clip(0, 5)
        )

    # --------------------------------------------------------
    # ALWAYS RECALCULATE CIA TOTAL
    # --------------------------------------------------------

    table[DERIVED_COLUMN] = (
        table["confidentiality_impact"]
        +
        table["integrity_impact"]
        +
        table["availability_impact"]
    )

    # --------------------------------------------------------
    # ADD TEMPORARY DELETE COLUMN
    # --------------------------------------------------------

    table["_delete"] = False

    # --------------------------------------------------------
    # HEADER
    # --------------------------------------------------------

    st.subheader(
        f"Attack Patterns ({len(table)})"
    )

    st.caption(
        "All database fields are editable except Pattern ID "
        "and CIA Total. Tick Delete for rows you want removed, "
        "then click Save Changes."
    )

    # --------------------------------------------------------
    # DATA EDITOR
    # --------------------------------------------------------

    edited_table = st.data_editor(
        table,
        column_config=get_column_config(database_columns),
        hide_index=True,
        use_container_width=True,
        num_rows="fixed",
        key="patterns_table_editor",
    )

    # --------------------------------------------------------
    # MAKE COPY
    # --------------------------------------------------------

    edited_table = edited_table.copy()

    # --------------------------------------------------------
    # DETERMINE DELETIONS
    # --------------------------------------------------------

    deleted_pattern_ids = set()

    if "_delete" in edited_table.columns:

        delete_mask = (
            edited_table["_delete"]
            .fillna(False)
            .astype(bool)
        )

        deleted_pattern_ids = set(
            edited_table.loc[
                delete_mask,
                IDENTITY_COLUMN,
            ].tolist()
        )

    # --------------------------------------------------------
    # RECALCULATE CIA TOTAL
    # --------------------------------------------------------

    edited_table[DERIVED_COLUMN] = (
        edited_table["confidentiality_impact"]
        .apply(normalise_cia_value)
        +
        edited_table["integrity_impact"]
        .apply(normalise_cia_value)
        +
        edited_table["availability_impact"]
        .apply(normalise_cia_value)
    )

    # --------------------------------------------------------
    # SHOW DELETE WARNING
    # --------------------------------------------------------

    if deleted_pattern_ids:

        st.warning(
            f"{len(deleted_pattern_ids)} row(s) marked for deletion. "
            "They will be permanently removed from the database "
            "when you save."
        )

    # --------------------------------------------------------
    # SAVE BUTTON
    # --------------------------------------------------------

    st.divider()

    left_column, right_column = st.columns([1, 5])

    with left_column:

        save_clicked = st.button(
            "💾 Save Changes",
            type="primary",
            use_container_width=True,
        )

    # --------------------------------------------------------
    # SAVE
    # --------------------------------------------------------

    if save_clicked:

        try:

            save_patterns(
                edited_table,
                deleted_pattern_ids,
            )

            # Clear the editor so the next render loads
            # the database fresh.
            if "patterns_table_editor" in st.session_state:
                del st.session_state["patterns_table_editor"]

            if deleted_pattern_ids:

                st.success(
                    f"Changes saved successfully. "
                    f"{len(deleted_pattern_ids)} row(s) deleted."
                )

            else:

                st.success(
                    "Changes saved successfully. "
                    "The database has been updated."
                )

            st.rerun()

        except Exception as error:

            st.error(
                f"Could not save changes: {error}"
            )

# ============================================================
# CAPABILITY LEXICON EDITOR
#
# The lexical rules used for capability identification live in
# capability_lexicon/*.json (one labelled file per capability) and are
# no longer defined in Python. This editor views and writes those files.
# The fixed C1-C6 ontology itself is not editable here.
# ============================================================

RULE_COLUMNS = [
    "rule_id",
    "category",
    "match_scope",
    "pattern",
    "reason",
    "confidence",
    "enabled",
]


def lexicon_rules_to_frame(document):
    """Convert a loaded lexicon document into an editable table."""

    rows = []

    for rule in document.get("rules", []):

        rows.append(
            {
                "rule_id": rule.get("rule_id", ""),
                "category": rule.get("category", "lexical_regex"),
                "match_scope": rule.get(
                    "match_scope", "tool_name_and_description"
                ),
                "pattern": rule.get("pattern", ""),
                "reason": rule.get("reason", ""),
                "confidence": rule.get("confidence", "Medium"),
                "enabled": bool(rule.get("enabled", True)),
            }
        )

    return pd.DataFrame(rows, columns=RULE_COLUMNS)


def frame_to_lexicon_rules(frame):
    """Convert the edited table back into rule dictionaries."""

    rules = []

    for _, row in frame.iterrows():

        pattern = str(row.get("pattern") or "").strip()

        # Blank rows added by the editor are ignored rather than saved.
        if not pattern:
            continue

        rules.append(
            {
                "rule_id": str(row.get("rule_id") or "").strip(),
                "category": str(
                    row.get("category") or "lexical_regex"
                ).strip(),
                "match_scope": str(
                    row.get("match_scope") or "tool_name_and_description"
                ).strip(),
                "pattern": pattern,
                "reason": str(row.get("reason") or "").strip(),
                "confidence": str(
                    row.get("confidence") or "Medium"
                ).strip(),
                "enabled": bool(row.get("enabled")),
            }
        )

    return rules


def get_lexicon_column_config():

    return {
        "rule_id": st.column_config.TextColumn(
            "Rule ID",
            help="Identifier within this capability, e.g. C2-R03.",
            width="small",
        ),
        "category": st.column_config.TextColumn(
            "Category",
            help="Rule category, e.g. lexical_regex.",
            width="small",
        ),
        "match_scope": st.column_config.TextColumn(
            "Match scope",
            help="Which declared text the pattern is matched against.",
            width="small",
        ),
        "pattern": st.column_config.TextColumn(
            "Pattern (regex)",
            help="Case-insensitive regular expression.",
            width="large",
        ),
        "reason": st.column_config.TextColumn(
            "Evidence text",
            help="Explanation recorded in the report when this rule matches.",
            width="large",
        ),
        "confidence": st.column_config.SelectboxColumn(
            "Confidence",
            options=list(VALID_CONFIDENCE),
            width="small",
        ),
        "enabled": st.column_config.CheckboxColumn(
            "Enabled",
            help="Disabled rules are kept in the file but not applied.",
            width="small",
        ),
    }


def render_capability_lexicon():

    st.header("Capability Lexicon (C1-C6)")

    st.caption(
        "These lexical rules drive capability identification in Module 3. "
        "They are stored in capability_lexicon/*.json, one labelled file "
        "per capability, and are loaded from those files at analysis time. "
        "The C1-C6 ontology itself is fixed and cannot be edited here."
    )

    capability_ids = sorted(LEXICON_FILES)

    selected = st.selectbox(
        "Capability",
        options=capability_ids,
        format_func=lambda cap: "{} - {}".format(
            cap,
            LEXICON_FILES[cap]
            .replace(cap + "_", "")
            .replace(".json", "")
            .replace("_", " ")
            .title(),
        ),
        key="lexicon_capability_select",
    )

    path = lexicon_path(selected)

    # --------------------------------------------------------
    # LOAD (no hardcoded fallback)
    # --------------------------------------------------------

    try:

        document = load_capability_file(selected)

    except LexiconError as error:

        st.error(
            f"The lexical-rule file for {selected} could not be loaded."
        )

        st.code(str(error))

        st.info(
            f"Expected file:\n{path}\n\n"
            "Capability identification will refuse to run until this file "
            "is valid. No hardcoded fallback rules are used."
        )

        return

    st.write(
        f"**{document.get('capability_id')} - "
        f"{document.get('capability_name')}**"
    )

    st.caption(f"File: {LEXICON_FILES[selected]}")

    if document.get("notes"):
        st.caption(document["notes"])

    table = lexicon_rules_to_frame(document)

    categories = sorted(
        {
            str(value)
            for value in table["category"].tolist()
            if str(value).strip()
        }
    )

    left, middle, right = st.columns(3)
    left.metric("Rules", len(table))
    middle.metric("Enabled", int(table["enabled"].sum()) if len(table) else 0)
    right.metric("Categories", len(categories))

    if categories:
        st.caption("Rule categories in this file: " + ", ".join(categories))

    edited_table = st.data_editor(
        table,
        key=f"lexicon_editor_{selected}",
        num_rows="dynamic",
        use_container_width=True,
        hide_index=True,
        column_config=get_lexicon_column_config(),
    )

    st.caption(
        "Patterns are case-insensitive regular expressions matched against "
        "the declared tool name and description. Each pattern is validated "
        "before the file is written."
    )

    save_clicked = st.button(
        "Save lexical rules",
        type="primary",
        key=f"lexicon_save_{selected}",
    )

    if not save_clicked:
        return

    # --------------------------------------------------------
    # SAVE BACK TO THE LEXICAL-RULE FILE
    # --------------------------------------------------------

    try:

        rules = frame_to_lexicon_rules(edited_table)

        save_capability_rules(
            selected,
            rules,
            notes=document.get("notes"),
        )

    except LexiconError as error:

        st.error("The rules were not saved because validation failed.")

        st.code(str(error))

        return

    except Exception as error:

        st.error(f"Could not write {LEXICON_FILES[selected]}: {error}")

        return

    if f"lexicon_editor_{selected}" in st.session_state:
        del st.session_state[f"lexicon_editor_{selected}"]

    st.success(
        f"Saved {len(rules)} rule(s) to {LEXICON_FILES[selected]}. "
        "The next analysis run will use the updated rules."
    )

    st.rerun()


# ============================================================
# TAB ENTRY POINT
# ============================================================

def render():

    patterns_tab, lexicon_tab = st.tabs(
        [
            "Attack patterns",
            "Capability lexicon (C1-C6)",
        ]
    )

    with patterns_tab:
        render_attack_patterns()

    with lexicon_tab:
        render_capability_lexicon()
