import pandas as pd
import streamlit as st
from datetime import datetime, date, timedelta


REQUIRED_COLUMNS = [
    "sec_uuid",
    "cve_id",
    "host_name",
    "cvss",
    "cve_cache.published",
    "remediation_status",
    "remediation_comment",
    "Team",
]

VALID_STATUSES = {
    "PENDING",
    "REMEDIATED",
    "FALSE_POSITIVE",
}


def normalize_text(value):
    if pd.isna(value):
        return ""
    return str(value).strip()


def normalize_status(value):
    return normalize_text(value).upper()


def normalize_severity(value):
    value = normalize_text(value).upper()
    return "MEDIUM" if value == "MODERATE" else value


def parse_date(value):
    value = normalize_text(value).split("T")[0]

    if not value:
        return None

    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except Exception:
        return None


def calculate_due_date(published, severity):
    published_date = parse_date(published)
    severity = normalize_severity(severity)

    if not published_date:
        return None

    if severity == "CRITICAL":
        return published_date + timedelta(days=14)

    if severity == "HIGH":
        return published_date + timedelta(days=60)

    if severity == "MEDIUM":
        return published_date + timedelta(days=180)

    return None


def is_overdue(row):
    status = normalize_status(row.get("remediation_status"))

    if status != "PENDING":
        return False

    due_date = calculate_due_date(
        row.get("cve_cache.published"),
        row.get("cvss"),
    )

    if not due_date:
        return False

    return date.today() > due_date


def add_issue(issue_details, check, excel_row, cve_id, host_name, current_value, expected_value, message):
    issue_details.append({
        "check": check,
        "excel_row": excel_row,
        "cve_id": cve_id,
        "host_name": host_name,
        "current_value": current_value,
        "expected_value": expected_value,
        "message": message,
    })


def analyze_xlsx(uploaded_file):
    df = pd.read_excel(uploaded_file, dtype=str)
    df.columns = df.columns.str.strip()

    total_rows = len(df)

    issues = []
    warnings = []
    issue_details = []
    warning_details = []

    df["excel_row"] = df.index + 2

    missing_columns = [
        col for col in REQUIRED_COLUMNS
        if col not in df.columns
    ]

    if missing_columns:
        issues.append({
            "check": "Missing required columns",
            "severity": "BLOCKER",
            "count": len(missing_columns),
            "rows": "N/A",
            "details": ", ".join(missing_columns),
        })

        for col in missing_columns:
            add_issue(
                issue_details,
                "Missing required columns",
                "N/A",
                "",
                "",
                "Missing",
                col,
                f"Required column is missing: {col}",
            )

        return df, issues, warnings, issue_details, warning_details, 0

    df["sec_uuid_norm"] = df["sec_uuid"].apply(normalize_text)
    df["cve_norm"] = df["cve_id"].apply(normalize_text)
    df["host_norm"] = df["host_name"].apply(normalize_text)
    df["remediation_status_norm"] = df["remediation_status"].apply(normalize_status)
    df["remediation_comment_norm"] = df["remediation_comment"].apply(normalize_text)
    df["cvss_norm"] = df["cvss"].apply(lambda x: normalize_text(x).upper())
    df["team_norm"] = df["Team"].apply(normalize_text)

    expected_sec_uuid = df["cve_norm"] + "_" + df["host_norm"]

    checks = []

    checks.append((
        "Blank sec_uuid",
        df[df["sec_uuid_norm"] == ""],
        "sec_uuid",
        "",
        "cve_id_host_name",
        "Rows with blank sec_uuid.",
    ))

    checks.append((
        "Invalid sec_uuid",
        df[
            (df["sec_uuid_norm"] != "")
            & (df["sec_uuid_norm"] != expected_sec_uuid)
        ],
        "sec_uuid",
        "dynamic_expected_sec_uuid",
        "sec_uuid must follow this format: cve_id_host_name.",
        "Invalid sec_uuid format.",
    ))

    duplicated_sec_uuid = df[
        (df["sec_uuid_norm"] != "")
        & df["sec_uuid_norm"].duplicated(keep=False)
    ]

    checks.append((
        "Duplicated sec_uuid",
        duplicated_sec_uuid,
        "sec_uuid",
        "Unique sec_uuid",
        "Duplicated sec_uuid values detected.",
        "Duplicated sec_uuid detected.",
    ))

    checks.append((
        "Blank remediation_status",
        df[df["remediation_status_norm"] == ""],
        "remediation_status",
        "",
        "PENDING, REMEDIATED, or FALSE_POSITIVE",
        "Rows with blank remediation_status.",
    ))

    checks.append((
        "Blank remediation_comment",
        df[df["remediation_comment_norm"] == ""],
        "remediation_comment",
        "",
        "Non-blank remediation_comment",
        "Rows with blank remediation_comment.",
    ))

    checks.append((
        "Invalid status",
        df[~df["remediation_status_norm"].isin(VALID_STATUSES)],
        "remediation_status",
        "PENDING, REMEDIATED, or FALSE_POSITIVE",
        "Allowed values: PENDING, REMEDIATED, FALSE_POSITIVE.",
        "Invalid remediation_status.",
    ))

    checks.append((
        "MODERATE not converted to MEDIUM",
        df[df["cvss_norm"] == "MODERATE"],
        "cvss",
        "MEDIUM",
        "Rows still using MODERATE instead of MEDIUM.",
        "Severity must be MEDIUM instead of MODERATE.",
    ))

    checks.append((
        "Date contains time in cve_cache.published",
        df[
            df["cve_cache.published"]
            .fillna("")
            .astype(str)
            .str.contains("T", regex=False)
        ],
        "cve_cache.published",
        "YYYY-MM-DD",
        "Date should be YYYY-MM-DD only.",
        "Date contains time component.",
    ))

    checks.append((
        "Team UNKNOWN or blank",
        df[
            (df["team_norm"] == "")
            | (df["team_norm"].str.upper() == "UNKNOWN")
        ],
        "Team",
        "Known team name",
        "Rows with Team UNKNOWN or blank.",
        "Team is UNKNOWN or blank.",
    ))

    for check_name, bad_df, column_name, expected_value, details, message in checks:
        if bad_df.empty:
            continue

        row_numbers = bad_df["excel_row"].astype(str).tolist()

        issues.append({
            "check": check_name,
            "severity": "BLOCKER",
            "count": len(bad_df),
            "rows": ", ".join(row_numbers[:50]) + ("..." if len(row_numbers) > 50 else ""),
            "details": details,
        })

        for _, row in bad_df.iterrows():
            if check_name == "Invalid sec_uuid":
                current = row.get("sec_uuid", "")
                expected = f"{row.get('cve_norm', '')}_{row.get('host_norm', '')}"
            else:
                current = row.get(column_name, "")
                expected = expected_value

            add_issue(
                issue_details,
                check_name,
                row.get("excel_row"),
                row.get("cve_id", ""),
                row.get("host_name", ""),
                current,
                expected,
                message,
            )

    df["is_overdue"] = df.apply(is_overdue, axis=1)
    overdue_pending = df[df["is_overdue"] == True]

    if not overdue_pending.empty:
        row_numbers = overdue_pending["excel_row"].astype(str).tolist()

        warnings.append({
            "check": "Pending overdue patches",
            "severity": "WARNING",
            "count": len(overdue_pending),
            "rows": ", ".join(row_numbers[:50]) + ("..." if len(row_numbers) > 50 else ""),
            "details": f"File can be submitted, but there are {len(overdue_pending)} pending overdue patches.",
        })

        for _, row in overdue_pending.iterrows():
            add_issue(
                warning_details,
                "Pending overdue patches",
                row.get("excel_row"),
                row.get("cve_id", ""),
                row.get("host_name", ""),
                row.get("remediation_status", ""),
                "Not a blocker",
                "File can be submitted, but this PENDING item is overdue.",
            )

    total_blockers = sum(item["count"] for item in issues)

    if total_rows == 0:
        readiness = 0
    else:
        readiness = max(0, round(100 - ((total_blockers / total_rows) * 100), 2))

    return df, issues, warnings, issue_details, warning_details, readiness


st.set_page_config(
    page_title="XLSX Readiness Analyzer",
    layout="wide",
)

st.title("XLSX Readiness Analyzer")
st.caption("Developed by Matheus Giroto | Report Submission Quality Check")

st.write("Upload the XLSX report to validate whether it is ready to be submitted.")

uploaded_file = st.file_uploader("Upload XLSX", type=["xlsx"])

if uploaded_file:
    if st.button("Analyze File", type="primary"):
        try:
            (
                df,
                issues,
                warnings,
                issue_details,
                warning_details,
                readiness,
            ) = analyze_xlsx(uploaded_file)

            st.subheader("Readiness Status")
            st.progress(int(readiness))

            if readiness == 100:
                if warnings:
                    st.warning(
                        f"File is ready to be submitted, but there are {warnings[0]['count']} pending overdue patches."
                    )
                else:
                    st.success("File is 100% ready to be submitted.")
            else:
                st.error(f"File is {readiness}% ready to be submitted.")

            col1, col2, col3 = st.columns(3)

            col1.metric("Readiness", f"{readiness}%")
            col2.metric("Blocking Issues", sum(item["count"] for item in issues))
            col3.metric("Warnings", sum(item["count"] for item in warnings))

            tab1, tab2, tab3, tab4, tab5 = st.tabs([
                "Blocking Summary",
                "Issue Details",
                "Warnings",
                "sec_uuid Details",
                "Raw Data",
            ])

            with tab1:
                st.subheader("Blocking Summary")

                if issues:
                    st.dataframe(pd.DataFrame(issues), use_container_width=True)
                else:
                    st.success("No blocking issues found.")

            with tab2:
                st.subheader("Issue Details by Excel Row")

                if issue_details:
                    details_df = pd.DataFrame(issue_details)
                    st.dataframe(details_df, use_container_width=True)

                    csv = details_df.to_csv(index=False).encode("utf-8")

                    st.download_button(
                        "Download Issue Details CSV",
                        data=csv,
                        file_name="xlsx_readiness_issue_details.csv",
                        mime="text/csv",
                    )
                else:
                    st.success("No issue details found.")

            with tab3:
                st.subheader("Warnings")

                if warnings:
                    st.dataframe(pd.DataFrame(warnings), use_container_width=True)

                    if warning_details:
                        st.subheader("Warning Details by Excel Row")
                        warning_details_df = pd.DataFrame(warning_details)
                        st.dataframe(warning_details_df, use_container_width=True)
                else:
                    st.success("No warnings found.")

            with tab4:
                st.subheader("sec_uuid Validation Details")

                if "sec_uuid_norm" in df.columns:
                    sec_uuid_details = df.copy()
                    sec_uuid_details["expected_sec_uuid"] = (
                        sec_uuid_details["cve_norm"]
                        + "_"
                        + sec_uuid_details["host_norm"]
                    )
                    sec_uuid_details["sec_uuid_valid"] = (
                        sec_uuid_details["sec_uuid_norm"]
                        == sec_uuid_details["expected_sec_uuid"]
                    )

                    st.dataframe(
                        sec_uuid_details[
                            [
                                "excel_row",
                                "sec_uuid",
                                "expected_sec_uuid",
                                "sec_uuid_valid",
                                "cve_id",
                                "host_name",
                            ]
                        ],
                        use_container_width=True,
                    )
                else:
                    st.info("sec_uuid validation could not run due to missing required columns.")

            with tab5:
                st.subheader("Raw Data")
                st.dataframe(df, use_container_width=True)

        except Exception as e:
            st.error(str(e))
