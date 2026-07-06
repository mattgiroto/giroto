import pandas as pd
import streamlit as st
from datetime import datetime, date, timedelta


CSV_OS_ALLOWED = ["ibm z/os", "ibm z/vm"]


def normalize_text(value):
    if pd.isna(value):
        return ""
    return str(value).strip()


def normalize_date(value):
    if pd.isna(value):
        return ""
    return str(value).split("T")[0].strip()


def normalize_severity(value):
    value = normalize_text(value).upper()
    return "MEDIUM" if value == "MODERATE" else value


def normalize_remediation_status(value):
    value = normalize_text(value).upper()

    if value in ["", "DEFFERED", "DEFERRED"]:
        return "PENDING"

    return value


def parse_date(value):
    value = normalize_date(value)

    if not value:
        return None

    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError:
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
    if row["remediation_status_norm"] != "PENDING":
        return False

    due_date = calculate_due_date(
        row.get("cve_cache.published"),
        row.get("cvss"),
    )

    if not due_date:
        return False

    return date.today() > due_date


def validate_columns(df, required_columns):
    missing = [col for col in required_columns if col not in df.columns]

    if missing:
        raise ValueError(f"Missing columns in XLSX: {', '.join(missing)}")


def prepare_data(xlsx_file):
    df = pd.read_excel(xlsx_file, sheet_name=0, dtype=str)
    df.columns = df.columns.str.strip()

    validate_columns(
        df,
        [
            "cve_id",
            "host_name",
            "operating_system",
            "cvss",
            "cve_cache.published",
            "remediation_status",
            "Team",
        ],
    )

    df["operating_system_norm"] = (
        df["operating_system"]
        .fillna("")
        .str.strip()
        .str.lower()
    )

    df = df[df["operating_system_norm"].isin(CSV_OS_ALLOWED)].copy()

    df["cve_id_norm"] = df["cve_id"].fillna("").astype(str).str.strip()
    df = df[df["cve_id_norm"] != ""].copy()

    df["severity_norm"] = df["cvss"].apply(normalize_severity)
    df["remediation_status_norm"] = df["remediation_status"].apply(
        normalize_remediation_status
    )

    df["published_date"] = df["cve_cache.published"].apply(parse_date)

    if "remediation_status_updated_at" in df.columns:
        df["status_updated_date"] = df["remediation_status_updated_at"].apply(parse_date)
    else:
        df["status_updated_date"] = None

    df["is_overdue"] = df.apply(is_overdue, axis=1)

    return df


def build_kpis(df):
    installed_patches = df[
        df["remediation_status_norm"] == "REMEDIATED"
    ]["cve_id_norm"].nunique()

    pending_patches = df[
        df["remediation_status_norm"] == "PENDING"
    ]["cve_id_norm"].nunique()

    critical_overdues = df[
        (df["severity_norm"] == "CRITICAL")
        & (df["is_overdue"])
    ]["cve_id_norm"].nunique()

    high_overdues = df[
        (df["severity_norm"] == "HIGH")
        & (df["is_overdue"])
    ]["cve_id_norm"].nunique()

    medium_overdues = df[
        (df["severity_norm"] == "MEDIUM")
        & (df["is_overdue"])
    ]["cve_id_norm"].nunique()

    last_30_days = date.today() - timedelta(days=30)

    installed_last_month = df[
        (df["remediation_status_norm"] == "REMEDIATED")
        & (df["status_updated_date"].notna())
        & (df["status_updated_date"] >= last_30_days)
    ]["cve_id_norm"].nunique()

    return {
        "installed_patches": installed_patches,
        "pending_patches": pending_patches,
        "critical_overdues": critical_overdues,
        "high_overdues": high_overdues,
        "medium_overdues": medium_overdues,
        "installed_last_month": installed_last_month,
    }


def build_pending_by_team(df):
    pending_df = df[df["remediation_status_norm"] == "PENDING"].copy()

    result = (
        pending_df
        .groupby("Team")["cve_id_norm"]
        .nunique()
        .reset_index()
        .rename(columns={"cve_id_norm": "pending_cves"})
        .sort_values("pending_cves", ascending=False)
    )

    return result


st.set_page_config(
    page_title="zOS KPI Dashboard",
    layout="wide",
)

st.title("zOS KPI Dashboard")
st.caption("Developed by Matheus Giroto | IBM Z Vulnerability Management Automation")

st.write("Upload do report XLSX para visualizar KPIs de patching.")

xlsx_file = st.file_uploader("Upload XLSX", type=["xlsx"])

if xlsx_file:
    if st.button("Generate KPIs"):
        progress = st.progress(0)
        status = st.empty()

        try:
            status.info("Reading XLSX...")
            progress.progress(25)

            df = prepare_data(xlsx_file)

            status.info("Calculating KPIs...")
            progress.progress(70)

            kpis = build_kpis(df)
            pending_by_team = build_pending_by_team(df)

            progress.progress(100)
            status.success("KPIs generated successfully.")

            col1, col2, col3 = st.columns(3)

            col1.metric("Patches Installed", kpis["installed_patches"])
            col2.metric("Pending Patches", kpis["pending_patches"])
            col3.metric("Installed Last 30 Days", kpis["installed_last_month"])

            col4, col5, col6 = st.columns(3)

            col4.metric("Critical Overdues", kpis["critical_overdues"])
            col5.metric("High Overdues", kpis["high_overdues"])
            col6.metric("Medium Overdues", kpis["medium_overdues"])

            tab1, tab2, tab3 = st.tabs(
                [
                    "Pending by Team",
                    "Overdue Details",
                    "Raw XLSX Data",
                ]
            )

            with tab1:
                st.subheader("Pending Patches by Team")
                st.dataframe(pending_by_team, use_container_width=True)

                if not pending_by_team.empty:
                    st.bar_chart(
                        pending_by_team.set_index("Team")["pending_cves"]
                    )

            with tab2:
                st.subheader("Overdue Details")

                overdue_details = df[df["is_overdue"]].copy()

                overdue_details = overdue_details[
                    [
                        "cve_id",
                        "host_name",
                        "operating_system",
                        "severity_norm",
                        "cve_cache.published",
                        "remediation_status_norm",
                        "Team",
                    ]
                ].rename(
                    columns={
                        "severity_norm": "severity",
                        "remediation_status_norm": "remediation_status",
                    }
                )

                st.dataframe(overdue_details, use_container_width=True)

            with tab3:
                st.subheader("Filtered XLSX Data")
                st.dataframe(df, use_container_width=True)

        except Exception as e:
            progress.progress(0)
            status.error(str(e))
