import sqlite3
import re
import time
import urllib.parse
from datetime import datetime, date, timedelta

import pandas as pd
import requests
import streamlit as st
from bs4 import BeautifulSoup
import urllib3


DB_PATH = "shield.db"

VERIFY_SSL = False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

IBM_BULLETIN_SEARCH_URL = "https://www.ibm.com/support/pages/bulletin/search/?q={query}"

PRODUCT_SEARCH_QUERIES = {
    "IBM DB2 UDB": "DB2 UDB",
    "IBM DB2 Purescale": "DB2 pureScale",
    "IBM MQ LTS": "IBM MQ",
    "IBM WAS": "WebSphere Application Server",
    "IBM IHS": "IBM HTTP Server",
    "IBM Storage Protect Server": "Storage Protect Server",
    "IBM Storage Protect Client": "Storage Protect Client",
    "Red Hat Open Shift": "OpenShift",
    "Red Hat Enterprise Linux 8": "Red Hat Enterprise Linux 8",
    "Red Hat Enterprise Linux 9": "Red Hat Enterprise Linux 9",
}

STATUSES = [
    "OPEN",
    "PENDING",
    "CLOSED",
    "REMEDIATED",
    "FALSE_POSITIVE",
    "NOT_APPLICABLE",
]


def connect_db():
    return sqlite3.connect(DB_PATH)


def init_db():
    conn = connect_db()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS products (
            product_id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_name TEXT UNIQUE NOT NULL,
            search_query TEXT NOT NULL,
            enabled INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_name TEXT NOT NULL,
            cve_id TEXT,
            apar_id TEXT,
            title TEXT,
            severity TEXT,
            cvss TEXT,
            published_date TEXT,
            due_date TEXT,
            status TEXT DEFAULT 'OPEN',
            comment TEXT,
            source_url TEXT,
            first_seen TEXT DEFAULT CURRENT_TIMESTAMP,
            last_seen TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(product_name, cve_id, apar_id, source_url)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS status_history (
            history_id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id INTEGER,
            old_status TEXT,
            new_status TEXT,
            comment TEXT,
            changed_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    for product_name, search_query in PRODUCT_SEARCH_QUERIES.items():
        cur.execute("""
            INSERT OR IGNORE INTO products (product_name, search_query)
            VALUES (?, ?)
        """, (product_name, search_query))

    conn.commit()
    conn.close()


def normalize_text(value):
    if pd.isna(value):
        return ""
    return str(value).strip()


def normalize_status(value):
    value = normalize_text(value).upper()

    if value in ["", "DEFERRED", "DEFFERED"]:
        return "OPEN"

    return value


def normalize_severity(value):
    value = normalize_text(value).upper()

    if value == "IMPORTANT":
        return "HIGH"
    if value == "MODERATE":
        return "MEDIUM"

    return value


def parse_date(value):
    value = normalize_text(value).split("T")[0]

    if not value:
        return None

    for fmt in ["%Y-%m-%d", "%d %B %Y", "%B %d, %Y"]:
        try:
            return datetime.strptime(value, fmt).date()
        except Exception:
            pass

    return None


def calculate_due_date(published_date, severity):
    published = parse_date(published_date)
    severity = normalize_severity(severity)

    if not published:
        return ""

    if severity == "CRITICAL":
        return (published + timedelta(days=14)).isoformat()
    if severity == "HIGH":
        return (published + timedelta(days=60)).isoformat()
    if severity == "MEDIUM":
        return (published + timedelta(days=180)).isoformat()

    return ""


def get_date_range(mode, custom_start=None, custom_end=None):
    today = date.today()

    if mode == "Last 30 days":
        return today - timedelta(days=30), today
    if mode == "Last 90 days":
        return today - timedelta(days=90), today
    if mode == "Last 180 days":
        return today - timedelta(days=180), today
    if mode == "Last 1 year":
        return today - timedelta(days=365), today
    if mode == "Custom":
        return custom_start, custom_end

    return None, None


def date_in_range(published_date, start_date, end_date):
    parsed = parse_date(published_date)

    if not parsed:
        return False

    if start_date and parsed < start_date:
        return False

    if end_date and parsed > end_date:
        return False

    return True


def is_overdue(status, due_date):
    status = normalize_status(status)

    if status not in ["OPEN", "PENDING"]:
        return False

    due = parse_date(due_date)

    if not due:
        return False

    return date.today() > due


def get_products_df():
    conn = connect_db()
    df = pd.read_sql_query(
        "SELECT * FROM products WHERE enabled = 1 ORDER BY product_name",
        conn,
    )
    conn.close()
    return df


def load_findings():
    conn = connect_db()
    df = pd.read_sql_query(
        "SELECT * FROM findings ORDER BY first_seen DESC",
        conn,
    )
    conn.close()

    if df.empty:
        return df

    df["status_norm"] = df["status"].apply(normalize_status)
    df["severity_norm"] = df["severity"].apply(normalize_severity)
    df["is_overdue"] = df.apply(
        lambda row: is_overdue(row["status_norm"], row["due_date"]),
        axis=1,
    )

    return df


def insert_finding(row):
    conn = connect_db()
    cur = conn.cursor()

    product_name = normalize_text(row.get("product_name"))
    cve_id = normalize_text(row.get("cve_id"))
    apar_id = normalize_text(row.get("apar_id"))
    title = normalize_text(row.get("title"))
    severity = normalize_severity(row.get("severity"))
    cvss = normalize_text(row.get("cvss"))
    published_date = normalize_text(row.get("published_date"))
    due_date = normalize_text(row.get("due_date")) or calculate_due_date(
        published_date,
        severity,
    )
    status = normalize_status(row.get("status"))
    comment = normalize_text(row.get("comment"))
    source_url = normalize_text(row.get("source_url"))

    cur.execute("""
        INSERT OR IGNORE INTO findings (
            product_name,
            cve_id,
            apar_id,
            title,
            severity,
            cvss,
            published_date,
            due_date,
            status,
            comment,
            source_url,
            last_seen
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    """, (
        product_name,
        cve_id,
        apar_id,
        title,
        severity,
        cvss,
        published_date,
        due_date,
        status,
        comment,
        source_url,
    ))

    cur.execute("""
        UPDATE findings
        SET last_seen = CURRENT_TIMESTAMP
        WHERE product_name = ?
          AND COALESCE(cve_id, '') = ?
          AND COALESCE(apar_id, '') = ?
          AND COALESCE(source_url, '') = ?
    """, (
        product_name,
        cve_id,
        apar_id,
        source_url,
    ))

    conn.commit()
    conn.close()


def update_finding_status(finding_id, new_status, comment):
    conn = connect_db()
    cur = conn.cursor()

    cur.execute("SELECT status FROM findings WHERE finding_id = ?", (finding_id,))
    result = cur.fetchone()

    if not result:
        conn.close()
        return

    old_status = result[0]
    new_status = normalize_status(new_status)

    cur.execute("""
        UPDATE findings
        SET status = ?, comment = ?, last_seen = CURRENT_TIMESTAMP
        WHERE finding_id = ?
    """, (new_status, comment, finding_id))

    cur.execute("""
        INSERT INTO status_history (
            finding_id,
            old_status,
            new_status,
            comment
        )
        VALUES (?, ?, ?, ?)
    """, (finding_id, old_status, new_status, comment))

    conn.commit()
    conn.close()


def http_get(url):
    headers = {
        "User-Agent": "Mozilla/5.0 SHIELD Patch Intelligence Tool",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    response = requests.get(
        url,
        headers=headers,
        timeout=30,
        verify=VERIFY_SSL,
    )
    response.raise_for_status()
    return response.text


def build_ibm_search_url(query):
    encoded = urllib.parse.quote_plus(query)
    return IBM_BULLETIN_SEARCH_URL.format(query=encoded)


def extract_bulletin_links_from_search(html):
    soup = BeautifulSoup(html, "html.parser")
    links = []

    for a in soup.find_all("a", href=True):
        href = a.get("href", "")
        text = a.get_text(" ", strip=True)

        if not href:
            continue

        if "security-bulletin" not in href.lower() and "support/pages/node" not in href.lower():
            continue

        if href.startswith("/"):
            href = "https://www.ibm.com" + href

        if href.startswith("http://www.ibm.com"):
            href = href.replace("http://", "https://", 1)

        if "ibm.com/support/pages" not in href:
            continue

        links.append({
            "title": text,
            "url": href.split("?")[0],
        })

    deduped = []
    seen = set()

    for item in links:
        if item["url"] not in seen:
            seen.add(item["url"])
            deduped.append(item)

    return deduped


def extract_cves(text):
    return sorted(set(
        cve.upper()
        for cve in re.findall(r"CVE-\d{4}-\d{4,}", text, flags=re.IGNORECASE)
    ))


def extract_apars(text):
    return sorted(set(re.findall(r"\b[A-Z]{2}\d{5}\b", text)))


def extract_cvss(text):
    patterns = [
        r"CVSS[^0-9]{0,40}([0-9]{1,2}\.[0-9])",
        r"Base Score[^0-9]{0,40}([0-9]{1,2}\.[0-9])",
    ]

    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            return match.group(1)

    return ""


def extract_severity(text):
    match = re.search(
        r"\b(Critical|High|Important|Medium|Moderate|Low)\b",
        text,
        flags=re.IGNORECASE,
    )

    if match:
        return normalize_severity(match.group(1))

    return ""


def extract_published_date(text):
    patterns = [
        r"(20\d{2}-\d{2}-\d{2})",
        r"Published[^0-9A-Za-z]{0,20}([A-Z][a-z]+ \d{1,2}, 20\d{2})",
        r"Release date[^0-9A-Za-z]{0,20}([A-Z][a-z]+ \d{1,2}, 20\d{2})",
    ]

    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            raw = match.group(1)
            parsed = parse_date(raw)
            return parsed.isoformat() if parsed else raw

    return ""


def parse_bulletin_page(url, product_name):
    html = http_get(url)
    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text("\n", strip=True)

    title = soup.title.get_text(" ", strip=True) if soup.title else "IBM Security Bulletin"

    cves = extract_cves(text)
    apars = extract_apars(text)
    severity = extract_severity(text)
    cvss = extract_cvss(text)
    published_date = extract_published_date(text)

    rows = []

    if cves:
        for cve in cves:
            rows.append({
                "product_name": product_name,
                "cve_id": cve,
                "apar_id": ", ".join(apars),
                "title": title,
                "severity": severity,
                "cvss": cvss,
                "published_date": published_date,
                "status": "OPEN",
                "comment": "",
                "source_url": url,
            })
    elif apars:
        for apar in apars:
            rows.append({
                "product_name": product_name,
                "cve_id": "",
                "apar_id": apar,
                "title": title,
                "severity": severity,
                "cvss": cvss,
                "published_date": published_date,
                "status": "OPEN",
                "comment": "",
                "source_url": url,
            })
    else:
        rows.append({
            "product_name": product_name,
            "cve_id": "",
            "apar_id": "",
            "title": title,
            "severity": severity,
            "cvss": cvss,
            "published_date": published_date,
            "status": "OPEN",
            "comment": "Review bulletin manually",
            "source_url": url,
        })

    return rows


def search_product_bulletins(product_name, query, max_bulletins):
    search_url = build_ibm_search_url(query)
    html = http_get(search_url)
    links = extract_bulletin_links_from_search(html)

    if max_bulletins:
        links = links[:max_bulletins]

    all_rows = []

    for link in links:
        try:
            rows = parse_bulletin_page(link["url"], product_name)
            all_rows.extend(rows)
            time.sleep(0.5)
        except Exception as e:
            all_rows.append({
                "product_name": product_name,
                "cve_id": "",
                "apar_id": "",
                "title": link.get("title", "Failed to parse bulletin"),
                "severity": "",
                "cvss": "",
                "published_date": "",
                "status": "OPEN",
                "comment": f"Parse failed: {e}",
                "source_url": link["url"],
            })

    return search_url, links, all_rows


def import_file(uploaded_file):
    filename = uploaded_file.name.lower()

    if filename.endswith(".csv"):
        df = pd.read_csv(uploaded_file, dtype=str)
    else:
        df = pd.read_excel(uploaded_file, dtype=str)

    df.columns = df.columns.str.strip()

    if "product_name" not in df.columns:
        raise ValueError("Missing required column: product_name")

    for _, row in df.iterrows():
        insert_finding(row.to_dict())

    return len(df)


def build_kpis(df):
    if df.empty:
        return {
            "open": 0,
            "closed": 0,
            "overdue": 0,
            "critical_overdue": 0,
            "high_overdue": 0,
            "medium_overdue": 0,
        }

    open_df = df[df["status_norm"].isin(["OPEN", "PENDING"])]
    closed_df = df[df["status_norm"].isin([
        "CLOSED",
        "REMEDIATED",
        "FALSE_POSITIVE",
        "NOT_APPLICABLE",
    ])]
    overdue_df = df[df["is_overdue"] == True]

    return {
        "open": open_df["finding_id"].nunique(),
        "closed": closed_df["finding_id"].nunique(),
        "overdue": overdue_df["finding_id"].nunique(),
        "critical_overdue": overdue_df[overdue_df["severity_norm"] == "CRITICAL"]["finding_id"].nunique(),
        "high_overdue": overdue_df[overdue_df["severity_norm"] == "HIGH"]["finding_id"].nunique(),
        "medium_overdue": overdue_df[overdue_df["severity_norm"] == "MEDIUM"]["finding_id"].nunique(),
    }


init_db()

st.set_page_config(
    page_title="Project SHIELD",
    layout="wide",
)

st.title("🛡️ Project SHIELD")
st.caption("Patch Intelligence Platform | Developed by Matheus Giroto")

tabs = st.tabs([
    "Search Bulletins",
    "Update DB",
    "KPIs",
    "Import",
    "Raw DB",
])

products_df = get_products_df()


with tabs[0]:
    st.subheader("Search IBM Security Bulletins")

    selected_products = st.multiselect(
        "Products",
        products_df["product_name"].tolist(),
        default=[],
    )

    max_bulletins = st.number_input(
        "Max bulletins per product",
        min_value=1,
        max_value=100,
        value=10,
        step=1,
    )

    date_filter_mode = st.selectbox(
        "Date filter",
        [
            "Last 30 days",
            "Last 90 days",
            "Last 180 days",
            "Last 1 year",
            "Custom",
            "No filter",
        ],
        index=3,
    )

    custom_start = None
    custom_end = None

    if date_filter_mode == "Custom":
        col_start, col_end = st.columns(2)
        with col_start:
            custom_start = st.date_input("Start date")
        with col_end:
            custom_end = st.date_input("End date")

    if st.button("Search and Update Local DB", type="primary"):
        if not selected_products:
            st.warning("Select at least one product.")
        else:
            start_filter, end_filter = get_date_range(
                date_filter_mode,
                custom_start,
                custom_end,
            )

            progress = st.progress(0)
            status = st.empty()
            logs = []
            preview_rows = []

            for idx, product_name in enumerate(selected_products, start=1):
                product_row = products_df[products_df["product_name"] == product_name].iloc[0]
                query = product_row["search_query"]

                status.info(f"Searching bulletins for {product_name}...")
                progress.progress(int((idx - 1) / len(selected_products) * 100))

                try:
                    search_url, links, rows = search_product_bulletins(
                        product_name,
                        query,
                        int(max_bulletins),
                    )

                    logs.append(f"[INFO] {product_name}: {len(links)} bulletin links found")
                    logs.append(f"[INFO] Search URL: {search_url}")

                    filtered_rows = []

                    for row in rows:
                        if start_filter or end_filter:
                            if not date_in_range(
                                row.get("published_date"),
                                start_filter,
                                end_filter,
                            ):
                                continue

                        insert_finding(row)
                        filtered_rows.append(row)

                    preview_rows.extend(filtered_rows)

                    logs.append(f"[INFO] {product_name}: {len(rows)} rows parsed")
                    logs.append(f"[INFO] {product_name}: {len(filtered_rows)} rows saved after date filter")

                except Exception as e:
                    logs.append(f"[ERROR] {product_name}: {e}")

            progress.progress(100)
            status.success("Search completed.")

            st.subheader("Preview")
            if preview_rows:
                st.dataframe(pd.DataFrame(preview_rows), use_container_width=True)
            else:
                st.warning("No rows found for the selected date range.")

            with st.expander("Logs"):
                st.code("\n".join(logs))


with tabs[1]:
    st.subheader("Update DB Status")

    df = load_findings()

    if df.empty:
        st.warning("No findings in local DB yet.")
    else:
        open_only = st.checkbox("Show only Open/Pending", value=True)

        selectable_df = df.copy()

        if open_only:
            selectable_df = selectable_df[
                selectable_df["status_norm"].isin(["OPEN", "PENDING"])
            ]

        if selectable_df.empty:
            st.info("No findings available for selected filter.")
        else:
            selected_id = st.selectbox(
                "Finding ID",
                selectable_df["finding_id"].tolist(),
            )

            selected_row = df[df["finding_id"] == selected_id].iloc[0]
            st.dataframe(pd.DataFrame([selected_row]), use_container_width=True)

            new_status = st.selectbox("New Status", STATUSES)
            comment = st.text_area("Comment / Evidence")

            if st.button("Update Status"):
                update_finding_status(selected_id, new_status, comment)
                st.success("Status updated.")


with tabs[2]:
    st.subheader("KPIs")

    df = load_findings()
    kpis = build_kpis(df)

    col1, col2, col3 = st.columns(3)
    col1.metric("Open", kpis["open"])
    col2.metric("Closed", kpis["closed"])
    col3.metric("Overdue", kpis["overdue"])

    col4, col5, col6 = st.columns(3)
    col4.metric("Critical Overdue", kpis["critical_overdue"])
    col5.metric("High Overdue", kpis["high_overdue"])
    col6.metric("Medium Overdue", kpis["medium_overdue"])

    if not df.empty:
        st.subheader("Open by Product")

        open_by_product = (
            df[df["status_norm"].isin(["OPEN", "PENDING"])]
            .groupby("product_name")["finding_id"]
            .nunique()
            .reset_index()
            .rename(columns={"finding_id": "open_findings"})
            .sort_values("open_findings", ascending=False)
        )

        st.dataframe(open_by_product, use_container_width=True)

        if not open_by_product.empty:
            st.bar_chart(open_by_product.set_index("product_name")["open_findings"])

        st.subheader("Overdue Details")
        st.dataframe(df[df["is_overdue"] == True], use_container_width=True)


with tabs[3]:
    st.subheader("Manual Import CSV/XLSX")

    st.write("Recommended Columns:")

    st.code(
        "product_name,cve_id,apar_id,title,severity,cvss,published_date,due_date,status,comment,source_url"
    )

    uploaded_file = st.file_uploader("Upload CSV or XLSX", type=["csv", "xlsx"])

    if uploaded_file and st.button("Import to Local DB"):
        try:
            count = import_file(uploaded_file)
            st.success(f"Imported {count} rows.")
        except Exception as e:
            st.error(str(e))


with tabs[4]:
    st.subheader("Raw Local Database")

    df = load_findings()

    if df.empty:
        st.info("Database is empty.")
    else:
        st.dataframe(df, use_container_width=True)

        export_csv = df.to_csv(index=False).encode("utf-8")

        st.download_button(
            "Export Full DB CSV",
            data=export_csv,
            file_name="shield_db_export.csv",
            mime="text/csv",
        )
