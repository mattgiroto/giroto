import sqlite3
import re
from datetime import datetime, date, timedelta
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import feedparser
import pandas as pd
import requests
import streamlit as st
from bs4 import BeautifulSoup
import urllib3


DB_PATH = "shield_live.db"

VERIFY_SSL = False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


IBM_RSS_FEEDS = {
    "IBM DB2 UDB": "https://www.ibm.com/systems/support/myfeed/xmlfeeder.wss?feeder.requid=feeder.create_feed&feeder.feedtype=RSS&feeder.uid=698000AXZD&feeder.subscrid=S19f3d4bc96d&feeder.subdefkey=swgother&feeder.maxfeed=25",
    "IBM MQ LTS": "https://www.ibm.com/systems/support/myfeed/xmlfeeder.wss?feeder.requid=feeder.create_feed&feeder.feedtype=RSS&feeder.uid=698000AXZD&feeder.subscrid=S19f3d479aee&feeder.subdefkey=swgother&feeder.maxfeed=25",
    "IBM WAS": "https://www.ibm.com/systems/support/myfeed/xmlfeeder.wss?feeder.requid=feeder.create_feed&feeder.feedtype=RSS&feeder.uid=698000AXZD&feeder.subscrid=S19f3d46b1ae&feeder.subdefkey=swgother&feeder.maxfeed=25",
    "IBM IHS": "https://www.ibm.com/systems/support/myfeed/xmlfeeder.wss?feeder.requid=feeder.create_feed&feeder.feedtype=RSS&feeder.uid=698000AXZD&feeder.subscrid=S18e0fc65efe&feeder.subdefkey=swgother&feeder.maxfeed=25",
    "IBM Storage Protect Server": "https://www.ibm.com/systems/support/myfeed/xmlfeeder.wss?feeder.requid=feeder.create_feed&feeder.feedtype=RSS&feeder.uid=698000AXZD&feeder.subscrid=S19f3d4c4442&feeder.subdefkey=swgother&feeder.maxfeed=25",
    "IBM Storage Protect Client": "https://www.ibm.com/systems/support/myfeed/xmlfeeder.wss?feeder.requid=feeder.create_feed&feeder.feedtype=RSS&feeder.uid=698000AXZD&feeder.subscrid=S18e0fbc8cc6&feeder.subdefkey=swgother&feeder.maxfeed=25",
    "Additional IBM Feed 1": "https://www.ibm.com/systems/support/myfeed/xmlfeeder.wss?feeder.requid=feeder.create_feed&feeder.feedtype=RSS&feeder.uid=698000AXZD&feeder.subscrid=S18e0fcc465a&feeder.subdefkey=swgother&feeder.maxfeed=25",
    "Additional IBM Feed 2": "https://www.ibm.com/systems/support/myfeed/xmlfeeder.wss?feeder.requid=feeder.create_feed&feeder.feedtype=RSS&feeder.uid=698000AXZD&feeder.subscrid=S18e0fc4ac40&feeder.subdefkey=swgother&feeder.maxfeed=25",
    "Additional IBM Feed 3": "https://www.ibm.com/systems/support/myfeed/xmlfeeder.wss?feeder.requid=feeder.create_feed&feeder.feedtype=RSS&feeder.uid=698000AXZD&feeder.subscrid=S19f3d472a2c&feeder.subdefkey=swgother&feeder.maxfeed=25",
}


SLO_DAYS_BY_SEVERITY = {
    "CRITICAL": 14,
    "HIGH": 60,
    "MEDIUM": 180,
}

GRACE_DAYS = 30
NO_DUE_DATE_SEVERITIES = {"LOW", "INFO", "INFORMATIONAL"}


def connect_db():
    return sqlite3.connect(DB_PATH)


def ensure_column(cur, table_name, column_name, column_definition):
    cur.execute(f"PRAGMA table_info({table_name})")
    existing_columns = [column[1] for column in cur.fetchall()]

    if column_name not in existing_columns:
        cur.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_definition}")


def init_db():
    conn = connect_db()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS bulletins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            url TEXT UNIQUE,
            product TEXT,
            feed_name TEXT,
            published_date TEXT,
            severity TEXT,
            cvss TEXT,
            status TEXT DEFAULT 'OPEN',
            first_seen TEXT DEFAULT CURRENT_TIMESTAMP,
            last_seen TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS cves (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bulletin_url TEXT,
            cve_id TEXT,
            status TEXT DEFAULT 'OPEN',
            due_date TEXT,
            grace_due_date TEXT,
            UNIQUE(bulletin_url, cve_id)
        )
    """)

    # Safe migrations for old local databases.
    ensure_column(cur, "bulletins", "feed_name", "TEXT")
    ensure_column(cur, "cves", "due_date", "TEXT")
    ensure_column(cur, "cves", "grace_due_date", "TEXT")

    conn.commit()
    conn.close()


def normalize_text(value):
    if value is None:
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
    if value in ["INFORMATION", "INFORMATIONAL"]:
        return "INFO"

    return value


def parse_date(value):
    value = normalize_text(value)

    if not value:
        return None

    original_value = value

    # ISO strings can come as YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS.
    if "T" in value:
        value = value.split("T")[0]

    formats = [
        "%Y-%m-%d",
        "%a, %d %b %Y %H:%M:%S %z",
        "%a, %d %b %Y %H:%M:%S %Z",
        "%d %b %Y",
        "%B %d, %Y",
    ]

    for candidate in [value, original_value]:
        for fmt in formats:
            try:
                parsed = datetime.strptime(candidate, fmt)
                return parsed.date()
            except Exception:
                pass

    return None


def calculate_due_date(published_date, severity):
    published = parse_date(published_date)
    severity = normalize_severity(severity)

    if not published:
        return ""

    slo_days = SLO_DAYS_BY_SEVERITY.get(severity)

    if not slo_days:
        return ""

    return (published + timedelta(days=slo_days)).isoformat()


def calculate_grace_due_date(published_date, severity):
    due_date = parse_date(calculate_due_date(published_date, severity))

    if not due_date:
        return ""

    return (due_date + timedelta(days=GRACE_DAYS)).isoformat()


def calculate_slo_zone(status, due_date, grace_due_date=None, severity=""):
    status = normalize_status(status)
    severity = normalize_severity(severity)

    if severity in NO_DUE_DATE_SEVERITIES:
        return "NO_DUE_DATE"

    if status != "OPEN":
        return "CLOSED"

    due = parse_date(due_date)

    if not due:
        return "NO_DUE_DATE"

    grace = parse_date(grace_due_date) if grace_due_date else due + timedelta(days=GRACE_DAYS)
    today = date.today()

    if today <= due:
        return "WITHIN_SLO"
    if today <= grace:
        return "DANGER_ZONE"

    return "RED_ZONE"


def calculate_days_to_due(due_date):
    due = parse_date(due_date)

    if not due:
        return None

    return (due - date.today()).days


def increase_feed_limit(url, limit):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)

    query["feeder.maxfeed"] = [str(limit)]

    new_query = urlencode(query, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def extract_cves(text):
    return sorted(set(
        cve.upper()
        for cve in re.findall(r"CVE-\d{4}-\d{4,}", text, flags=re.IGNORECASE)
    ))


def extract_cvss(text):
    patterns = [
        r"CVSS[^0-9]{0,40}([0-9]{1,2}\.[0-9])",
        r"Base Score[^0-9]{0,40}([0-9]{1,2}\.[0-9])",
    ]

    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(1)

    return ""


def extract_severity(text):
    match = re.search(
        r"\b(Critical|High|Important|Medium|Moderate|Low|Info|Informational)\b",
        text,
        re.IGNORECASE,
    )

    if match:
        return normalize_severity(match.group(1))

    return ""


def fetch_bulletin_page(url):
    headers = {
        "User-Agent": "Mozilla/5.0 Project SHIELD Live Patch Intelligence",
    }

    response = requests.get(
        url,
        headers=headers,
        timeout=30,
        verify=VERIFY_SSL,
    )
    response.raise_for_status()

    soup = BeautifulSoup(response.text, "html.parser")
    return soup.get_text("\n", strip=True)


def save_bulletin(title, url, product, feed_name, published_date, severity, cvss, cves):
    conn = connect_db()
    cur = conn.cursor()

    severity = normalize_severity(severity)
    due_date = calculate_due_date(published_date, severity)
    grace_due_date = calculate_grace_due_date(published_date, severity)

    cur.execute("""
        INSERT OR IGNORE INTO bulletins (
            title,
            url,
            product,
            feed_name,
            published_date,
            severity,
            cvss
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        title,
        url,
        product,
        feed_name,
        published_date,
        severity,
        cvss,
    ))

    cur.execute("""
        UPDATE bulletins
        SET last_seen = CURRENT_TIMESTAMP,
            product = ?,
            feed_name = ?,
            published_date = COALESCE(NULLIF(published_date, ''), ?),
            severity = COALESCE(NULLIF(severity, ''), ?),
            cvss = COALESCE(NULLIF(cvss, ''), ?)
        WHERE url = ?
    """, (
        product,
        feed_name,
        published_date,
        severity,
        cvss,
        url,
    ))

    for cve in cves:
        cur.execute("""
            INSERT OR IGNORE INTO cves (
                bulletin_url,
                cve_id,
                status,
                due_date,
                grace_due_date
            )
            VALUES (?, ?, 'OPEN', ?, ?)
        """, (
            url,
            cve,
            due_date,
            grace_due_date,
        ))

        cur.execute("""
            UPDATE cves
            SET due_date = COALESCE(NULLIF(due_date, ''), ?),
                grace_due_date = COALESCE(NULLIF(grace_due_date, ''), ?)
            WHERE bulletin_url = ?
              AND cve_id = ?
        """, (
            due_date,
            grace_due_date,
            url,
            cve,
        ))

    conn.commit()
    conn.close()


def sync_single_rss(feed_name, feed_url, max_feed_items):
    feed_url = increase_feed_limit(feed_url, max_feed_items)
    feed = feedparser.parse(feed_url)

    logs = []
    processed = 0
    saved = 0

    if feed.bozo:
        logs.append(f"[WARNING] {feed_name}: Feed parser warning: {feed.bozo_exception}")

    for entry in feed.entries:
        processed += 1

        title = normalize_text(entry.get("title"))
        url = normalize_text(entry.get("link"))
        summary = normalize_text(entry.get("summary"))
        published = (
            normalize_text(entry.get("published"))
            or normalize_text(entry.get("updated"))
        )

        if not url:
            logs.append(f"[SKIP] {feed_name}: entry without URL: {title}")
            continue

        try:
            page_text = fetch_bulletin_page(url)
        except Exception as e:
            logs.append(f"[WARNING] {feed_name}: Could not fetch page, using RSS text only: {title} | {e}")
            page_text = f"{title}\n{summary}"

        cves = extract_cves(page_text)
        severity = extract_severity(page_text)
        cvss = extract_cvss(page_text)

        parsed_date = parse_date(published)
        published_date = parsed_date.isoformat() if parsed_date else ""

        save_bulletin(
            title=title,
            url=url,
            product=feed_name,
            feed_name=feed_name,
            published_date=published_date,
            severity=severity,
            cvss=cvss,
            cves=cves,
        )

        saved += 1
        logs.append(
            f"[OK] {feed_name} | {title} | CVEs: {len(cves)} | Severity: {severity or 'N/A'}"
        )

    return processed, saved, logs


def sync_selected_feeds(selected_feeds, max_feed_items):
    all_logs = []
    total_processed = 0
    total_saved = 0

    for feed_name in selected_feeds:
        feed_url = IBM_RSS_FEEDS[feed_name]

        processed, saved, logs = sync_single_rss(
            feed_name,
            feed_url,
            max_feed_items,
        )

        total_processed += processed
        total_saved += saved
        all_logs.extend(logs)

    return total_processed, total_saved, all_logs


def load_data():
    conn = connect_db()

    bulletins = pd.read_sql_query(
        "SELECT * FROM bulletins ORDER BY first_seen DESC",
        conn,
    )

    cves = pd.read_sql_query(
        "SELECT * FROM cves ORDER BY id DESC",
        conn,
    )

    conn.close()

    return bulletins, cves


def enrich_cves_with_bulletins(cves, bulletins):
    if cves.empty:
        return cves

    enriched = cves.copy()

    if not bulletins.empty:
        product_map = bulletins.set_index("url")["product"].to_dict()
        feed_map = bulletins.set_index("url")["feed_name"].to_dict()
        severity_map = bulletins.set_index("url")["severity"].to_dict()
        published_map = bulletins.set_index("url")["published_date"].to_dict()
        title_map = bulletins.set_index("url")["title"].to_dict()
        cvss_map = bulletins.set_index("url")["cvss"].to_dict()

        enriched["product"] = enriched["bulletin_url"].map(product_map)
        enriched["feed_name"] = enriched["bulletin_url"].map(feed_map)
        enriched["severity"] = enriched["bulletin_url"].map(severity_map)
        enriched["published_date"] = enriched["bulletin_url"].map(published_map)
        enriched["bulletin_title"] = enriched["bulletin_url"].map(title_map)
        enriched["cvss"] = enriched["bulletin_url"].map(cvss_map)
    else:
        enriched["product"] = ""
        enriched["feed_name"] = ""
        enriched["severity"] = ""
        enriched["published_date"] = ""
        enriched["bulletin_title"] = ""
        enriched["cvss"] = ""

    # Backfill dates in the dataframe if old DB records do not have them yet.
    enriched["due_date"] = enriched.apply(
        lambda row: row["due_date"] or calculate_due_date(row.get("published_date", ""), row.get("severity", "")),
        axis=1,
    )

    enriched["grace_due_date"] = enriched.apply(
        lambda row: row["grace_due_date"] or calculate_grace_due_date(row.get("published_date", ""), row.get("severity", "")),
        axis=1,
    )

    enriched["status_norm"] = enriched["status"].apply(normalize_status)
    enriched["severity"] = enriched["severity"].apply(normalize_severity)

    enriched["slo_zone"] = enriched.apply(
        lambda row: calculate_slo_zone(
            row["status_norm"],
            row["due_date"],
            row["grace_due_date"],
            row["severity"],
        ),
        axis=1,
    )

    enriched["days_to_due"] = enriched["due_date"].apply(calculate_days_to_due)

    return enriched


def is_overdue(status, due_date):
    status = normalize_status(status)

    if status != "OPEN":
        return False

    parsed = parse_date(due_date)

    if not parsed:
        return False

    return date.today() > parsed


def build_kpis(bulletins, cves):
    if cves.empty:
        return {
            "open": 0,
            "closed": 0,
            "overdue": 0,
            "danger_zone": 0,
            "red_zone": 0,
            "no_due_date": 0,
            "unique_cves": 0,
            "bulletins": len(bulletins),
        }

    enriched = enrich_cves_with_bulletins(cves, bulletins)

    enriched["is_overdue"] = enriched.apply(
        lambda row: is_overdue(row["status_norm"], row["due_date"]),
        axis=1,
    )

    return {
        "open": len(enriched[enriched["status_norm"] == "OPEN"]),
        "closed": len(enriched[enriched["status_norm"] != "OPEN"]),
        "overdue": len(enriched[enriched["is_overdue"] == True]),
        "danger_zone": len(enriched[enriched["slo_zone"] == "DANGER_ZONE"]),
        "red_zone": len(enriched[enriched["slo_zone"] == "RED_ZONE"]),
        "no_due_date": len(enriched[enriched["slo_zone"] == "NO_DUE_DATE"]),
        "unique_cves": enriched["cve_id"].nunique(),
        "bulletins": len(bulletins),
    }


def update_cve_status(cve_db_id, new_status):
    conn = connect_db()
    cur = conn.cursor()

    cur.execute("""
        UPDATE cves
        SET status = ?
        WHERE id = ?
    """, (
        normalize_status(new_status),
        cve_db_id,
    ))

    conn.commit()
    conn.close()


def backfill_cve_dates():
    bulletins, cves = load_data()

    if bulletins.empty or cves.empty:
        return 0

    enriched = enrich_cves_with_bulletins(cves, bulletins)
    conn = connect_db()
    cur = conn.cursor()
    updated = 0

    for _, row in enriched.iterrows():
        if row.get("due_date") or row.get("grace_due_date"):
            cur.execute("""
                UPDATE cves
                SET due_date = ?,
                    grace_due_date = ?
                WHERE id = ?
            """, (
                row.get("due_date", ""),
                row.get("grace_due_date", ""),
                int(row["id"]),
            ))
            updated += 1

    conn.commit()
    conn.close()

    return updated


init_db()

st.set_page_config(
    page_title="Project SHIELD Live",
    layout="wide",
)

st.title("🛡️Project SHIELD Live")
st.caption("Security Advisory Intelligence Platform | Developed by Matheus Giroto")

with st.sidebar:
    st.header("SLO Rules")
    st.markdown("""
    - **Critical:** 14 days
    - **High:** 60 days
    - **Medium:** 180 days
    - **Low / Info:** No Due Date
    - **Grace:** 30 days after original SLO
    """)

    if st.button("Backfill Due Dates"):
        updated = backfill_cve_dates()
        st.success(f"Backfill completed. CVE rows evaluated: {updated}.")

tabs = st.tabs([
    "Live RSS Sync",
    "KPIs",
    "Bulletins",
    "CVEs",
    "Update Status",
])

with tabs[0]:
    st.subheader("IBM RSS Sync")

    selected_feeds = st.multiselect(
        "RSS Feeds / Products",
        list(IBM_RSS_FEEDS.keys()),
        default=list(IBM_RSS_FEEDS.keys()),
    )

    max_feed_items = st.number_input(
        "Max feed items per RSS",
        min_value=1,
        max_value=500,
        value=100,
        step=25,
    )

    st.info(
        "This sync reads multiple IBM RSS feeds, fetches each bulletin page, extracts CVEs, severity and CVSS, "
        "then stores everything in a local SQLite database. Due Date and Grace Due Date are calculated automatically."
    )

    if st.button("Sync Selected RSS Feeds", type="primary"):
        if not selected_feeds:
            st.warning("Select at least one RSS feed.")
        else:
            with st.spinner("Syncing selected RSS feeds..."):
                try:
                    processed, saved, logs = sync_selected_feeds(
                        selected_feeds,
                        int(max_feed_items),
                    )

                    st.success(
                        f"Sync completed. Feed entries processed: {processed}. Bulletins saved/updated: {saved}."
                    )

                    with st.expander("Logs"):
                        st.code("\n".join(logs))

                except Exception as e:
                    st.error(str(e))

    with st.expander("Configured RSS Feed URLs"):
        for feed_name, feed_url in IBM_RSS_FEEDS.items():
            st.markdown(f"**{feed_name}**")
            st.code(feed_url)

with tabs[1]:
    st.subheader("KPIs")

    bulletins, cves = load_data()
    kpis = build_kpis(bulletins, cves)

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Open", kpis["open"])
    col2.metric("Closed", kpis["closed"])
    col3.metric("Unique CVEs", kpis["unique_cves"])
    col4.metric("Bulletins", kpis["bulletins"])

    col5, col6, col7, col8 = st.columns(4)
    col5.metric("Overdue", kpis["overdue"])
    col6.metric("Danger Zone", kpis["danger_zone"])
    col7.metric("Red Zone", kpis["red_zone"])
    col8.metric("No Due Date", kpis["no_due_date"])

    if not bulletins.empty:
        by_product = (
            bulletins
            .groupby("product")["url"]
            .nunique()
            .reset_index()
            .rename(columns={"url": "bulletins"})
            .sort_values("bulletins", ascending=False)
        )

        st.subheader("Bulletins by Product")
        st.dataframe(by_product, use_container_width=True)

        if not by_product.empty:
            st.bar_chart(by_product.set_index("product")["bulletins"])

    if not cves.empty:
        enriched = enrich_cves_with_bulletins(cves, bulletins)
        zone_counts = (
            enriched
            .groupby("slo_zone")["cve_id"]
            .count()
            .reset_index()
            .rename(columns={"cve_id": "count"})
            .sort_values("count", ascending=False)
        )

        st.subheader("CVEs by SLO Zone")
        st.dataframe(zone_counts, use_container_width=True)

        if not zone_counts.empty:
            st.bar_chart(zone_counts.set_index("slo_zone")["count"])

with tabs[2]:
    st.subheader("Bulletins Database")

    bulletins, _ = load_data()

    if bulletins.empty:
        st.info("No bulletins synced yet.")
    else:
        product_filter = st.multiselect(
            "Filter by Product",
            sorted(bulletins["product"].dropna().unique().tolist()),
            default=[],
            key="bulletins_product_filter",
        )

        view = bulletins.copy()

        if product_filter:
            view = view[view["product"].isin(product_filter)]

        st.dataframe(view, use_container_width=True)

        st.download_button(
            "Export Bulletins CSV",
            data=view.to_csv(index=False).encode("utf-8"),
            file_name="shield_bulletins.csv",
            mime="text/csv",
        )

with tabs[3]:
    st.subheader("CVE Database")

    bulletins, cves = load_data()

    if cves.empty:
        st.info("No CVEs synced yet.")
    else:
        cves = enrich_cves_with_bulletins(cves, bulletins)

        product_filter = st.multiselect(
            "Filter by Product",
            sorted(cves["product"].dropna().unique().tolist()) if "product" in cves.columns else [],
            default=[],
            key="cves_product_filter",
        )

        severity_filter = st.multiselect(
            "Filter by Severity",
            sorted(cves["severity"].dropna().unique().tolist()) if "severity" in cves.columns else [],
            default=[],
        )

        zone_filter = st.multiselect(
            "Filter by SLO Zone",
            sorted(cves["slo_zone"].dropna().unique().tolist()) if "slo_zone" in cves.columns else [],
            default=[],
        )

        status_filter = st.multiselect(
            "Filter by Status",
            sorted(cves["status_norm"].dropna().unique().tolist()) if "status_norm" in cves.columns else [],
            default=[],
        )

        view = cves.copy()

        if product_filter and "product" in view.columns:
            view = view[view["product"].isin(product_filter)]

        if severity_filter and "severity" in view.columns:
            view = view[view["severity"].isin(severity_filter)]

        if zone_filter and "slo_zone" in view.columns:
            view = view[view["slo_zone"].isin(zone_filter)]

        if status_filter and "status_norm" in view.columns:
            view = view[view["status_norm"].isin(status_filter)]

        preferred_columns = [
            "id",
            "cve_id",
            "severity",
            "cvss",
            "status_norm",
            "published_date",
            "due_date",
            "grace_due_date",
            "days_to_due",
            "slo_zone",
            "product",
            "bulletin_title",
            "bulletin_url",
        ]
        available_columns = [column for column in preferred_columns if column in view.columns]
        other_columns = [column for column in view.columns if column not in available_columns]
        view = view[available_columns + other_columns]

        st.dataframe(view, use_container_width=True)

        st.download_button(
            "Export CVEs CSV",
            data=view.to_csv(index=False).encode("utf-8"),
            file_name="shield_cves.csv",
            mime="text/csv",
        )

with tabs[4]:
    st.subheader("Update CVE Status")

    bulletins, cves = load_data()

    if cves.empty:
        st.info("No CVEs available.")
    else:
        cves = enrich_cves_with_bulletins(cves, bulletins)
        open_only = st.checkbox("Show only OPEN", value=True)

        selectable = cves.copy()

        if open_only:
            selectable = selectable[selectable["status_norm"] == "OPEN"]

        if selectable.empty:
            st.info("No CVEs available for this filter.")
        else:
            selected_id = st.selectbox(
                "CVE DB ID",
                selectable["id"].tolist(),
            )

            selected_row = cves[cves["id"] == selected_id].iloc[0]
            st.dataframe(pd.DataFrame([selected_row]), use_container_width=True)

            new_status = st.selectbox(
                "New Status",
                ["OPEN", "CLOSED", "REMEDIATED", "FALSE_POSITIVE", "NOT_APPLICABLE"],
            )

            if st.button("Update Status"):
                update_cve_status(selected_id, new_status)
                st.success("Status updated.")
