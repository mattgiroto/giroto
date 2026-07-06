import streamlit as st
import requests
import datetime
import re
import csv
from io import StringIO


APP_TITLE = "Red Hat CVE to RHSA Analyzer"
AUTHOR = "Developed by Matheus Giroto"

CVE_BATCH_URL = "https://access.redhat.com/hydra/rest/securitydata/cve.json?ids={ids}"
CSAF_BATCH_URL = "https://access.redhat.com/hydra/rest/securitydata/csaf.json?rhsa_ids={ids}"
CVE_SINGLE_URL = "https://access.redhat.com/hydra/rest/securitydata/cve/{cve}.json"


def normalize_rhsa_token(tok: str) -> str:
    tok = tok.strip().replace(" ", "")
    if not tok.upper().startswith("RHSA"):
        return ""

    m = re.match(r"(?i)RHSA[-:]?(\d{4})[-:]?(\d+)", tok)
    if not m:
        return ""

    return f"RHSA-{m.group(1)}:{m.group(2)}"


def expand_rhsa_range(start_tok: str, end_tok: str) -> list[str]:
    start_norm = normalize_rhsa_token(start_tok)
    end_norm = normalize_rhsa_token(end_tok)

    if not start_norm or not end_norm:
        return []

    m1 = re.match(r"RHSA-(\d{4}):(\d+)", start_norm)
    m2 = re.match(r"RHSA-(\d{4}):(\d+)", end_norm)

    if not m1 or not m2:
        return []

    year1, num1 = m1.group(1), int(m1.group(2))
    year2, num2 = m2.group(1), int(m2.group(2))

    if year1 != year2:
        return [start_norm, end_norm]

    if num1 > num2:
        num1, num2 = num2, num1

    return [f"RHSA-{year1}:{n}" for n in range(num1, num2 + 1)]


def dedupe(seq):
    seen = set()
    out = []

    for item in seq:
        if item not in seen:
            seen.add(item)
            out.append(item)

    return out


def parse_cve_rhsa_input(raw: str) -> tuple[list[str], list[str]]:
    cves = []
    rhsas = []

    text = raw.replace("\r", "\n").replace(";", ",")
    tokens = re.split(r"[\n,]+", text)

    for tok in tokens:
        tok = tok.strip()
        if not tok:
            continue

        if "RHSA" in tok.upper() and (".." in tok or " - " in tok):
            parts = tok.split("..") if ".." in tok else tok.split(" - ")
            if len(parts) == 2:
                rhsas.extend(expand_rhsa_range(parts[0], parts[1]))
                continue

        if tok.upper().startswith("CVE-"):
            tok = tok.upper()
            if re.match(r"CVE-\d{4}-\d+", tok):
                cves.append(tok)
            continue

        if tok.upper().startswith("RHSA"):
            norm = normalize_rhsa_token(tok)
            if norm:
                rhsas.append(norm)
            continue

        for rh in re.findall(r"RHSA[-:]?\d{4}[-:]?\d+", tok, flags=re.IGNORECASE):
            norm = normalize_rhsa_token(rh)
            if norm:
                rhsas.append(norm)

        for cv in re.findall(r"CVE-\d{4}-\d+", tok, flags=re.IGNORECASE):
            cves.append(cv.upper())

    return dedupe(cves), dedupe(rhsas)


def parse_installed_rhsa_input(raw: str) -> set[str]:
    _, rhsas = parse_cve_rhsa_input(raw)
    return set(rhsas)


def fetch_cve_single(cve_id: str) -> dict | None:
    try:
        response = requests.get(CVE_SINGLE_URL.format(cve=cve_id), timeout=15)
        if response.status_code == 200:
            return response.json()
    except Exception:
        return None

    return None


def fetch_cves_batch(cve_list, batch_size=50, log=None):
    out = {}
    total = len(cve_list)

    for i in range(0, total, batch_size):
        chunk = cve_list[i:i + batch_size]
        ids_param = ",".join(chunk)

        if log is not None:
            log.append(f"[INFO] Fetching CVE batch {i + 1}-{i + len(chunk)} of {total}")

        try:
            response = requests.get(CVE_BATCH_URL.format(ids=ids_param), timeout=20)
        except Exception:
            continue

        if response.status_code != 200:
            continue

        data = response.json()

        if isinstance(data, list):
            for item in data:
                cid = item.get("CVE") or item.get("cve")
                if cid:
                    out[cid] = item

        elif isinstance(data, dict):
            cid = data.get("CVE") or data.get("cve")
            if cid:
                out[cid] = data

    return out


def fetch_csaf_batch(rhsa_list, batch_size=40, log=None):
    out = {}
    total = len(rhsa_list)

    for i in range(0, total, batch_size):
        chunk = rhsa_list[i:i + batch_size]
        ids_param = ",".join(chunk)

        if log is not None:
            log.append(f"[INFO] Fetching RHSA batch {i + 1}-{i + len(chunk)} of {total}")

        try:
            response = requests.get(CSAF_BATCH_URL.format(ids=ids_param), timeout=20)
        except Exception:
            continue

        if response.status_code != 200:
            continue

        data = response.json()

        if isinstance(data, list):
            for item in data:
                rh = item.get("RHSA")
                if rh:
                    out[rh] = item

        elif isinstance(data, dict):
            rh = data.get("RHSA")
            if rh:
                out[rh] = data

    return out


def normalize_severity(sev: str | None) -> str:
    if not sev:
        return "unknown"

    s = sev.lower()

    if s in ("low", "info", "informational"):
        return "low"
    if s == "moderate":
        return "moderate"
    if s in ("important", "high"):
        return "important"
    if s == "critical":
        return "critical"

    return s


def calc_due_date(release_date: str | None, severity: str) -> tuple[str | None, int]:
    if not release_date:
        return None, 0

    try:
        base = datetime.date.fromisoformat(release_date)
    except Exception:
        return None, 0

    sev = normalize_severity(severity)

    if sev == "critical":
        delta_days = 14
    elif sev == "important":
        delta_days = 90
    else:
        delta_days = 180

    due = base + datetime.timedelta(days=delta_days)
    overdue_days = max((datetime.date.today() - due).days, 0)

    return due.isoformat(), overdue_days


def filter_packages_by_arch(released_packages: list[str], selected_arches: set[str]) -> bool:
    for pkg in released_packages:
        parts = pkg.split(".")
        last = parts[-1] if parts else ""

        if last in selected_arches:
            return True

    return False


def extract_rhel_rhsas_from_cve_json(cve_json):
    out = []

    affected = cve_json.get("affected_release") or []
    pkg_states = cve_json.get("package_state") or []

    for item in affected:
        product_name = item.get("product_name", "")
        advisory = item.get("advisory", "")
        release_date = item.get("release_date", "")

        if "Red Hat Enterprise Linux 8" in product_name or "Red Hat Enterprise Linux 9" in product_name:
            if advisory:
                out.append((normalize_rhsa_token(advisory), product_name, release_date))

    for item in pkg_states:
        product_name = item.get("product_name", "")
        advisory = item.get("advisory", "")
        release_date = item.get("release_date", "")

        if "Red Hat Enterprise Linux 8" in product_name or "Red Hat Enterprise Linux 9" in product_name:
            if advisory:
                out.append((normalize_rhsa_token(advisory), product_name, release_date))

    return out


def rows_to_csv(rows: list[dict]) -> bytes:
    headers = [
        "installed",
        "searched_cve",
        "related_rhsa",
        "source_product",
        "matched_arch",
        "release_date",
        "severity",
        "due_date",
        "days_overdue",
        "cve_list_from_rhsa",
    ]

    buffer = StringIO()
    writer = csv.writer(buffer)
    writer.writerow(headers)

    for row in rows:
        writer.writerow([
            row["installed"],
            row["searched_cve"],
            row["related_rhsa"],
            row["source_product"],
            row["matched_arch"],
            row["release_date"],
            row["severity"],
            row["due_date"] if row["due_date"] else "",
            row["days_overdue"],
            ";".join(row["cve_list_from_rhsa"]),
        ])

    return buffer.getvalue().encode("utf-8")


def run_analyzer(raw_input_text, installed_raw, start_date_text, end_date_text, arch_choice):
    logs = []
    progress = st.progress(0)
    status = st.empty()

    cve_list, rhsa_list_user = parse_cve_rhsa_input(raw_input_text)
    installed_set = parse_installed_rhsa_input(installed_raw)

    if arch_choice == "s390x + noarch":
        selected_arches = {"s390x", "noarch"}
    elif arch_choice == "s390x only":
        selected_arches = {"s390x"}
    else:
        selected_arches = {"noarch"}

    if not cve_list and not rhsa_list_user:
        raise ValueError("Please provide at least one CVE or RHSA.")

    logs.append(f"[INFO] Parsed CVEs: {len(cve_list)}")
    logs.append(f"[INFO] Parsed RHSAs user input: {len(rhsa_list_user)}")

    status.info("Fetching CVEs...")
    progress.progress(15)

    cve_jsons = fetch_cves_batch(cve_list, batch_size=50, log=logs) if cve_list else {}

    status.info("Running CVE fallback checks...")
    progress.progress(30)

    for cve_id in cve_list:
        data = cve_jsons.get(cve_id)
        missing = False

        if not data:
            missing = True
        else:
            affected_release = data.get("affected_release")
            package_state = data.get("package_state")
            if not affected_release and not package_state:
                missing = True

        if missing:
            logs.append(f"[INFO] Fallback single fetch for {cve_id}")
            single = fetch_cve_single(cve_id)
            if single:
                cve_jsons[cve_id] = single

    status.info("Extracting RHSAs from CVEs...")
    progress.progress(45)

    cve_to_rhsa = {}
    rhsas_from_cves = set()

    for cve_id in cve_list:
        cve_json = cve_jsons.get(cve_id)

        if not cve_json:
            continue

        rhsa_items = extract_rhel_rhsas_from_cve_json(cve_json)
        cve_to_rhsa[cve_id] = rhsa_items

        for rhsa_id, _, _ in rhsa_items:
            if rhsa_id:
                rhsas_from_cves.add(rhsa_id)

    logs.append(f"[INFO] RHSAs extracted from CVEs RHEL8/9 only: {len(rhsas_from_cves)}")

    all_rhsa_set = set(rhsa_list_user) | rhsas_from_cves
    all_rhsa_list = sorted(all_rhsa_set)

    logs.append(f"[INFO] Total unique RHSAs to fetch CSAF: {len(all_rhsa_list)}")

    status.info("Fetching CSAF RHSA data...")
    progress.progress(60)

    csaf_map = fetch_csaf_batch(all_rhsa_list, batch_size=40, log=logs) if all_rhsa_list else {}

    all_rows = []

    summary_counts = {
        "installed_yes": 0,
        "installed_no": 0,
        "installed_na": 0,
        "overdue": 0,
        "low": 0,
        "moderate": 0,
        "important": 0,
        "critical": 0,
    }

    def date_filter_ok(rel_on_iso):
        if start_date_text:
            try:
                start_date = datetime.date.fromisoformat(start_date_text)
                if rel_on_iso and datetime.date.fromisoformat(rel_on_iso) < start_date:
                    return False
            except Exception:
                pass

        if end_date_text:
            try:
                end_date = datetime.date.fromisoformat(end_date_text)
                if rel_on_iso and datetime.date.fromisoformat(rel_on_iso) > end_date:
                    return False
            except Exception:
                pass

        return True

    def add_summary(severity, overdue_days, installed_status):
        if installed_status == "Yes":
            summary_counts["installed_yes"] += 1
        elif installed_status == "No":
            summary_counts["installed_no"] += 1
        else:
            summary_counts["installed_na"] += 1

        if overdue_days > 0:
            summary_counts["overdue"] += 1

        if severity == "critical":
            summary_counts["critical"] += 1
        elif severity == "important":
            summary_counts["important"] += 1
        elif severity == "moderate":
            summary_counts["moderate"] += 1
        else:
            summary_counts["low"] += 1

    def process_rhsa_row(searched_cve, rhsa_id, source_product):
        csaf = csaf_map.get(rhsa_id)

        if not csaf:
            logs.append(f"[WARNING] No CSAF found for {rhsa_id}")
            return

        severity = normalize_severity(csaf.get("severity", ""))
        rel_on = csaf.get("released_on", "")
        rel_on_iso = rel_on.split("T")[0] if rel_on else ""

        if not date_filter_ok(rel_on_iso):
            return

        released_packages = csaf.get("released_packages", []) or []
        has_arch = filter_packages_by_arch(released_packages, selected_arches)

        due_date, overdue_days = calc_due_date(rel_on_iso, severity)

        if not has_arch:
            installed_status = "N/A"
            matched_arch = "N/A"
        else:
            installed_status = "Yes" if rhsa_id in installed_set else "No"
            matched_arch = "s390x|noarch" if selected_arches == {"s390x", "noarch"} else list(selected_arches)[0]

        add_summary(severity, overdue_days, installed_status)

        all_rows.append({
            "installed": installed_status,
            "searched_cve": searched_cve,
            "related_rhsa": rhsa_id,
            "source_product": source_product,
            "matched_arch": matched_arch,
            "release_date": rel_on_iso,
            "severity": severity,
            "due_date": due_date,
            "days_overdue": overdue_days,
            "cve_list_from_rhsa": csaf.get("CVEs", []),
        })

    status.info("Building report rows...")
    progress.progress(80)

    for cve_id in cve_list:
        for rhsa_id, product_name, _ in cve_to_rhsa.get(cve_id, []):
            if rhsa_id:
                process_rhsa_row(cve_id, rhsa_id, product_name)

    for rhsa_id in rhsa_list_user:
        norm_rhsa = normalize_rhsa_token(rhsa_id)
        if norm_rhsa:
            process_rhsa_row("", norm_rhsa, "")

    progress.progress(100)
    status.success("Analysis complete.")

    logs.append("")
    logs.append("[SUMMARY]")
    logs.append(f"Installed: {summary_counts['installed_yes']}")
    logs.append(f"Not Installed: {summary_counts['installed_no']}")
    logs.append(f"Not Applicable: {summary_counts['installed_na']}")
    logs.append(f"Overdue: {summary_counts['overdue']}")
    logs.append(f"Low: {summary_counts['low']}")
    logs.append(f"Moderate: {summary_counts['moderate']}")
    logs.append(f"Important: {summary_counts['important']}")
    logs.append(f"Critical: {summary_counts['critical']}")

    return all_rows, summary_counts, logs


st.set_page_config(page_title=APP_TITLE, layout="wide")

st.title(APP_TITLE)
st.caption(AUTHOR)
st.write("Paste CVEs and/or RHSAs. Supports comma, lines and RHSA ranges.")

with st.sidebar:
    st.header("Filters")

    arch_choice = st.radio(
        "Architecture filter",
        ["s390x + noarch", "s390x only", "noarch only"],
        index=0,
    )

    start_date_text = st.text_input("Start date", placeholder="YYYY-MM-DD")
    end_date_text = st.text_input("End date", placeholder="YYYY-MM-DD")

    st.markdown("---")
    st.caption("Support: matheus.giroto@matheusgiroto.com")

col1, col2 = st.columns(2)

with col1:
    raw_input_text = st.text_area(
        "CVE / RHSA input",
        height=260,
        placeholder="CVE-2024-1234\nRHSA-2024:5678\nRHSA-2024:1000..RHSA-2024:1010",
    )

with col2:
    installed_raw = st.text_area(
        "Installed RHSAs optional",
        height=260,
        placeholder="RHSA-2024:5678\nRHSA-2024:9999",
    )

if st.button("Fetch & Export CSV", type="primary"):
    try:
        rows, summary, logs = run_analyzer(
            raw_input_text,
            installed_raw,
            start_date_text.strip(),
            end_date_text.strip(),
            arch_choice,
        )

        col_a, col_b, col_c, col_d = st.columns(4)

        col_a.metric("Installed", summary["installed_yes"])
        col_b.metric("Not Installed", summary["installed_no"])
        col_c.metric("Not Applicable", summary["installed_na"])
        col_d.metric("Overdue", summary["overdue"])

        col_e, col_f, col_g, col_h = st.columns(4)

        col_e.metric("Low", summary["low"])
        col_f.metric("Moderate", summary["moderate"])
        col_g.metric("Important", summary["important"])
        col_h.metric("Critical", summary["critical"])

        if rows:
            st.subheader("Results")
            st.dataframe(rows, use_container_width=True)

            csv_bytes = rows_to_csv(rows)

            st.download_button(
                label="Download CSV",
                data=csv_bytes,
                file_name="rhsa_analysis.csv",
                mime="text/csv",
            )
        else:
            st.warning("No rows to export. Check filters, dates or architecture.")

        with st.expander("Log"):
            st.code("\n".join(logs))

    except Exception as e:
        st.error(str(e))
