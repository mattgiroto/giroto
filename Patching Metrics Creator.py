
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import pandas as pd
from datetime import datetime
from tkinter import *
from tkinter import ttk, filedialog, messagebox

# -------------------------------------------------------------
# COLUMN POSITION MAP (CSV — same layout as XLSX version)
# -------------------------------------------------------------
COLUMN_MAP = {
    "ReleaseDate": 22,   # column W
    "CVSS": 30,          # column AE
    "Status": 35,        # column AJ
    "Team": 38           # column AM
}

# -------------------------------------------------------------
# DEFAULTS
# -------------------------------------------------------------
DEFAULT_SLOS = {
    "Critical": 999,
    "High": 999,
    "Medium": 999,
    "Low": None,
}

DEFAULT_CVSS_BANDS = {
    "Critical_min": 9.0,
    "High_min": 7.0,
    "Medium_min": 4.0,
}

# Regex patterns
FALSE_POSITIVE = re.compile(r"false\s*-?\s*positive", re.I)
REMEDIATED = re.compile(r"remediated?", re.I)
DEFERRED = re.compile(r"deferr?ed", re.I)


# -------------------------------------------------------------
# HELPERS
# -------------------------------------------------------------
def classify_status(s):
    if s is None or str(s).strip() == "":
        return "Open"
    s = str(s)
    if FALSE_POSITIVE.search(s) or REMEDIATED.search(s):
        return "Closed"
    if DEFERRED.search(s):
        return "Open"
    return "Open"


def cvss_to_sev(v, bands):
    try:
        v = float(v)
    except:
        return "Low"

    if v >= bands["Critical_min"]:
        return "Critical"
    if v >= bands["High_min"]:
        return "High"
    if v >= bands["Medium_min"]:
        return "Medium"
    return "Low"


def compute_due(release_date, severity, slos):
    if severity == "Low":
        return pd.NaT
    return release_date + pd.Timedelta(days=slos[severity])


def aging_bucket(days_left):
    if pd.isna(days_left):
        return "No Due Date"
    d = int(days_left)
    if d < 0:
        return "Overdue"
    if d <= 7:
        return "0–7"
    if d <= 14:
        return "8–14"
    if d <= 30:
        return "15–30"
    if d <= 60:
        return "31–60"
    if d <= 90:
        return "61–90"
    if d <= 180:
        return "91–180"
    return ">180"


def cumulative_counts(series):
    s = series.dropna().astype(int)
    return {
        "≤7": (s <= 7).sum(),
        "≤14": (s <= 14).sum(),
        "≤30": (s <= 30).sum(),
        "≤60": (s <= 60).sum(),
        "≤90": (s <= 90).sum(),
        "≤180": (s <= 180).sum(),
    }


# -------------------------------------------------------------
# GUI APPLICATION
# -------------------------------------------------------------
class App:

    def __init__(self, root):
        self.root = root
        root.title("Patching Metrics Creator (CSV Version)")

        self.file_path = StringVar()
        self.slo_critical = IntVar(value=14)
        self.slo_high = IntVar(value=60)
        self.slo_medium = IntVar(value=180)
        self.max_overdue = IntVar(value=2)
        self.denominator_all = BooleanVar(value=True)

        self.cvss_crit = StringVar(value="9.0")
        self.cvss_high = StringVar(value="7.0")
        self.cvss_med = StringVar(value="4.0")

        self.df = None
        self.results = {}

        self.build_ui()

    # -------------------------------------------------------------
    # UI
    # -------------------------------------------------------------
    def build_ui(self):
        top = ttk.Frame(self.root)
        top.pack(fill="x", padx=10, pady=5)

        ttk.Button(top, text="Select CSV", command=self.pick_csv).pack(side="left")
        ttk.Label(top, textvariable=self.file_path).pack(side="left", padx=10)

        opts = ttk.LabelFrame(self.root, text="Options")
        opts.pack(fill="x", padx=10, pady=10)

        f = ttk.Frame(opts)
        f.pack(fill="x", pady=5)
        ttk.Label(f, text="SLO Days: Critical").grid(row=0, column=0)
        ttk.Entry(f, textvariable=self.slo_critical, width=6).grid(row=0, column=1)
        ttk.Label(f, text="High").grid(row=0, column=2)
        ttk.Entry(f, textvariable=self.slo_high, width=6).grid(row=0, column=3)
        ttk.Label(f, text="Medium").grid(row=0, column=4)
        ttk.Entry(f, textvariable=self.slo_medium, width=6).grid(row=0, column=5)

        f2 = ttk.Frame(opts)
        f2.pack(fill="x", pady=5)
        ttk.Label(f2, text="CVSS Bands: Critical ≥").grid(row=0, column=0)
        ttk.Entry(f2, textvariable=self.cvss_crit, width=6).grid(row=0, column=1)
        ttk.Label(f2, text="High ≥").grid(row=0, column=2)
        ttk.Entry(f2, textvariable=self.cvss_high, width=6).grid(row=0, column=3)
        ttk.Label(f2, text="Medium ≥").grid(row=0, column=4)
        ttk.Entry(f2, textvariable=self.cvss_med, width=6).grid(row=0, column=5)

        f3 = ttk.Frame(opts)
        f3.pack(fill="x", pady=5)
        ttk.Label(f3, text="Max Overdue %:").grid(row=0, column=0)
        ttk.Entry(f3, textvariable=self.max_overdue, width=6).grid(row=0, column=1)
        ttk.Radiobutton(f3, text="Denominator: All tracked", variable=self.denominator_all, value=True).grid(row=0, column=2)
        ttk.Radiobutton(f3, text="Open only", variable=self.denominator_all, value=False).grid(row=0, column=3)

        actions = ttk.Frame(self.root)
        actions.pack(fill="x", padx=10, pady=5)
        ttk.Button(actions, text="Generate Report", command=self.generate).pack(side="left")
        ttk.Button(actions, text="Export Excel", command=self.export_excel).pack(side="left", padx=10)

        self.txt = Text(self.root, height=15)
        self.txt.pack(fill="both", expand=True, padx=10, pady=10)
        self.txt.config(state=DISABLED)

        frame_team = ttk.LabelFrame(self.root, text="By Team")
        frame_team.pack(fill="both", expand=True, padx=10, pady=10)

        cols = ("Team", "Open", "Closed", "Overdue", "Overdue %",
                "≤7", "≤14", "≤30", "≤60", "≤90", "≤180")

        self.tree = ttk.Treeview(frame_team, columns=cols, show="headings", height=12)
        for c in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=90, anchor="center")
        self.tree.column("Team", width=250, anchor="w")
        self.tree.pack(fill="both", expand=True)

    # -------------------------------------------------------------
    # FILE PICKER
    # -------------------------------------------------------------
    def pick_csv(self):
        p = filedialog.askopenfilename(
            title="Select CSV",
            filetypes=[("CSV", "*.csv")]
        )
        if p:
            self.file_path.set(p)

    def log(self, msg):
        self.txt.config(state=NORMAL)
        self.txt.insert(END, msg + "\n")
        self.txt.config(state=DISABLED)

    # -------------------------------------------------------------
    # LOAD CSV
    # -------------------------------------------------------------
    def load_csv(self, path):
        try:
            df = pd.read_csv(
                path,
                header=None,
                low_memory=False,
                dtype=str
            )
        except Exception as e:
            messagebox.showerror("Error", str(e))
            return None

        df = df.rename(columns={
            COLUMN_MAP["ReleaseDate"]: "ReleaseDate",
            COLUMN_MAP["CVSS"]: "CVSS",
            COLUMN_MAP["Status"]: "Status",
            COLUMN_MAP["Team"]: "Team"
        })

        return df

    # -------------------------------------------------------------
    # COMPUTE METRICS
    # -------------------------------------------------------------
    def compute(self, df):
        bands = {
            "Critical_min": float(self.cvss_crit.get()),
            "High_min": float(self.cvss_high.get()),
            "Medium_min": float(self.cvss_med.get())
        }

        slos = {
            "Critical": self.slo_critical.get(),
            "High": self.slo_high.get(),
            "Medium": self.slo_medium.get(),
            "Low": None
        }

        df = df.copy()

        # ---------- FIXED ISO DATE PARSING ----------
        df["ReleaseDate"] = df["ReleaseDate"].str.replace("Z", "", regex=False)
        df["ReleaseDate"] = df["ReleaseDate"].str.replace("T", " ", regex=False)

        df["ReleaseDate"] = pd.to_datetime(
            df["ReleaseDate"],
            format="%Y-%m-%d %H:%M:%S.%f",
            errors="coerce"
        )

        df["ReleaseDate"] = df["ReleaseDate"].dt.date
        df["ReleaseDate"] = pd.to_datetime(df["ReleaseDate"], errors="coerce")
        # ---------------------------------------------

        today = pd.Timestamp(datetime.now().date())

        df["CVSS"] = pd.to_numeric(df["CVSS"], errors="coerce")
        df["StatusRaw"] = df["Status"].astype(str)
        df["State"] = df["StatusRaw"].apply(classify_status)
        df["Severity"] = df["CVSS"].apply(lambda v: cvss_to_sev(v, bands))
        df["Team"] = df["Team"].astype(str)

        df["DueDate"] = df.apply(
            lambda r: compute_due(r["ReleaseDate"], r["Severity"], slos),
            axis=1,
        )

        df["DaysLeft"] = (df["DueDate"] - today).dt.days

        tracked = df["Severity"].isin(["Critical", "High", "Medium"])
        open_mask = df["State"] == "Open"
        closed_mask = df["State"] == "Closed"

        overdue_mask = tracked & open_mask & df["DaysLeft"].notna() & (df["DaysLeft"] < 0)

        total = tracked.sum()
        open_cnt = (tracked & open_mask).sum()
        closed_cnt = (tracked & closed_mask).sum()
        overdue_cnt = overdue_mask.sum()

        denominator = total if self.denominator_all.get() else open_cnt
        overdue_pct = round(overdue_cnt / denominator * 100, 2) if denominator > 0 else 0

        due_candidates = df[
            tracked & open_mask & df["DaysLeft"].notna() & (df["DaysLeft"] >= 0)
        ]
        cum = cumulative_counts(due_candidates["DaysLeft"])

        df["Aging"] = df["DaysLeft"].apply(aging_bucket)

        rows = []
        for team, g in df[tracked].groupby("Team"):
            g_open = (g["State"] == "Open").sum()
            g_closed = (g["State"] == "Closed").sum()
            g_over = ((g["State"] == "Open") & (g["DaysLeft"] < 0)).sum()

            denom = len(g) if self.denominator_all.get() else g_open
            denom = denom or 1

            pct = round(g_over / denom * 100, 2)

            g_due = g[(g["State"] == "Open") & (g["DaysLeft"] >= 0)]
            g_cum = cumulative_counts(g_due["DaysLeft"])

            rows.append({
                "Team": team,
                "Open": g_open,
                "Closed": g_closed,
                "Overdue": g_over,
                "Overdue %": pct,
                "≤7": g_cum["≤7"],
                "≤14": g_cum["≤14"],
                "≤30": g_cum["≤30"],
                "≤60": g_cum["≤60"],
                "≤90": g_cum["≤90"],
                "≤180": g_cum["≤180"],
            })

        byteam_df = pd.DataFrame(rows).sort_values("Overdue", ascending=False)

        return {
            "df": df,
            "today": today.date(),
            "total": total,
            "open": open_cnt,
            "closed": closed_cnt,
            "overdue": overdue_cnt,
            "overdue_pct": overdue_pct,
            "cum": cum,
            "byteam": byteam_df,
        }

    # -------------------------------------------------------------
    # GENERATE REPORT
    # -------------------------------------------------------------
    def generate(self):
        self.txt.config(state=NORMAL)
        self.txt.delete("1.0", END)
        self.txt.config(state=DISABLED)

        for i in self.tree.get_children():
            self.tree.delete(i)

        path = self.file_path.get()
        if not path:
            messagebox.showerror("Error", "Select a CSV file first.")
            return

        df = self.load_csv(path)
        if df is None:
            return

        self.results = self.compute(df)
        r = self.results

        self.log(f"Report date: {r['today']}")
        self.log(f"Total tracked: {r['total']}")
        self.log(f"Closed: {r['closed']}")
        self.log(f"Open: {r['open']}")
        self.log(f"Overdue: {r['overdue']}")
        self.log(f"Overdue %: {r['overdue_pct']}%")

        if r["overdue_pct"] > self.max_overdue.get():
            self.log("⚠️ Over the 2% threshold")
        else:
            self.log("✅ Within threshold")

        self.log("\nOpen due in (cumulative):")
        for k, v in r["cum"].items():
            self.log(f"{k}: {v}")

        for _, row in r["byteam"].iterrows():
            self.tree.insert("", END, values=row.to_list())

    # -------------------------------------------------------------
    # EXPORT EXCEL
    # -------------------------------------------------------------
    def export_excel(self):
        if not self.results:
            messagebox.showerror("Error", "Run the report first.")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".xlsx",
            initialfile="SLO_Report.xlsx",
            filetypes=[("Excel Files", "*.xlsx")]
        )

        if not path:
            return

        r = self.results
        df = r["df"]

        summary = pd.DataFrame([
            ["Report Date", r["today"]],
            ["Total tracked", r["total"]],
            ["Open", r["open"]],
            ["Closed", r["closed"]],
            ["Overdue", r["overdue"]],
            ["Overdue %", r["overdue_pct"]],
            ["≤7", r["cum"]["≤7"]],
            ["≤14", r["cum"]["≤14"]],
            ["≤30", r["cum"]["≤30"]],
            ["≤60", r["cum"]["≤60"]],
            ["≤90", r["cum"]["≤90"]],
            ["≤180", r["cum"]["≤180"]],
        ], columns=["Metric", "Value"])

        aging = df[
            df["Severity"].isin(["Critical", "High", "Medium"]) &
            (df["State"] == "Open")
        ].groupby("Aging").size().reset_index(name="Count")

        try:
            with pd.ExcelWriter(path, engine="openpyxl") as w:
                summary.to_excel(w, index=False, sheet_name="Summary")
                r["byteam"].to_excel(w, index=False, sheet_name="ByTeam")
                aging.to_excel(w, index=False, sheet_name="Aging")
                df.to_excel(w, index=False, sheet_name="RawData")

            messagebox.showinfo("Success", "Excel report exported successfully!")

        except Exception as e:
            messagebox.showerror("Error", str(e))

# -------------------------------------------------------------
# MAIN
# -------------------------------------------------------------
def main():
    root = Tk()
    App(root)
    root.geometry("1300x900")
    root.mainloop()


if __name__ == "__main__":
    main()
