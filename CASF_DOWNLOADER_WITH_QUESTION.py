import requests
import csv
from datetime import datetime, timedelta

print(f"\nHello, lets get the RHSA list for you - Giroto")
print(f"\nJust remove the last CSV generated from this folder")

# Cutdate date questions
after_input = input("Inform your last patch cycle cutdate (format YYYY-MM-DD): ")
before_input = input("Now, inform the current patch cycle cutdate? (format YYYY-MM-DD): ")

BASE_URL = "https://access.redhat.com/hydra/rest/securitydata/csaf.json"
PARAMS = {
    "after": after_input,
    "before": before_input,
    "per_page": 1000
}

output_file = "redhat_csaf_expanded_cutdate.csv"

with open(output_file, "w", newline="", encoding="utf-8") as csvfile:
    fieldnames = [
        "advisory", "severity", "released_on", "due_date",
        "cve", "architectures", "applies_to_s390x",
        "contains noarch?", "released_packages_info"
    ]
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()

    for page in range(1, 21):
        print(f"Downloading RHSA from page {page}...")
        PARAMS["page"] = page
        r = requests.get(BASE_URL, params=PARAMS)
        if r.status_code != 200:
            print(f"Error {page}: {r.status_code}")
            continue

        data = r.json()
        for item in data:
            cves = []
            if "CVE_list" in item and item["CVE_list"]:
                cves = item["CVE_list"]
            elif "CVE" in item and isinstance(item["CVE"], list):
                cves = item["CVE"]
            elif "CVEs" in item and isinstance(item["CVEs"], list):
                cves = item["CVEs"]

            released_on = item.get("released_on", "")
            due_date = ""
            release_dt = None
            if released_on:
                try:
                    release_dt = datetime.fromisoformat(released_on.replace("Z", "+00:00"))
                    released_on = release_dt.strftime("%Y-%m-%d")

                    severity = item.get("severity", "").lower()
                    if severity == "critical":
                        due_date = (release_dt + timedelta(days=14)).strftime("%Y-%m-%d")
                    elif severity == "important":
                        due_date = (release_dt + timedelta(days=90)).strftime("%Y-%m-%d")
                    elif severity in ["moderate", "low"]:
                        due_date = (release_dt + timedelta(days=180)).strftime("%Y-%m-%d")
                except ValueError:
                    pass

            architectures = set()
            for pkg in item.get("released_packages", []):
                if "." in pkg:
                    arch = pkg.split(".")[-1]
                    architectures.add(arch)
            architectures_str = ", ".join(sorted(architectures))

            applies_to_s390x = "YES" if "s390x" in architectures else ""
            contains_noarch = "YES" if "noarch" in architectures else ""
            released_packages_info = ", ".join(item.get("released_packages", []))

            for cve in cves:
                writer.writerow({
                    "advisory": item.get("RHSA", ""),
                    "severity": item.get("severity", ""),
                    "released_on": released_on,
                    "due_date": due_date,
                    "cve": cve,
                    "architectures": architectures_str,
                    "applies_to_s390x": applies_to_s390x,
                    "contains noarch?": contains_noarch,
                    "released_packages_info": released_packages_info
                })

print(f"\nFile generated: {output_file}")