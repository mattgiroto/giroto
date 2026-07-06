import requests
import csv
from datetime import datetime, timedelta

# Lógica de cálculo do Due Date (30 dias após release date, pode ajustar conforme sua regra)
def calcular_due_date(release_date_str):
    try:
        release_date = datetime.strptime(release_date_str, "%Y-%m-%d")
        due_date = release_date + timedelta(days=30)
        return due_date.strftime("%Y-%m-%d")
    except:
        return ""

# Buscar dados do CVE
def buscar_dados_cve(cve):
    url = f"https://access.redhat.com/hydra/rest/securitydata/cve/{cve}.json"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    return None

# Buscar dados do RHSA (CSAF)
def buscar_dados_rhsa(rhsa):
    url = f"https://access.redhat.com/hydra/rest/securitydata/csaf/{rhsa}.json"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    return None

# Entrada do usuário
cve_input = input("Digite a lista de CVEs separadas por vírgula: ")
cve_list = [c.strip() for c in cve_input.split(",")]

# Lista de resultados
resultados = []

for cve in cve_list:
    dados_cve = buscar_dados_cve(cve)
    if not dados_cve:
        continue

    # Procurar RHSA aplicável ao RHEL 8 ou 9
    rhsa_rhel = None
    for pkg in dados_cve.get("package_state", []):
        if pkg.get("product_name") in ["Red Hat Enterprise Linux 8", "Red Hat Enterprise Linux 9"] and pkg.get("advisory"):
            rhsa_rhel = pkg["advisory"]
            break
    if not rhsa_rhel:
        continue

    dados_rhsa = buscar_dados_rhsa(rhsa_rhel)
    if not dados_rhsa:
        continue

    release_date = dados_rhsa.get("document", {}).get("tracking", {}).get("initial_release_date", "")[:10]
    due_date = calcular_due_date(release_date)

    # Verificar se aplica a s390x e noarch
    applies_s390x = False
    applies_noarch = False
    packages = set()

    for branch in dados_rhsa.get("product_tree", {}).get("branches", []):
        for sub_branch in branch.get("branches", []):
            product_id = sub_branch.get("product", {}).get("product_id", "")
            if "s390x" in product_id:
                applies_s390x = True
            if "noarch" in product_id:
                applies_noarch = True
            packages.add(product_id)

    resultados.append({
        "RHSA": rhsa_rhel,
        "CVE": cve,
        "Release Date": release_date,
        "Due Date": due_date,
        "Applies to S390x": applies_s390x,
        "Applies to noarch": applies_noarch,
        "Packages": ", ".join(packages)
    })

# Gerar CSV
with open("relatorio_rhsa_cve.csv", "w", newline="") as csvfile:
    fieldnames = ["RHSA", "CVE", "Release Date", "Due Date", "Applies to S390x", "Applies to noarch", "Packages"]
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    for row in resultados:
        writer.writerow(row)

print("Arquivo 'relatorio_rhsa_cve.csv' gerado com sucesso.")