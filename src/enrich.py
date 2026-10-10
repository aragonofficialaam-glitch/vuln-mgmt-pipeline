"""
enrich.py
Enriquece los hallazgos normalizados con contexto de explotabilidad real:
  - KEV  (CISA Known Exploited Vulnerabilities): ¿se explota activamente?
  - EPSS (Exploit Prediction Scoring System): probabilidad de explotación.

Entrada:  data/processed/findings_normalized.csv
Salida:   data/processed/findings_enriched.csv
"""

import csv
import os
import re
import requests

IN_FILE = os.path.join("data", "processed", "findings_normalized.csv")
OUT_FILE = os.path.join("data", "processed", "findings_enriched.csv")

# URLs oficiales de las fuentes
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"


# ---------------------------------------------------------------------------
# SECCION 1: Extraer CVEs del campo 'cve'
# ---------------------------------------------------------------------------
# El campo 'cve' puede traer vacio, un CVE, o varios separados. Usamos una
# expresion regular para encontrar todos los que tengan formato CVE-AAAA-NNNN.
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

def extract_cves(text):
    if not text:
        return []
    return [c.upper() for c in CVE_PATTERN.findall(text)]


# ---------------------------------------------------------------------------
# SECCION 2: Descargar la lista KEV completa
# ---------------------------------------------------------------------------
# KEV es una sola lista que bajamos entera. La guardamos como un conjunto
# (set) de CVEs para consultar rapidisimo si un CVE esta o no en ella.
def load_kev():
    print("Descargando lista KEV de CISA...")
    resp = requests.get(KEV_URL, timeout=60)
    resp.raise_for_status()
    data = resp.json()
    kev_set = {item["cveID"].upper() for item in data.get("vulnerabilities", [])}
    print(f"KEV: {len(kev_set)} CVEs conocidos como explotados")
    return kev_set


# ---------------------------------------------------------------------------
# SECCION 3: Consultar EPSS por lotes
# ---------------------------------------------------------------------------
# La API de EPSS acepta muchos CVEs a la vez (separados por coma). Los pedimos
# en lotes para no hacer miles de peticiones. Devuelve un diccionario
# {CVE: score}.
def load_epss(cve_list):
    print(f"Consultando EPSS para {len(cve_list)} CVEs unicos...")
    epss_scores = {}
    batch_size = 100
    for i in range(0, len(cve_list), batch_size):
        batch = cve_list[i:i + batch_size]
        params = {"cve": ",".join(batch)}
        resp = requests.get(EPSS_URL, params=params, timeout=60)
        if resp.status_code != 200:
            continue
        for item in resp.json().get("data", []):
            epss_scores[item["cve"].upper()] = item.get("epss", "")
    print(f"EPSS: {len(epss_scores)} CVEs con score")
    return epss_scores


# ---------------------------------------------------------------------------
# SECCION 4: Programa principal
# ---------------------------------------------------------------------------
def main():
    # Leer el CSV normalizado
    with open(IN_FILE, encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    print(f"Leidos {len(rows)} hallazgos normalizados")

    # Juntar todos los CVEs unicos de toda la tabla
    all_cves = set()
    for r in rows:
        for cve in extract_cves(r.get("cve", "")):
            all_cves.add(cve)
    all_cves = sorted(all_cves)
    print(f"CVEs unicos encontrados: {len(all_cves)}")

    # Descargar las dos fuentes de enriquecimiento
    kev_set = load_kev()
    epss_scores = load_epss(all_cves) if all_cves else {}

    # Agregar las columnas nuevas a cada fila
    for r in rows:
        cves = extract_cves(r.get("cve", ""))
        # in_kev = "yes" si alguno de los CVEs de la fila esta en KEV
        r["in_kev"] = "yes" if any(c in kev_set for c in cves) else "no"
        # epss = el score mas alto entre los CVEs de la fila
        scores = [float(epss_scores[c]) for c in cves if c in epss_scores]
        r["epss"] = str(max(scores)) if scores else ""

    # Escribir el CSV enriquecido (columnas originales + las 2 nuevas)
    fieldnames = list(rows[0].keys())
    with open(OUT_FILE, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    # Resumen
    kev_count = sum(1 for r in rows if r["in_kev"] == "yes")
    print(f"\nHallazgos en KEV (explotados activamente): {kev_count}")
    print(f"Archivo escrito en: {OUT_FILE}")


if __name__ == "__main__":
    main()