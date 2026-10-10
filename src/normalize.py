"""
normalize.py
Normaliza los hallazgos de las tres fuentes de escaneo (Prowler, Trivy,
Greenbone) a un unico formato comun y los escribe en un solo CSV.

Fuentes de entrada (en data/raw/):
  - Prowler:   misconfig-20261006.csv   (CSV separado por ';')
  - Trivy:     nginx-old.json, python36.json   (JSON)
  - Greenbone: report-*.csv   (CSV separado por ',')

Salida:
  - data/processed/findings_normalized.csv
"""

import csv
import json
import glob
import os

# ---------------------------------------------------------------------------
# SECCION 1: Rutas y esquema comun
# ---------------------------------------------------------------------------
# Definimos las carpetas de entrada y salida de forma relativa a la raiz del
# repo. El script se corre desde la raiz del proyecto.
RAW_DIR = os.path.join("data", "raw")
OUT_DIR = os.path.join("data", "processed")
OUT_FILE = os.path.join(OUT_DIR, "findings_normalized.csv")

# Estas son las columnas del "idioma comun". Toda fuente, sin importar su
# formato original, se traduce a estas mismas columnas. Asi podemos juntarlas
# en una sola tabla y compararlas/priorizarlas despues.
COMMON_COLUMNS = [
    "source",       # de que herramienta vino: prowler / trivy / greenbone
    "asset_id",     # id del activo afectado (del inventario lab/assets.csv)
    "asset_name",   # nombre legible del activo
    "finding_id",   # identificador del hallazgo (CVE o check id)
    "title",        # nombre corto del problema
    "severity",     # Critical / High / Medium / Low
    "cvss",         # puntaje numerico CVSS (texto, puede venir vacio)
    "cve",          # el CVE si existe
    "location",     # donde: puerto, recurso de nube o paquete
    "solution",     # como remediar
]


# ---------------------------------------------------------------------------
# SECCION 2: Funcion auxiliar para unificar la severidad
# ---------------------------------------------------------------------------
# Cada herramienta escribe la severidad distinto (mayusculas, minusculas,
# "CRITICAL" vs "Critical"). Esta funcion la deja siempre en el mismo formato
# (Capitalizada) para que el dashboard no muestre duplicados tipo
# "HIGH" y "High" como si fueran cosas distintas.
def normalize_severity(value):
    if not value:
        return "Unknown"
    value = value.strip().capitalize()
    # Trivy a veces usa "Negligible"; lo tratamos como Low.
    if value == "Negligible":
        return "Low"
    return value


# ---------------------------------------------------------------------------
# SECCION 3: Normalizar Prowler (nube / AWS)
# ---------------------------------------------------------------------------
# Prowler saca un CSV separado por ';'. Solo nos interesan las filas con
# STATUS = FAIL (los hallazgos reales; PASS son controles que pasaron bien).
def load_prowler(path):
    rows = []
    # newline="" y encoding utf-8 para leer bien el CSV en Windows.
    with open(path, encoding="utf-8", newline="") as f:
        # delimiter=';' porque Prowler usa punto y coma, no coma.
        reader = csv.DictReader(f, delimiter=";")
        for r in reader:
            # Saltamos todo lo que no sea un hallazgo fallido.
            if r.get("STATUS", "").strip().upper() != "FAIL":
                continue
            rows.append({
                "source": "prowler",
                "asset_id": "A-003",                 # la cuenta AWS del inventario
                "asset_name": "AWS Account",
                "finding_id": r.get("CHECK_ID", ""),
                "title": r.get("CHECK_TITLE", ""),
                "severity": normalize_severity(r.get("SEVERITY", "")),
                "cvss": "",                           # Prowler no da CVSS
                "cve": "",                            # Prowler no da CVE
                "location": r.get("RESOURCE_UID", "") or r.get("REGION", ""),
                "solution": r.get("REMEDIATION_RECOMMENDATION_TEXT", ""),
            })
    return rows


# ---------------------------------------------------------------------------
# SECCION 4: Normalizar Trivy (imagenes de contenedor)
# ---------------------------------------------------------------------------
# Trivy entrega JSON. La estructura es: d["Results"] es una lista; cada result
# tiene una lista "Vulnerabilities". Recorremos todas.
# Le pasamos tambien el asset_id/asset_name porque cada archivo es una imagen.
def load_trivy(path, asset_id, asset_name):
    rows = []
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    # "Results" puede no existir si la imagen no tuvo hallazgos; usamos []
    # como valor por defecto para no romper.
    for result in data.get("Results", []):
        # Lo mismo con "Vulnerabilities".
        for v in result.get("Vulnerabilities", []):
            # El CVSS en Trivy viene anidado y varia segun el proveedor.
            # Intentamos sacar el score de NVD; si no esta, queda vacio.
            cvss_score = ""
            cvss_data = v.get("CVSS", {})
            if isinstance(cvss_data, dict):
                nvd = cvss_data.get("nvd", {})
                cvss_score = nvd.get("V3Score") or nvd.get("V2Score") or ""

            rows.append({
                "source": "trivy",
                "asset_id": asset_id,
                "asset_name": asset_name,
                "finding_id": v.get("VulnerabilityID", ""),   # el CVE
                "title": v.get("Title", "") or v.get("PkgName", ""),
                "severity": normalize_severity(v.get("Severity", "")),
                "cvss": str(cvss_score),
                "cve": v.get("VulnerabilityID", ""),
                # location = paquete afectado y su version.
                "location": f'{v.get("PkgName","")} {v.get("InstalledVersion","")}'.strip(),
                "solution": (f'Update to {v.get("FixedVersion")}'
                             if v.get("FixedVersion") else "No fix available"),
            })
    return rows


# ---------------------------------------------------------------------------
# SECCION 5: Normalizar Greenbone (escaneo de red)
# ---------------------------------------------------------------------------
# Greenbone entrega CSV separado por ',' (coma normal). Tiene muchas columnas;
# solo tomamos las que mapean a nuestro esquema comun.
def load_greenbone(path):
    rows = []
    with open(path, encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)   # delimiter por defecto = ','
        for r in reader:
            rows.append({
                "source": "greenbone",
                "asset_id": "A-001",                 # Metasploitable2
                "asset_name": "Metasploitable2",
                "finding_id": r.get("NVT OID", ""),
                "title": r.get("NVT Name", ""),
                "severity": normalize_severity(r.get("Severity", "")),
                "cvss": r.get("CVSS", ""),
                "cve": r.get("CVEs", ""),            # puede traer uno o varios
                "location": f'{r.get("Port","")}/{r.get("Port Protocol","")}'.strip("/"),
                "solution": r.get("Solution", ""),
            })
    return rows


# ---------------------------------------------------------------------------
# SECCION 6: Programa principal
# ---------------------------------------------------------------------------
# Junta las tres fuentes en una sola lista y la escribe al CSV de salida.
def main():
    all_findings = []

    # --- Prowler: usamos el escaneo misconfig (baseline oficial, 71 FAIL) ---
    prowler_file = os.path.join(RAW_DIR, "prowler", "misconfig-20261006.csv")
    if os.path.exists(prowler_file):
        prowler_rows = load_prowler(prowler_file)
        all_findings += prowler_rows
        print(f"Prowler: {len(prowler_rows)} hallazgos (FAIL)")
    else:
        print("AVISO: no se encontro el CSV de Prowler, se omite.")

    # --- Trivy: procesamos las dos imagenes ---
    trivy_targets = [
        ("python36.json", "A-004", "python:3.6"),
        ("nginx-old.json", "A-005", "nginx:1.14"),
    ]
    for filename, aid, aname in trivy_targets:
        tpath = os.path.join(RAW_DIR, "trivy", filename)
        if os.path.exists(tpath):
            trivy_rows = load_trivy(tpath, aid, aname)
            all_findings += trivy_rows
            print(f"Trivy ({aname}): {len(trivy_rows)} hallazgos")
        else:
            print(f"AVISO: no se encontro {filename}, se omite.")

    # --- Greenbone: buscamos el CSV del reporte (nombre largo con guiones) ---
    # Usamos glob para encontrar cualquier report-*.csv sin escribir el nombre
    # exacto, que es muy largo.
    greenbone_files = glob.glob(os.path.join(RAW_DIR, "greenbone", "report-*.csv"))
    if greenbone_files:
        gb_rows = load_greenbone(greenbone_files[0])
        all_findings += gb_rows
        print(f"Greenbone: {len(gb_rows)} hallazgos")
    else:
        print("AVISO: no se encontro el CSV de Greenbone, se omite.")

    # --- Escribir el CSV unificado ---
    # Creamos la carpeta de salida si no existe.
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(OUT_FILE, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=COMMON_COLUMNS)
        writer.writeheader()
        writer.writerows(all_findings)

    print(f"\nTotal normalizado: {len(all_findings)} hallazgos")
    print(f"Archivo escrito en: {OUT_FILE}")


# Punto de entrada: esto corre solo si ejecutas el script directamente.
if __name__ == "__main__":
    main()