import csv
import os

IN_FILE = os.path.join("data", "processed", "findings_enriched.csv")
OUT_FILE = os.path.join("data", "processed", "findings_scored.csv")

def asignar_prioridad(hallazgo):
    if hallazgo["in_kev"]== "yes":
        return "P1"

    severidad = hallazgo["severity"]
    if severidad == "Critical":
        return "P1"
    if severidad == "High":
        return "P2"
    if severidad == "Medium":
        return "P3"
    return "P4"

# SLA: dias maximos para remediar segun prioridad
SLA_DIAS = {
    "P1": 7,
    "P2": 30,
    "P3": 90,
    "P4": 180,
}

def main():
    # Leer el CSV enriquecido
    with open(IN_FILE, encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    print(f"Leidos {len(rows)} hallazgos")

    # A cada hallazgo le agregamos prioridad y SLA
    for r in rows:
        prioridad = asignar_prioridad(r)
        r["priority"] = prioridad
        r["sla_dias"] = SLA_DIAS[prioridad]

    # Escribir el CSV con las columnas nuevas
    fieldnames = list(rows[0].keys())
    with open(OUT_FILE, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    # Resumen: cuantos hay de cada prioridad
    for p in ["P1", "P2", "P3", "P4"]:
        cantidad = sum(1 for r in rows if r["priority"] == p)
        print(f"{p}: {cantidad} hallazgos")
    print(f"\nArchivo escrito en: {OUT_FILE}")


if __name__ == "__main__":
    main()