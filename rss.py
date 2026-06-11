import feedparser
import requests
import re
import json
import os
import time
import pandas as pd
from datetime import datetime

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

RSS_AVIS   = "https://www.cert.ssi.gouv.fr/avis/feed/"
RSS_ALERTE = "https://www.cert.ssi.gouv.fr/alerte/feed/"

API_MITRE  = "https://cveawg.mitre.org/api/cve/{cve_id}"
API_EPSS   = "https://api.first.org/data/v1/epss?cve={cve_id}"

DELAY_BETWEEN_REQUESTS = 2   # secondes (rate limiting responsable)
OUTPUT_CSV = "anssi_cve_enrichi.csv"

# Dossiers de données locales pré-téléchargées (si disponibles)
LOCAL_AVIS_DIR   = "avis/"
LOCAL_ALERTE_DIR = "alertes/"
LOCAL_MITRE_DIR  = "mitre/"
LOCAL_FIRST_DIR  = "first/"

CVSS_SEVERITY = {
    (0.0, 3.9):  "Low",
    (4.0, 6.9):  "Medium",
    (7.0, 8.9):  "High",
    (9.0, 10.0): "Critical",
}


# ─────────────────────────────────────────────────────────────────────────────
# UTILITAIRES
# ─────────────────────────────────────────────────────────────────────────────

def get_severity(score):
    """Retourne la sévérité textuelle à partir d'un score CVSS."""
    if score is None:
        return "N/A"
    for (low, high), label in CVSS_SEVERITY.items():
        if low <= float(score) <= high:
            return label
    return "N/A"


def safe_get(url, retries=3, delay=DELAY_BETWEEN_REQUESTS):
    """Requête GET avec gestion d'erreurs et retry."""
    for attempt in range(retries):
        try:
            response = requests.get(url, timeout=15)
            response.raise_for_status()
            time.sleep(delay)
            return response
        except requests.RequestException as e:
            print(f"  [!] Tentative {attempt+1}/{retries} échouée pour {url} : {e}")
            time.sleep(delay * 2)
    return None


def load_local_json(filepath):
    """Charge un fichier JSON local si disponible."""
    if os.path.exists(filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    return None


# ─────────────────────────────────────────────────────────────────────────────
# ÉTAPE 1 : EXTRACTION DES FLUX RSS
# ─────────────────────────────────────────────────────────────────────────────

def extraire_flux_rss(url, type_bulletin):
    """
    Parse le flux RSS ANSSI et retourne une liste de bulletins.

    Paramètres
    ----------
    url : str
        URL du flux RSS (avis ou alertes).
    type_bulletin : str
        "Avis" ou "Alerte".

    Retourne
    --------
    list[dict] avec les clés : id, titre, type, date, lien
    """
    print(f"\n[*] Extraction flux RSS {type_bulletin} : {url}")
    feed = feedparser.parse(url)

    if feed.bozo:
        print(f"  [!] Avertissement feedparser : {feed.bozo_exception}")

    bulletins = []
    for entry in feed.entries:
        # L'ID ANSSI se trouve dans le lien  ex: .../CERTFR-2024-ALE-001/
        lien = entry.get("link", "")
        anssi_id = lien.rstrip("/").split("/")[-1]

        # Date : on tente published_parsed, sinon chaîne brute
        date_pub = None
        if hasattr(entry, "published_parsed") and entry.published_parsed:
            date_pub = datetime(*entry.published_parsed[:6]).strftime("%Y-%m-%d")
        elif hasattr(entry, "published"):
            date_pub = entry.published

        bulletin = {
            "id_anssi":  anssi_id,
            "titre":     entry.get("title", ""),
            "type":      type_bulletin,
            "date":      date_pub,
            "lien":      lien,
        }
        bulletins.append(bulletin)
        print(f"  -> {anssi_id} | {date_pub} | {bulletin['titre'][:60]}")

    print(f"  [+] {len(bulletins)} bulletins extraits.")
    return bulletins


def extraire_tous_bulletins():
    """Fusionne avis + alertes en une seule liste."""
    avis    = extraire_flux_rss(RSS_AVIS,   "Avis")
    alertes = extraire_flux_rss(RSS_ALERTE, "Alerte")
    return avis + alertes


# ─────────────────────────────────────────────────────────────────────────────
# ÉTAPE 2 : EXTRACTION DES CVE PAR BULLETIN
# ─────────────────────────────────────────────────────────────────────────────

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}")


def extraire_cve_bulletin(bulletin):
    """
    Récupère le JSON ANSSI d'un bulletin et en extrait la liste de CVE.

    Cherche d'abord en local (dossiers avis/ ou alertes/), puis en ligne.

    Retourne
    --------
    list[str] : identifiants CVE uniques trouvés
    """
    anssi_id     = bulletin["id_anssi"]
    type_bulletin = bulletin["type"]
    data         = None

    # Tentative locale
    sous_dossier = LOCAL_ALERTE_DIR if type_bulletin == "Alerte" else LOCAL_AVIS_DIR
    local_path   = os.path.join(sous_dossier, anssi_id)
    data         = load_local_json(local_path)

    if data is None:
        # Tentative en ligne : l'URL JSON = lien + "json/"
        json_url = bulletin["lien"].rstrip("/") + "/json/"
        print(f"  [→] Chargement en ligne : {json_url}")
        resp = safe_get(json_url)
        if resp is None:
            print(f"  [!] Impossible de récupérer {anssi_id}")
            return []
        try:
            data = resp.json()
        except json.JSONDecodeError:
            print(f"  [!] Réponse JSON invalide pour {anssi_id}")
            return []

    # Extraction depuis la clé "cves" (liste de dicts {name, url})
    cves_from_key = []
    if isinstance(data.get("cves"), list):
        for item in data["cves"]:
            if isinstance(item, dict) and "name" in item:
                cves_from_key.append(item["name"])
            elif isinstance(item, str):
                cves_from_key.append(item)

    # Extraction regex de secours sur tout le contenu
    cves_regex = CVE_PATTERN.findall(json.dumps(data))

    # Union, dédoublonnée, triée
    toutes_cves = sorted(set(cves_from_key) | set(cves_regex))
    print(f"    [{anssi_id}] {len(toutes_cves)} CVE trouvés : {toutes_cves[:5]}{'…' if len(toutes_cves) > 5 else ''}")
    return toutes_cves


# ─────────────────────────────────────────────────────────────────────────────
# ÉTAPE 3 : ENRICHISSEMENT DES CVE
# ─────────────────────────────────────────────────────────────────────────────

def get_cvss_score(metrics):
    """
    Parcourt la liste 'metrics' et retourne le premier baseScore CVSS trouvé.
    Gère cvssV3_1, cvssV3_0, cvssV2_0.
    """
    for metric in metrics:
        for version_key in ("cvssV3_1", "cvssV3_0", "cvssV2_0"):
            if version_key in metric:
                return metric[version_key].get("baseScore")
    return None


def enrichir_depuis_mitre(cve_id):
    """
    Interroge l'API MITRE CVE (ou le cache local) pour un identifiant CVE.
    Retourne
    --------
    dict avec : description, cvss_score, base_severity, cwe, cwe_desc,
                vendor, product, versions_affectees
    """
    result = {
        "description":        "N/A",
        "cvss_score":         None,
        "base_severity":      "N/A",
        "cwe":                "N/A",
        "cwe_desc":           "N/A",
        "vendor":             "N/A",
        "product":            "N/A",
        "versions_affectees": "N/A",
    }

    # Cache local
    local_path = os.path.join(LOCAL_MITRE_DIR, cve_id)
    data = load_local_json(local_path)

    if data is None:
        url  = API_MITRE.format(cve_id=cve_id)
        resp = safe_get(url)
        if resp is None:
            return result
        try:
            data = resp.json()
        except json.JSONDecodeError:
            return result

    try:
        cna = data["containers"]["cna"]

        # Description
        descs = cna.get("descriptions", [])
        if descs:
            result["description"] = descs[0].get("value", "N/A")

        # Score CVSS
        metrics = cna.get("metrics", [])
        score   = get_cvss_score(metrics)
        result["cvss_score"]    = score
        result["base_severity"] = get_severity(score)

        # CWE
        problem_types = cna.get("problemTypes", [])
        if problem_types:
            cwe_descs = problem_types[0].get("descriptions", [])
            if cwe_descs:
                result["cwe"]      = cwe_descs[0].get("cweId",       "N/A")
                result["cwe_desc"] = cwe_descs[0].get("description", "N/A")

        # Produits affectés
        affected = cna.get("affected", [])
        if affected:
            vendors   = []
            products  = []
            versions  = []
            for prod in affected:
                vendors.append(prod.get("vendor",  "N/A"))
                products.append(prod.get("product", "N/A"))
                vers_affected = [
                    v["version"]
                    for v in prod.get("versions", [])
                    if v.get("status") == "affected"
                ]
                versions.extend(vers_affected)

            result["vendor"]             = " | ".join(set(vendors))
            result["product"]            = " | ".join(set(products))
            result["versions_affectees"] = ", ".join(versions) if versions else "N/A"

    except (KeyError, IndexError, TypeError) as e:
        print(f"    [!] Parsing MITRE {cve_id} : {e}")

    return result


def enrichir_depuis_epss(cve_id):
    """
    Interroge l'API EPSS (FIRST) ou le cache local.

    Retourne
    --------
    float | None : score EPSS (0–1)
    """
    local_path = os.path.join(LOCAL_FIRST_DIR, cve_id)
    data = load_local_json(local_path)

    if data is None:
        url  = API_EPSS.format(cve_id=cve_id)
        resp = safe_get(url)
        if resp is None:
            return None
        try:
            data = resp.json()
        except json.JSONDecodeError:
            return None

    epss_data = data.get("data", [])
    if epss_data:
        try:
            return float(epss_data[0]["epss"])
        except (KeyError, ValueError, TypeError):
            pass
    return None


def enrichir_cve(cve_id):
    """
    Agrège les informations MITRE + EPSS pour un CVE.

    Retourne
    --------
    dict complet prêt à être inséré dans le DataFrame.
    """
    print(f"    [~] Enrichissement {cve_id} …")
    mitre = enrichir_depuis_mitre(cve_id)
    epss  = enrichir_depuis_epss(cve_id)
    mitre["epss_score"] = epss
    return mitre


# ─────────────────────────────────────────────────────────────────────────────
# CONSOLIDATION (ÉTAPE 4 – structure de base)
# ─────────────────────────────────────────────────────────────────────────────

def construire_dataframe(bulletins):
    """
    Parcourt tous les bulletins, extrait les CVE et les enrichit,
    puis retourne un DataFrame pandas une-ligne-par-CVE.
    """
    rows = []

    for bulletin in bulletins:
        print(f"\n[*] Traitement bulletin : {bulletin['id_anssi']} ({bulletin['type']})")
        cves = extraire_cve_bulletin(bulletin)

        if not cves:
            # Bulletin sans CVE : on conserve quand même une ligne vide
            rows.append({
                "id_anssi":           bulletin["id_anssi"],
                "titre":              bulletin["titre"],
                "type":               bulletin["type"],
                "date":               bulletin["date"],
                "lien":               bulletin["lien"],
                "cve_id":             None,
                "cvss_score":         None,
                "base_severity":      "N/A",
                "cwe":                "N/A",
                "cwe_desc":           "N/A",
                "epss_score":         None,
                "description":        "N/A",
                "vendor":             "N/A",
                "product":            "N/A",
                "versions_affectees": "N/A",
            })
            continue

        for cve_id in cves:
            info = enrichir_cve(cve_id)
            rows.append({
                "id_anssi":           bulletin["id_anssi"],
                "titre":              bulletin["titre"],
                "type":               bulletin["type"],
                "date":               bulletin["date"],
                "lien":               bulletin["lien"],
                "cve_id":             cve_id,
                "cvss_score":         info["cvss_score"],
                "base_severity":      info["base_severity"],
                "cwe":                info["cwe"],
                "cwe_desc":           info["cwe_desc"],
                "epss_score":         info["epss_score"],
                "description":        info["description"],
                "vendor":             info["vendor"],
                "product":            info["product"],
                "versions_affectees": info["versions_affectees"],
            })

    df = pd.DataFrame(rows)

    # Typage
    df["cvss_score"]  = pd.to_numeric(df["cvss_score"],  errors="coerce")
    df["epss_score"]  = pd.to_numeric(df["epss_score"],  errors="coerce")
    df["date"]        = pd.to_datetime(df["date"],        errors="coerce")

    return df


# ─────────────────────────────────────────────────────────────────────────────
# POINT D'ENTRÉE
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("  ANSSI CVE Pipeline – Étapes 1, 2 & 3")
    print("=" * 60)

    # ── Étape 1 : flux RSS ───────────────────────────────────────
    bulletins = extraire_tous_bulletins()
    print(f"\n[+] Total bulletins extraits : {len(bulletins)}")

    # ── Étapes 2 & 3 + consolidation préliminaire ────────────────
    df = construire_dataframe(bulletins)

    # ── Aperçu ───────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("  Aperçu du DataFrame consolidé")
    print("=" * 60)
    print(df.head(10).to_string(index=False))
    print(f"\nDimensions : {df.shape[0]} lignes × {df.shape[1]} colonnes")
    print("\nStatistiques CVSS :")
    print(df["cvss_score"].describe())
    print("\nRépartition par sévérité :")
    print(df["base_severity"].value_counts())
    print("\nRépartition par type de bulletin :")
    print(df["type"].value_counts())

    # ── Export CSV ───────────────────────────────────────────────
    df.to_csv(OUTPUT_CSV, index=False, encoding="utf-8-sig")
    print(f"\n[+] DataFrame exporté → {OUTPUT_CSV}")

    return df


if __name__ == "__main__":
    df = main()