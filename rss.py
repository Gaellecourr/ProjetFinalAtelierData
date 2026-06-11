import feedparser
import requests
import re
import json
import os
import time
import threading
import pandas as pd
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

#coucou
# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

RSS_AVIS   = "https://www.cert.ssi.gouv.fr/avis/feed/"
RSS_ALERTE = "https://www.cert.ssi.gouv.fr/alerte/feed/"

API_MITRE      = "https://cveawg.mitre.org/api/cve/{cve_id}"
API_EPSS_BATCH = "https://api.first.org/data/v1/epss?cve={cves}"   # jusqu'à ~100 CVE/requête

OUTPUT_CSV = "anssi_cve_enrichi.csv"

# Dossiers de données locales pré-téléchargées (si disponibles)
LOCAL_AVIS_DIR   = "avis/"
LOCAL_ALERTE_DIR = "alertes/"
LOCAL_MITRE_DIR  = "mitre/"
LOCAL_FIRST_DIR  = "first/"

# ── Paramètres de parallélisme ────────────────────────────────────────────────
MAX_WORKERS_BULLETINS = 10   # requêtes JSON bulletins ANSSI en parallèle
MAX_WORKERS_MITRE     = 15   # requêtes MITRE en parallèle
EPSS_BATCH_SIZE       = 100  # CVE par requête EPSS (limite API FIRST)
REQUEST_TIMEOUT       = 15   # secondes par requête

# Session HTTP partagée (keep-alive, connection pooling)
_session_lock = threading.Lock()
_session = requests.Session()
_session.headers.update({"User-Agent": "ANSSI-CVE-Pipeline/1.0"})

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


def safe_get(url, retries=3):
    """
    Requête GET thread-safe avec retry exponentiel.
    Utilise la session persistante partagée (connection pooling).
    Pas de sleep fixe : le backoff est uniquement sur erreur.
    """
    for attempt in range(retries):
        try:
            with _session_lock:
                response = _session.get(url, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            return response
        except requests.RequestException as e:
            wait = 2 ** attempt          # 1s, 2s, 4s
            print(f"  [!] Tentative {attempt+1}/{retries} échouée ({url[:60]}…) : {e} – attente {wait}s")
            time.sleep(wait)
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
    Les deux flux (avis + alertes) sont parsés en parallèle depuis main().
    """
    print(f"\n[*] Extraction flux RSS {type_bulletin} : {url}")
    feed = feedparser.parse(url)

    if feed.bozo:
        print(f"  [!] Avertissement feedparser : {feed.bozo_exception}")

    bulletins = []
    for entry in feed.entries:
        lien     = entry.get("link", "")
        anssi_id = lien.rstrip("/").split("/")[-1]

        date_pub = None
        if hasattr(entry, "published_parsed") and entry.published_parsed:
            date_pub = datetime(*entry.published_parsed[:6]).strftime("%Y-%m-%d")
        elif hasattr(entry, "published"):
            date_pub = entry.published

        bulletins.append({
            "id_anssi": anssi_id,
            "titre":    entry.get("title", ""),
            "type":     type_bulletin,
            "date":     date_pub,
            "lien":     lien,
        })

    print(f"  [+] {len(bulletins)} bulletins {type_bulletin} extraits.")
    return bulletins


def extraire_tous_bulletins():
    """
    Fusionne avis + alertes.
    Les deux flux RSS sont récupérés en parallèle via ThreadPoolExecutor.
    """
    with ThreadPoolExecutor(max_workers=2) as ex:
        fut_avis    = ex.submit(extraire_flux_rss, RSS_AVIS,   "Avis")
        fut_alertes = ex.submit(extraire_flux_rss, RSS_ALERTE, "Alerte")
        avis    = fut_avis.result()
        alertes = fut_alertes.result()
    return avis + alertes


# ─────────────────────────────────────────────────────────────────────────────
# ÉTAPE 2 : EXTRACTION DES CVE PAR BULLETIN  (parallélisée)
# ─────────────────────────────────────────────────────────────────────────────

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}")


def extraire_cve_bulletin(bulletin):
    """
    Récupère le JSON ANSSI d'un bulletin et en extrait la liste de CVE.
    Appelée en parallèle depuis extraire_cve_tous_bulletins().
    """
    anssi_id      = bulletin["id_anssi"]
    type_bulletin = bulletin["type"]

    sous_dossier = LOCAL_ALERTE_DIR if type_bulletin == "Alerte" else LOCAL_AVIS_DIR
    data = load_local_json(os.path.join(sous_dossier, anssi_id))

    if data is None:
        json_url = bulletin["lien"].rstrip("/") + "/json/"
        resp = safe_get(json_url)
        if resp is None:
            print(f"  [!] Impossible de récupérer {anssi_id}")
            return anssi_id, []
        try:
            data = resp.json()
        except json.JSONDecodeError:
            print(f"  [!] JSON invalide pour {anssi_id}")
            return anssi_id, []

    cves_from_key = []
    if isinstance(data.get("cves"), list):
        for item in data["cves"]:
            if isinstance(item, dict) and "name" in item:
                cves_from_key.append(item["name"])
            elif isinstance(item, str):
                cves_from_key.append(item)

    cves_regex  = CVE_PATTERN.findall(json.dumps(data))
    toutes_cves = sorted(set(cves_from_key) | set(cves_regex))
    print(f"  [{anssi_id}] {len(toutes_cves)} CVE")
    return anssi_id, toutes_cves


def extraire_cve_tous_bulletins(bulletins):
    """
    Lance l'extraction CVE de tous les bulletins en parallèle.
    Retourne un dict {id_anssi: [cve_id, …]}.
    """
    print(f"\n[*] Extraction CVE ({len(bulletins)} bulletins, {MAX_WORKERS_BULLETINS} workers)…")
    resultats = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS_BULLETINS) as ex:
        futures = {ex.submit(extraire_cve_bulletin, b): b for b in bulletins}
        for fut in as_completed(futures):
            anssi_id, cves = fut.result()
            resultats[anssi_id] = cves
    return resultats


# ─────────────────────────────────────────────────────────────────────────────
# ÉTAPE 3 : ENRICHISSEMENT DES CVE  (parallélisé + EPSS batch)
# ─────────────────────────────────────────────────────────────────────────────

def get_cvss_score(metrics):
    for metric in metrics:
        for key in ("cvssV3_1", "cvssV3_0", "cvssV2_0"):
            if key in metric:
                return metric[key].get("baseScore")
    return None


def enrichir_depuis_mitre(cve_id):
    """Récupère CVSS, CWE, description, vendor/produit depuis MITRE."""
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

    data = load_local_json(os.path.join(LOCAL_MITRE_DIR, cve_id))
    if data is None:
        resp = safe_get(API_MITRE.format(cve_id=cve_id))
        if resp is None:
            return result
        try:
            data = resp.json()
        except json.JSONDecodeError:
            return result

    try:
        cna = data["containers"]["cna"]

        descs = cna.get("descriptions", [])
        if descs:
            result["description"] = descs[0].get("value", "N/A")

        score = get_cvss_score(cna.get("metrics", []))
        result["cvss_score"]    = score
        result["base_severity"] = get_severity(score)

        pts = cna.get("problemTypes", [])
        if pts:
            cd = pts[0].get("descriptions", [])
            if cd:
                result["cwe"]      = cd[0].get("cweId",       "N/A")
                result["cwe_desc"] = cd[0].get("description", "N/A")

        affected = cna.get("affected", [])
        if affected:
            vendors, products, versions = [], [], []
            for prod in affected:
                vendors.append(prod.get("vendor",  "N/A"))
                products.append(prod.get("product", "N/A"))
                versions.extend(
                    v["version"] for v in prod.get("versions", [])
                    if v.get("status") == "affected"
                )
            result["vendor"]             = " | ".join(set(vendors))
            result["product"]            = " | ".join(set(products))
            result["versions_affectees"] = ", ".join(versions) or "N/A"

    except (KeyError, IndexError, TypeError) as e:
        print(f"    [!] Parsing MITRE {cve_id} : {e}")

    return result


def enrichir_epss_batch(cve_ids):
    """
    Interroge l'API EPSS pour un lot de CVE en une seule requête.
    L'API FIRST accepte jusqu'à ~100 CVE séparés par des virgules.
    Retourne un dict {cve_id: epss_score}.
    """
    scores = {}

    # D'abord, tenter le cache local pour chaque CVE
    a_requeter = []
    for cve_id in cve_ids:
        data = load_local_json(os.path.join(LOCAL_FIRST_DIR, cve_id))
        if data:
            epss_data = data.get("data", [])
            if epss_data:
                try:
                    scores[cve_id] = float(epss_data[0]["epss"])
                    continue
                except (KeyError, ValueError, TypeError):
                    pass
        a_requeter.append(cve_id)

    # Requêtes batch par tranches de EPSS_BATCH_SIZE
    for i in range(0, len(a_requeter), EPSS_BATCH_SIZE):
        batch = a_requeter[i:i + EPSS_BATCH_SIZE]
        url   = API_EPSS_BATCH.format(cves=",".join(batch))
        resp  = safe_get(url)
        if resp is None:
            continue
        try:
            data = resp.json()
        except json.JSONDecodeError:
            continue

        for item in data.get("data", []):
            try:
                scores[item["cve"]] = float(item["epss"])
            except (KeyError, ValueError, TypeError):
                pass

    return scores


def enrichir_mitre_tous(cve_ids):
    """
    Enrichit tous les CVE depuis MITRE en parallèle.
    Retourne un dict {cve_id: info_dict}.
    """
    print(f"\n[*] Enrichissement MITRE ({len(cve_ids)} CVE, {MAX_WORKERS_MITRE} workers)…")
    resultats = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS_MITRE) as ex:
        futures = {ex.submit(enrichir_depuis_mitre, cve_id): cve_id for cve_id in cve_ids}
        done = 0
        for fut in as_completed(futures):
            cve_id = futures[fut]
            resultats[cve_id] = fut.result()
            done += 1
            if done % 50 == 0:
                print(f"  … {done}/{len(cve_ids)} CVE MITRE traités")
    return resultats


# ─────────────────────────────────────────────────────────────────────────────
# CONSOLIDATION
# ─────────────────────────────────────────────────────────────────────────────

def construire_dataframe(bulletins, cves_par_bulletin, mitre_data, epss_data):
    """
    Assemble toutes les données en un DataFrame une-ligne-par-CVE.
    """
    rows = []
    for bulletin in bulletins:
        bid  = bulletin["id_anssi"]
        cves = cves_par_bulletin.get(bid, [])

        if not cves:
            rows.append({
                "id_anssi": bid, "titre": bulletin["titre"],
                "type": bulletin["type"], "date": bulletin["date"],
                "lien": bulletin["lien"], "cve_id": None,
                "cvss_score": None, "base_severity": "N/A",
                "cwe": "N/A", "cwe_desc": "N/A", "epss_score": None,
                "description": "N/A", "vendor": "N/A",
                "product": "N/A", "versions_affectees": "N/A",
            })
            continue

        for cve_id in cves:
            info = mitre_data.get(cve_id, {})
            rows.append({
                "id_anssi":           bid,
                "titre":              bulletin["titre"],
                "type":               bulletin["type"],
                "date":               bulletin["date"],
                "lien":               bulletin["lien"],
                "cve_id":             cve_id,
                "cvss_score":         info.get("cvss_score"),
                "base_severity":      info.get("base_severity", "N/A"),
                "cwe":                info.get("cwe",           "N/A"),
                "cwe_desc":           info.get("cwe_desc",      "N/A"),
                "epss_score":         epss_data.get(cve_id),
                "description":        info.get("description",   "N/A"),
                "vendor":             info.get("vendor",        "N/A"),
                "product":            info.get("product",       "N/A"),
                "versions_affectees": info.get("versions_affectees", "N/A"),
            })

    df = pd.DataFrame(rows)
    df["cvss_score"] = pd.to_numeric(df["cvss_score"], errors="coerce")
    df["epss_score"] = pd.to_numeric(df["epss_score"], errors="coerce")
    df["date"]       = pd.to_datetime(df["date"],      errors="coerce")
    return df


# ─────────────────────────────────────────────────────────────────────────────
# POINT D'ENTRÉE
# ─────────────────────────────────────────────────────────────────────────────

def main():
    t0 = time.time()
    print("=" * 60)
    print("  ANSSI CVE Pipeline – Étapes 1, 2 & 3  (parallélisé)")
    print("=" * 60)

    # ── Étape 1 : flux RSS (les 2 flux en parallèle) ─────────────
    bulletins = extraire_tous_bulletins()
    print(f"\n[+] Total bulletins : {len(bulletins)}")

    # ── Étape 2 : extraction CVE (bulletins en parallèle) ────────
    cves_par_bulletin = extraire_cve_tous_bulletins(bulletins)
    toutes_cves = sorted({
        cve
        for cves in cves_par_bulletin.values()
        for cve in cves
    })
    print(f"\n[+] CVE uniques : {len(toutes_cves)}")

    # ── Étape 3a : MITRE (CVE en parallèle) ──────────────────────
    mitre_data = enrichir_mitre_tous(toutes_cves)

    # ── Étape 3b : EPSS (batch, une ou quelques requêtes) ────────
    print(f"\n[*] Enrichissement EPSS batch ({len(toutes_cves)} CVE)…")
    epss_data = enrichir_epss_batch(toutes_cves)
    print(f"  [+] {len(epss_data)} scores EPSS récupérés.")

    # ── Consolidation ─────────────────────────────────────────────
    df = construire_dataframe(bulletins, cves_par_bulletin, mitre_data, epss_data)

    # ── Aperçu ───────────────────────────────────────────────────
    elapsed = time.time() - t0
    print("\n" + "=" * 60)
    print(f"  DataFrame consolidé  ({elapsed:.1f}s)")
    print("=" * 60)
    print(df.head(10).to_string(index=False))
    print(f"\nDimensions    : {df.shape[0]} lignes × {df.shape[1]} colonnes")
    print(f"Durée totale  : {elapsed:.1f}s")
    print("\nSévérités :")
    print(df["base_severity"].value_counts())

    # ── Export CSV ───────────────────────────────────────────────
    df.to_csv(OUTPUT_CSV, index=False, encoding="utf-8-sig")
    print(f"\n[+] CSV exporté → {OUTPUT_CSV}")

    return df


if __name__ == "__main__":
    df = main()