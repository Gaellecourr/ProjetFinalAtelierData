# Analyse des Avis et Alertes ANSSI avec Enrichissement des CVE

Projet réalisé dans le cadre du MasterCamp Data & IA — EFREI 2026.

---

## Présentation du projet

Ce projet construit un pipeline automatisé de veille cybersécurité à partir
des bulletins publiés par l'ANSSI (Agence Nationale de la Sécurité des
Systèmes d'Information). Il extrait, enrichit, analyse et visualise les
vulnérabilités recensées, puis applique des modèles de Machine Learning
pour prioriser les menaces.

---

## Fonctionnalités

- Extraction des flux RSS ANSSI (avis et alertes CERT-FR)
- Identification des CVE mentionnés dans chaque bulletin
- Enrichissement via l'API MITRE (score CVSS, type CWE, produits affectés)
- Enrichissement via l'API EPSS de FIRST (probabilité d'exploitation)
- Consolidation dans un DataFrame pandas exporté en CSV
- Analyse exploratoire et visualisations (8 graphiques)
- Modèles Machine Learning :
  - K-Means clustering (segmentation par profil de risque)
  - DBSCAN (détection de CVE ultra-dangereux)
  - XGBoost Classification (prédiction de sévérité)
  - Random Forest Régression (prédiction du score EPSS)
- Génération d'alertes email HTML personnalisées

---

## Structure du projet
Projet/
    │
    ├── rss.py                    # Pipeline principal (étapes 1 à 4)
    ├── alertes.py                # Générateur d'alertes email (étape 7)
    ├── Visualizations.ipynb      # Analyse, visualisations et ML (étapes 5 et 6)
    ├── Visualizations.html       # Export HTML du notebook
    │
    ├── FluxRSS.ipynb             # Prototype exploratoire (extraction RSS)
    ├── Exploration.ipynb         # Prototype exploratoire (analyse initiale)
    │
    ├── data/
    │   ├── Avis/                 # JSON des avis ANSSI (~4 025 fichiers)
    │   ├── alertes/              # JSON des alertes ANSSI (~78 fichiers)
    │   ├── mitre/                # Données CVE MITRE (~37 279 fichiers)
    │   └── first/                # Scores EPSS FIRST (~37 279 fichiers)
    │
    ├── anssi_cve_enrichi.csv     # CSV généré (non versionné — trop volumineux)
    └── README.md                 # Ce fichier
---

## Installation

### Prérequis

- Python 3.10 ou supérieur
- pip

### Installation des dépendances

```bash
pip install pandas numpy matplotlib seaborn scikit-learn xgboost \
            feedparser requests jupyter nbconvert
```

---

## Données locales (dossier `data/`)

Le dossier `data/` n'est pas versionné en raison de sa taille (~2 Go).
Il contient les fichiers pré-téléchargés fournis par l'enseignant :

    data/
    ├── Avis/        # Bulletins ANSSI avis (~4 025 fichiers JSON)
    ├── alertes/     # Bulletins ANSSI alertes (~78 fichiers JSON)
    ├── mitre/       # Données CVE MITRE (~37 279 fichiers)
    └── first/       # Scores EPSS FIRST (~37 279 fichiers)

Sans ce dossier, `rss.py` fonctionne uniquement via l'API en ligne
(données limitées aux 40 derniers bulletins RSS).

## Utilisation

### Étape 1 — Générer le CSV enrichi

```bash
python rss.py
```

Ce script :
1. Récupère les bulletins depuis les flux RSS ANSSI en ligne
2. Fusionne avec les données locales du dossier `data/`
3. Extrait les CVE de chaque bulletin
4. Enrichit chaque CVE via les APIs MITRE et EPSS
5. Exporte le DataFrame consolidé → `anssi_cve_enrichi.csv`

Durée estimée : 5 à 10 minutes selon la connexion.

### Étape 2 — Lancer l'analyse et le ML

Ouvrir `Visualizations.ipynb` dans VS Code ou Jupyter et exécuter
toutes les cellules (`Run All`).

Le notebook charge `anssi_cve_enrichi.csv` et produit :
- Les statistiques descriptives du dataset
- 8 visualisations interactives
- Les modèles K-Means, DBSCAN, XGBoost et Random Forest
- La synthèse comparative des modèles

### Étape 3 — Générer une alerte email

```bash
python alertes.py
```

L'alerte est sauvegardée dans `alerte_email.html`.
Ouvrir dans un navigateur pour visualiser le rendu.

Pour activer l'envoi réel par email, modifier dans `alertes.py` :

```python
EMAIL_EXPEDITEUR   = "votre_email@gmail.com"
EMAIL_DESTINATAIRE = "destinataire@email.com"
EMAIL_MOT_DE_PASSE = "mot_de_passe_application"
ENVOI_ACTIF        = True
```

---

## Sources de données

| Source | Description | URL |
|--------|-------------|-----|
| ANSSI CERT-FR | Flux RSS avis | https://www.cert.ssi.gouv.fr/avis/feed/ |
| ANSSI CERT-FR | Flux RSS alertes | https://www.cert.ssi.gouv.fr/alerte/feed/ |
| MITRE CVE | API CVE (CVSS, CWE) | https://cveawg.mitre.org/api/cve/{cve_id} |
| FIRST EPSS | Score d'exploitation | https://api.first.org/data/v1/epss?cve={cve_id} |

---

## Description du CSV produit

Le fichier `anssi_cve_enrichi.csv` contient **127 016 lignes** (une par CVE
par bulletin) et **15 colonnes** :

| Colonne | Description |
|---------|-------------|
| `id_anssi` | Identifiant du bulletin ANSSI |
| `titre` | Titre du bulletin |
| `type` | Type de bulletin (Avis ou Alerte) |
| `date` | Date de publication |
| `lien` | URL du bulletin original |
| `cve_id` | Identifiant CVE |
| `cvss_score` | Score de criticité CVSS (0-10) |
| `base_severity` | Sévérité (Low / Medium / High / Critical) |
| `cwe` | Catégorie de vulnérabilité CWE |
| `cwe_desc` | Description du CWE |
| `epss_score` | Probabilité d'exploitation (0-1) |
| `description` | Description de la vulnérabilité |
| `vendor` | Éditeur affecté |
| `product` | Produit affecté |
| `versions_affectees` | Versions impactées |

---

## Modèles Machine Learning

### Non supervisé

| Modèle | Paramètres | Résultat |
|--------|-----------|---------|
| K-Means | k=4 | 4 clusters de profils de risque cohérents |
| DBSCAN | eps=1.0, min_samples=5 | 79 CVE ultra-dangereux isolés (EPSS > 0.47) |

### Supervisé

| Modèle | Features | Performance |
|--------|---------|-------------|
| XGBoost Classification | epss_score, cwe_encoded, type_encoded | CV 5-fold : 63.7% ± 1.3% |
| Random Forest Régression | cvss_score, cwe_encoded, type_encoded | R²=0.168, MAE=0.020 |

> **Note** : `cvss_score` est exclu des features de classification car il
> détermine mécaniquement `base_severity` (data leakage direct).

---

## Gestion responsable des ressources externes

Conformément aux recommandations du sujet :
- Délai de 2 secondes entre chaque requête (`safe_get` avec retry exponentiel)
- Utilisation prioritaire des fichiers locaux pré-téléchargés (`data/`)
- Requêtes EPSS groupées par batch de 100 CVE

---

## Livraisons

| Livrable | Fichier | Statut |
|----------|---------|--------|
| Code Python fonctionnel | `rss.py`, `alertes.py` | ✅ |
| README | `README.md` | ✅ |
| CSV consolidé | `anssi_cve_enrichi.csv` | ✅ |
| Notebook analyse + ML | `Visualizations.ipynb` | ✅ |
| Export HTML notebook | `Visualizations.html` | ✅ |
| Vidéo démo 3 min | `demo.mp4` | ✅ |