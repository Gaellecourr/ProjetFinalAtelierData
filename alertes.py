# ==============================================================================
# ÉTAPE 7 — GÉNÉRATION D'ALERTES ET NOTIFICATIONS EMAIL
# Projet Mastercamp 2026 — Analyse des avis et alertes ANSSI
# ==============================================================================
#
# Ce script :
#   1. Charge le CSV enrichi produit par rss.py
#   2. Filtre les CVE selon des critères de criticité configurables
#   3. Génère un email HTML professionnel
#   4. Envoie l'email via Gmail (optionnel — désactivé par défaut)
#
# Critères d'alerte configurables :
#   - Score CVSS minimum
#   - Score EPSS minimum
#   - Sévérités ciblées
#   - Produits/éditeurs surveillés
# ==============================================================================

import os
import json
import smtplib
import pandas as pd
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION — à adapter selon les besoins
# ─────────────────────────────────────────────────────────────────────────────

CSV_PATH = "anssi_cve_enrichi.csv"

# Critères de filtrage des CVE dangereux
SEUIL_CVSS       = 7.0          # Score CVSS minimum
SEUIL_EPSS       = 0.1          # Score EPSS minimum (10% de probabilité)
SEVERITES_CIBLES = ["Critical", "High"]  # Sévérités surveillées
MAX_CVE_EMAIL    = 20           # Nombre maximum de CVE dans l'email

# Produits/éditeurs à surveiller en priorité (liste vide = tous)
PRODUITS_SURVEILLES = []        # Ex: ["Microsoft", "Apache", "Ivanti"]

# Configuration email (optionnel)
EMAIL_EXPEDITEUR  = "votre_email@gmail.com"
EMAIL_DESTINATAIRE = "destinataire@email.com"
EMAIL_MOT_DE_PASSE = "mot_de_passe_application"  # Mot de passe d'application Gmail
ENVOI_ACTIF       = False       # Mettre True pour envoyer réellement


# ─────────────────────────────────────────────────────────────────────────────
# CHARGEMENT ET FILTRAGE
# ─────────────────────────────────────────────────────────────────────────────

def charger_donnees(csv_path):
    """Charge le CSV enrichi et prépare les colonnes."""
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"CSV introuvable : {csv_path}")

    df = pd.read_csv(csv_path)
    df['cvss_score'] = pd.to_numeric(df['cvss_score'], errors='coerce')
    df['epss_score'] = pd.to_numeric(df['epss_score'], errors='coerce')
    df['date']       = pd.to_datetime(df['date'], errors='coerce')

    print(f"[+] CSV chargé : {len(df):,} lignes × {df.shape[1]} colonnes")
    return df


def filtrer_cve_dangereux(df):
    """
    Filtre les CVE selon les critères configurés.
    Retourne un DataFrame trié par dangerosité décroissante.
    """
    masque = pd.Series([True] * len(df), index=df.index)

    # Filtre CVSS
    masque &= df['cvss_score'].fillna(0) >= SEUIL_CVSS

    # Filtre EPSS
    masque &= df['epss_score'].fillna(0) >= SEUIL_EPSS

    # Filtre sévérité
    if SEVERITES_CIBLES:
        masque &= df['base_severity'].isin(SEVERITES_CIBLES)

    # Filtre produits surveillés
    if PRODUITS_SURVEILLES:
        masque &= df['vendor'].str.contains(
            '|'.join(PRODUITS_SURVEILLES), case=False, na=False
        )

    df_filtre = df[masque].drop_duplicates(subset=['cve_id']).copy()

    # Tri par dangerosité : EPSS d'abord, puis CVSS
    df_filtre = df_filtre.sort_values(
        ['epss_score', 'cvss_score'], ascending=False
    ).head(MAX_CVE_EMAIL)

    print(f"[+] CVE dangereux filtrés : {len(df_filtre)}")
    print(f"    Critères : CVSS >= {SEUIL_CVSS} | EPSS >= {SEUIL_EPSS} "
          f"| Sévérités : {SEVERITES_CIBLES}")

    return df_filtre


# ─────────────────────────────────────────────────────────────────────────────
# GÉNÉRATION DE L'EMAIL HTML
# ─────────────────────────────────────────────────────────────────────────────

def get_severity_color(severity):
    """Retourne la couleur HTML associée à une sévérité."""
    colors = {
        'Critical': '#dc2626',
        'High':     '#ea580c',
        'Medium':   '#d97706',
        'Low':      '#16a34a',
    }
    return colors.get(severity, '#6b7280')


def generer_ligne_cve(row):
    """Génère une ligne HTML pour un CVE donné."""
    severity       = row.get('base_severity', 'N/A')
    severity_color = get_severity_color(severity)
    cvss           = f"{row['cvss_score']:.1f}" if pd.notna(row.get('cvss_score')) else 'N/A'
    epss           = f"{row['epss_score']:.3f}" if pd.notna(row.get('epss_score')) else 'N/A'
    epss_pct       = f"{float(epss)*100:.1f}%" if epss != 'N/A' else 'N/A'
    vendor         = str(row.get('vendor', 'N/A'))[:30]
    product        = str(row.get('product', 'N/A'))[:30]
    lien           = row.get('lien', '#')
    description    = str(row.get('description', 'N/A'))[:120] + '...'

    return f"""
    <tr style="border-bottom: 1px solid #e5e7eb;">
        <td style="padding: 12px 8px; font-weight: bold; color: #1e40af;">
            <a href="{lien}" style="color: #1e40af; text-decoration: none;">
                {row.get('cve_id', 'N/A')}
            </a>
        </td>
        <td style="padding: 12px 8px; text-align: center;">
            <span style="background-color: {severity_color}; color: white;
                         padding: 3px 8px; border-radius: 4px; font-size: 12px;
                         font-weight: bold;">
                {severity}
            </span>
        </td>
        <td style="padding: 12px 8px; text-align: center; font-weight: bold;">
            {cvss}
        </td>
        <td style="padding: 12px 8px; text-align: center; color: #dc2626;
                   font-weight: bold;">
            {epss_pct}
        </td>
        <td style="padding: 12px 8px; color: #374151;">{vendor}</td>
        <td style="padding: 12px 8px; color: #374151;">{product}</td>
        <td style="padding: 12px 8px; color: #6b7280; font-size: 12px;">
            {description}
        </td>
    </tr>"""


def generer_email_html(df_alerte, date_generation):
    """
    Génère le corps HTML complet de l'email d'alerte.
    Retourne une chaîne HTML prête à être envoyée.
    """
    nb_critical = len(df_alerte[df_alerte['base_severity'] == 'Critical'])
    nb_high     = len(df_alerte[df_alerte['base_severity'] == 'High'])
    epss_max    = df_alerte['epss_score'].max()
    cvss_max    = df_alerte['cvss_score'].max()

    # Lignes du tableau CVE
    lignes_cve = "\n".join(
        generer_ligne_cve(row) for _, row in df_alerte.iterrows()
    )

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Alerte ANSSI — Vulnérabilités Critiques</title>
</head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont,
             'Segoe UI', Roboto, sans-serif; background-color: #f3f4f6;">

    <!-- En-tête -->
    <div style="background: linear-gradient(135deg, #1e3a5f 0%, #dc2626 100%);
                padding: 30px 40px; text-align: center;">
        <h1 style="color: white; margin: 0; font-size: 24px; font-weight: 700;">
            🔴 ALERTE CYBERSÉCURITÉ — CERT-FR
        </h1>
        <p style="color: #fecaca; margin: 8px 0 0 0; font-size: 14px;">
            Bulletin automatique généré le {date_generation}
        </p>
    </div>

    <!-- Résumé exécutif -->
    <div style="background-color: white; margin: 20px 40px; padding: 24px;
                border-radius: 8px; border-left: 4px solid #dc2626;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
        <h2 style="color: #1e3a5f; margin: 0 0 16px 0; font-size: 18px;">
            Résumé exécutif
        </h2>
        <p style="color: #374151; margin: 0 0 12px 0; line-height: 1.6;">
            Ce bulletin recense <strong>{len(df_alerte)} vulnérabilités</strong>
            détectées dans les bulletins ANSSI nécessitant une attention immédiate,
            dont <strong style="color: #dc2626;">{nb_critical} critiques</strong>
            et <strong style="color: #ea580c;">{nb_high} élevées</strong>.
        </p>
        <p style="color: #374151; margin: 0; line-height: 1.6;">
            La vulnérabilité la plus dangereuse présente un score CVSS de
            <strong>{cvss_max:.1f}/10</strong> avec une probabilité d'exploitation
            (EPSS) de <strong style="color: #dc2626;">{epss_max*100:.1f}%</strong>.
        </p>
    </div>

    <!-- KPI -->
    <div style="display: flex; margin: 0 40px 20px 40px; gap: 12px;">
        <div style="flex: 1; background: #fef2f2; padding: 16px; border-radius: 8px;
                    text-align: center; border: 1px solid #fecaca;">
            <div style="font-size: 32px; font-weight: 700; color: #dc2626;">
                {nb_critical}
            </div>
            <div style="color: #991b1b; font-size: 13px; font-weight: 600;">
                CRITIQUES
            </div>
        </div>
        <div style="flex: 1; background: #fff7ed; padding: 16px; border-radius: 8px;
                    text-align: center; border: 1px solid #fed7aa;">
            <div style="font-size: 32px; font-weight: 700; color: #ea580c;">
                {nb_high}
            </div>
            <div style="color: #9a3412; font-size: 13px; font-weight: 600;">
                ÉLEVÉES
            </div>
        </div>
        <div style="flex: 1; background: #eff6ff; padding: 16px; border-radius: 8px;
                    text-align: center; border: 1px solid #bfdbfe;">
            <div style="font-size: 32px; font-weight: 700; color: #1d4ed8;">
                {cvss_max:.1f}
            </div>
            <div style="color: #1e40af; font-size: 13px; font-weight: 600;">
                CVSS MAX
            </div>
        </div>
        <div style="flex: 1; background: #fdf4ff; padding: 16px; border-radius: 8px;
                    text-align: center; border: 1px solid #e9d5ff;">
            <div style="font-size: 32px; font-weight: 700; color: #7c3aed;">
                {epss_max*100:.0f}%
            </div>
            <div style="color: #6d28d9; font-size: 13px; font-weight: 600;">
                EPSS MAX
            </div>
        </div>
    </div>

    <!-- Tableau des CVE -->
    <div style="background-color: white; margin: 0 40px 20px 40px; padding: 24px;
                border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
        <h2 style="color: #1e3a5f; margin: 0 0 16px 0; font-size: 18px;">
            Détail des vulnérabilités ({len(df_alerte)} CVE)
        </h2>
        <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
            <thead>
                <tr style="background-color: #1e3a5f; color: white;">
                    <th style="padding: 12px 8px; text-align: left;">CVE</th>
                    <th style="padding: 12px 8px; text-align: center;">Sévérité</th>
                    <th style="padding: 12px 8px; text-align: center;">CVSS</th>
                    <th style="padding: 12px 8px; text-align: center;">EPSS</th>
                    <th style="padding: 12px 8px; text-align: left;">Éditeur</th>
                    <th style="padding: 12px 8px; text-align: left;">Produit</th>
                    <th style="padding: 12px 8px; text-align: left;">Description</th>
                </tr>
            </thead>
            <tbody>
                {lignes_cve}
            </tbody>
        </table>
    </div>

    <!-- Recommandations -->
    <div style="background-color: #fffbeb; margin: 0 40px 20px 40px; padding: 24px;
                border-radius: 8px; border: 1px solid #fcd34d;">
        <h2 style="color: #92400e; margin: 0 0 12px 0; font-size: 16px;">
            ⚠️ Recommandations
        </h2>
        <ul style="color: #78350f; margin: 0; padding-left: 20px;
                   line-height: 1.8; font-size: 14px;">
            <li>Appliquer immédiatement les correctifs disponibles pour les
                vulnérabilités <strong>Critical</strong></li>
            <li>Prioriser les CVE avec un score EPSS supérieur à 50%
                — exploitation active probable</li>
            <li>Consulter les bulletins ANSSI originaux pour les
                contournements provisoires</li>
            <li>Mettre à jour les systèmes de détection (IDS/IPS)
                avec les signatures associées</li>
        </ul>
    </div>

    <!-- Pied de page -->
    <div style="text-align: center; padding: 20px 40px;
                color: #9ca3af; font-size: 12px;">
        <p style="margin: 0;">
            Bulletin généré automatiquement depuis les données CERT-FR (ANSSI) •
            <a href="https://www.cert.ssi.gouv.fr" style="color: #6b7280;">
                www.cert.ssi.gouv.fr
            </a>
        </p>
        <p style="margin: 4px 0 0 0;">
            Ce message est généré automatiquement — ne pas répondre directement.
        </p>
    </div>

</body>
</html>"""

    return html


# ─────────────────────────────────────────────────────────────────────────────
# ENVOI EMAIL (optionnel)
# ─────────────────────────────────────────────────────────────────────────────

def envoyer_email(sujet, corps_html, destinataire):
    """
    Envoie l'email via Gmail SMTP.
    Nécessite un mot de passe d'application Gmail
    (Compte Google → Sécurité → Mots de passe des applications).
    """
    msg = MIMEMultipart('alternative')
    msg['Subject'] = sujet
    msg['From']    = EMAIL_EXPEDITEUR
    msg['To']      = destinataire

    # Partie texte (fallback si HTML non supporté)
    corps_texte = "Alerte ANSSI — Voir la version HTML de cet email."
    msg.attach(MIMEText(corps_texte, 'plain', 'utf-8'))
    msg.attach(MIMEText(corps_html,  'html',  'utf-8'))

    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(EMAIL_EXPEDITEUR, EMAIL_MOT_DE_PASSE)
            server.sendmail(EMAIL_EXPEDITEUR, destinataire, msg.as_string())
        print(f"[+] Email envoyé à {destinataire}")
    except Exception as e:
        print(f"[!] Erreur envoi email : {e}")


# ─────────────────────────────────────────────────────────────────────────────
# POINT D'ENTRÉE
# ─────────────────────────────────────────────────────────────────────────────

def main():
    date_generation = datetime.now().strftime("%d/%m/%Y à %H:%M")

    print("=" * 55)
    print("  ANSSI — Générateur d'alertes CVE")
    print("=" * 55)

    # 1. Chargement
    df = charger_donnees(CSV_PATH)

    # 2. Filtrage
    df_alerte = filtrer_cve_dangereux(df)

    if df_alerte.empty:
        print("[!] Aucun CVE ne correspond aux critères définis.")
        return

    # 3. Génération du sujet
    nb_critical = len(df_alerte[df_alerte['base_severity'] == 'Critical'])
    sujet = (
        f"🔴 ALERTE CERT-FR — {len(df_alerte)} vulnérabilités critiques "
        f"détectées ({nb_critical} Critical) — {datetime.now().strftime('%d/%m/%Y')}"
    )

    # 4. Génération du corps HTML
    corps_html = generer_email_html(df_alerte, date_generation)

    # 5. Sauvegarde locale de l'email (toujours)
    chemin_html = "alerte_email.html"
    with open(chemin_html, "w", encoding="utf-8") as f:
        f.write(corps_html)
    print(f"\n[+] Email généré → {chemin_html}")
    print(f"    Sujet : {sujet}")

    # 6. Affichage des CVE dans la console
    print(f"\n{'='*55}")
    print(f"  TOP CVE DÉTECTÉS")
    print(f"{'='*55}")
    colonnes = ['cve_id', 'base_severity', 'cvss_score', 'epss_score', 'vendor']
    print(df_alerte[colonnes].head(10).to_string(index=False))

    # 7. Envoi email (optionnel)
    if ENVOI_ACTIF:
        print(f"\n[*] Envoi email à {EMAIL_DESTINATAIRE}...")
        envoyer_email(sujet, corps_html, EMAIL_DESTINATAIRE)
    else:
        print(f"\n[i] Envoi désactivé (ENVOI_ACTIF = False).")
        print(f"    Pour envoyer, configurez EMAIL_EXPEDITEUR,")
        print(f"    EMAIL_MOT_DE_PASSE et passez ENVOI_ACTIF à True.")

    return df_alerte, corps_html, sujet


if __name__ == "__main__":
    df_alerte, corps_html, sujet = main()