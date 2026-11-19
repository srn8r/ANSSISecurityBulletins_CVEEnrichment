"""Static configuration: data sources and output schema."""

FEEDS: dict[str, str] = {
    "Avis": "https://www.cert.ssi.gouv.fr/avis/feed/",
    "Alerte": "https://www.cert.ssi.gouv.fr/alerte/feed/",
}

MITRE_CVE_API = "https://cveawg.mitre.org/api/cve/{cve_id}"
FIRST_EPSS_API = "https://api.first.org/data/v1/epss"

# FIRST accepts a comma-separated list of CVEs; keep batches small enough for the URL.
EPSS_BATCH_SIZE = 100

REQUEST_TIMEOUT = 15  # seconds
USER_AGENT = "anssi-cve-enrichment/1.0 (+https://github.com/srn8r/Analyse_Avis_Alertes_ANSSI_Enrichissement_CVE)"

# Output columns are kept in French to match the CERT-FR source data.
COLUMNS: list[str] = [
    "ID ANSSI",
    "Titre ANSSI",
    "Type",
    "Date",
    "CVE",
    "CVSS",
    "Base Severity",
    "CWE",
    "EPSS",
    "Lien",
    "Description",
    "Éditeur",
    "Produit",
    "Versions affectées",
]
