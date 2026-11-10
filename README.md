# ANSSI Security Bulletins Analysis with CVE Enrichment

Python script that collects the security advisories and alerts published by ANSSI (CERT-FR, the French national cybersecurity agency), extracts the CVEs they reference and enriches them with MITRE and FIRST data, producing a consolidated vulnerability table.

## How it works

1. **Read the CERT-FR RSS feeds**
   - advisories: https://www.cert.ssi.gouv.fr/avis/feed/
   - alerts: https://www.cert.ssi.gouv.fr/alerte/feed/
2. **Fetch the JSON of each bulletin** to extract its ANSSI identifier and the list of CVEs.
3. **Enrich each CVE**
   - MITRE CVE API (`cveawg.mitre.org`) for description, CVSS score, CWE, vendor, product and affected versions
   - FIRST EPSS API (`api.first.org`) for the exploitation probability
4. **Consolidate** all rows into a pandas DataFrame, one row per bulletin / CVE pair.

## Output columns

| Column | Source |
|---|---|
| ID ANSSI, Titre ANSSI, Type, Date, Lien | CERT-FR feed |
| CVE | Bulletin JSON |
| CVSS, CWE, Description, Éditeur, Produit, Versions affectées | MITRE |
| EPSS | FIRST |
| Base Severity | Planned, not filled yet |

Column names are kept in French, as in the source data.

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
python script.py
```

The script is split into cells (`#%%`), so it can also be run step by step in Spyder or VS Code. At the end, the `df` variable holds the consolidated table and its first rows are printed.

The script calls external APIs, so an internet connection is required, and a run can take a few minutes depending on the number of bulletins.

## Roadmap

- CSV export of the table
- Compute Base Severity from the CVSS score
- Email alerts for critical vulnerabilities
- Scheduled runs for continuous monitoring
- Visualization dashboard (vendors, products, CVSS, EPSS)
- Storage in a SQL database

## Tech stack

Python · feedparser · requests · pandas
