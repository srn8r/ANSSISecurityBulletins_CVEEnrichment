# Analyse des avis et alertes ANSSI avec enrichissement des CVE

Script Python qui récupère les avis et alertes de sécurité publiés par l'ANSSI (CERT-FR), extrait les CVE qu'ils mentionnent et les enrichit avec les données de MITRE et de FIRST, pour obtenir un tableau consolidé des vulnérabilités.

## Fonctionnement

1. **Lecture des flux RSS du CERT-FR**
   - avis : https://www.cert.ssi.gouv.fr/avis/feed/
   - alertes : https://www.cert.ssi.gouv.fr/alerte/feed/
2. **Récupération du JSON de chaque bulletin** pour en extraire l'identifiant ANSSI et la liste des CVE.
3. **Enrichissement de chaque CVE**
   - API CVE de MITRE (`cveawg.mitre.org`) pour la description, le score CVSS, la CWE, l'éditeur, le produit et les versions affectées
   - API EPSS de FIRST (`api.first.org`) pour la probabilité d'exploitation
4. **Consolidation** de toutes les lignes dans un DataFrame pandas, une ligne par couple bulletin / CVE.

## Colonnes produites

| Colonne | Source |
|---|---|
| ID ANSSI, Titre ANSSI, Type, Date, Lien | Flux CERT-FR |
| CVE | JSON du bulletin |
| CVSS, CWE, Description, Éditeur, Produit, Versions affectées | MITRE |
| EPSS | FIRST |
| Base Severity | Prévue, pas encore renseignée |

## Installation

```bash
pip install -r requirements.txt
```

## Utilisation

```bash
python script.py
```

Le script est découpé en cellules (`#%%`), il peut aussi être exécuté pas à pas dans Spyder ou VS Code. À la fin, la variable `df` contient le tableau consolidé et ses premières lignes sont affichées.

Le script interroge des API externes, une connexion internet est donc nécessaire, et l'exécution peut prendre quelques minutes selon le nombre de bulletins.

## Pistes d'amélioration

- Export du tableau en CSV
- Calcul de la colonne Base Severity à partir du score CVSS
- Alertes par email pour les vulnérabilités critiques
- Exécution planifiée pour une veille continue
- Tableau de bord de visualisation (éditeurs, produits, CVSS, EPSS)
- Stockage dans une base SQL

## Stack

Python · feedparser · requests · pandas
