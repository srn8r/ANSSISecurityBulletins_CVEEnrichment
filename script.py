# -*- coding: utf-8 -*-
"""
Created on Fri Jan  9 09:13:15 2026

@author: kures
"""

import feedparser
import requests
import pandas as pd
#%%
URLS = {
    "avis": "https://www.cert.ssi.gouv.fr/avis/feed/",
    "alerte": "https://www.cert.ssi.gouv.fr/alerte/feed/"
}

colonnes = ["ID ANSSI", "Titre ANSSI", "Type", "Date", "CVE", "CVSS", 
            "Base Severity", "CWE", "EPSS", "Lien", "Description", 
            "Éditeur", "Produit", "Versions affectées"]


#%%
def recup_json(url):
    response = requests.get(url)
    return response.json()

def determiner_type(lien):
    if "avis" in lien:
        return "Avis"
    if "alerte" in lien:
        return "Alerte"
    return "Inconnu"

def extraire_id_anssi(lien):
    for element in lien.split("/"):
        if "CERTFR" in element:
            return element
    return None

def extraire_cves(donnees_json):
    cves = []
    for cve in donnees_json.get("cves", []):
        cves.append(cve.get("name"))

    if not cves:
        return [""]
    return cves

def recherche_API_CVE(cve_id):
    if not cve_id:
        return {}
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    response = requests.get(url)
    data = response.json()
    
    containers = data.get("containers", {})
    cna = containers.get("cna", {})
    if not cna:
        return {}

    descriptions = cna.get("descriptions", [{}])
    description = descriptions[0].get("value", "N/A")
    
    metrics = cna.get("metrics", [{}])
    cvss_score = None
    if metrics and "cvssV3_1" in metrics[0]:
        cvss_score = metrics[0]["cvssV3_1"].get("baseScore")
    elif metrics and "cvssV3_0" in metrics[0]:
        cvss_score = metrics[0]["cvssV3_0"].get("baseScore")
    elif metrics and "cvssV4_0" in metrics[0]:
        cvss_score = metrics[0]["cvssV4_0"].get("baseScore")
    else:
        print(metrics)
    
    cwe = "Non disponible"
    problemtype = cna.get("problemTypes", [])
    if problemtype and "descriptions" in problemtype[0]:
        cwe = problemtype[0]["descriptions"][0].get("cweId", "Non disponible")
        
    affected_list = cna.get("affected", [])
    vendor, product_name, versions = "N/A", "N/A", []
    
    if affected_list:
        affected = affected_list[0]
        vendor = affected.get("vendor", "N/A")
        product_name = affected.get("product", "N/A")
        versions = [v.get("version") for v in affected.get("versions", []) if v.get("status") == "affected"]
    
    return {
        "Editeur": vendor,
        "Produit": product_name,
        "Versions": ', '.join(versions) if versions else "N/A",
        "Score CVSS": cvss_score,
        "Type CWE": cwe,
        "Description": description
    }



def score_epss(cve_id):
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    response = requests.get(url)
    donnees = response.json()
    epss_data = donnees.get("data", [])
    if not epss_data:
        return None
    return epss_data[0].get("epss")

#%%
def entry_to_lignes(entry):
    lignes = []
    url_json = entry.link + "json/"
    donnees = recup_json(url_json)
    
    cves = extraire_cves(donnees)
    type_avis = determiner_type(entry.link)
    id_anssi = extraire_id_anssi(entry.link)
    
    for cve in cves:
        cve_dict = recherche_API_CVE(cve)
        epss = score_epss(cve)
        ligne = {
            "ID ANSSI": id_anssi,
            "Titre ANSSI": entry.title,
            "Type": type_avis,
            "Date": entry.published,
            "CVE": cve,
            "CVSS": cve_dict.get("CVSS"),
            "Base Severity": None,
            "CWE": cve_dict.get("CWE"),
            "EPSS": epss,
            "Lien": entry.link,
            "Description": cve_dict.get("Description"),
            "Éditeur": cve_dict.get("Editeur"),
            "Produit": cve_dict.get("Produit"),
            "Versions affectées": cve_dict.get("Versions")
        }

        lignes.append(ligne)

    return lignes


#%%
def construire_dataframe_depuis_flux(url_flux):
    flux = feedparser.parse(url_flux)
    toutes_les_lignes = []
    i = 0
    for entry in flux.entries:
        print(i)
        i +=1
        try:
            lignes = entry_to_lignes(entry)
            toutes_les_lignes.extend(lignes)
        except Exception as erreur:
            print(f"Erreur sur {entry.link} : {erreur}")

    return toutes_les_lignes


def construire_dataframe_complet():
    toutes_les_lignes = []

    for nom_flux, url in URLS.items():
        print(f"Traitement du flux : {nom_flux}")
        lignes_flux = construire_dataframe_depuis_flux(url)
        toutes_les_lignes.extend(lignes_flux)

    df = pd.DataFrame(toutes_les_lignes, columns=colonnes)
    return df


#%%
df = construire_dataframe_complet()
print(df.head(10))
    