# Système de récupération et d’analyse des avis et alertes ANSSI

## Présentation générale
Ce projet a pour objectif d’automatiser la récupération et le traitement des avis et alertes publiés par l’ANSSI (CERT-FR). Le script lit les flux RSS officiels, télécharge les données associées, enrichit les CVE via les sources externes MITRE et FIRST, puis génère un fichier CSV consolidé. Des notifications par email peuvent ensuite être envoyées pour les vulnérabilités les plus critiques.

Ce projet est conçu pour être exécuté simplement dans Spyder (Anaconda) sans configuration complexe.

## Organisation du projet

Les dossiers alertes, avis, mitre et first doivent se trouver dans le même dossier que projet.py.

Le script détecte automatiquement son propre emplacement grâce à la variable BASE_DIR. Si le projet est organisé comme indiqué ci-dessus, il n’est pas nécessaire de modifier manuellement le répertoire de travail dans Spyder.

## Fonctionnement du script

1. Lecture des fichiers locaux (alertes et avis)
   Le programme parcourt les dossiers alertes et avis et extrait les informations essentielles : identifiant ANSSI, date, titre, CVE, description, systèmes affectés, etc.

2. Récupération des données ANSSI via RSS
   Le script interroge automatiquement les flux suivants :
   - https://www.cert.ssi.gouv.fr/avis/feed/
   - https://www.cert.ssi.gouv.fr/alerte/feed/
   Chaque entrée RSS est traitée pour récupérer les données JSON détaillées qui y sont associées.

3. Enrichissement des CVE
   Pour chaque CVE détectée, le script interroge :
   - MITRE (description, CVSS, CWE, éditeur, produit)
   - FIRST (score EPSS)

4. Création du fichier CSV final
   Toutes les données sont fusionnées et écrites dans le fichier donnees_consolidees_complet.csv. Les doublons sont éliminés et certaines colonnes sont nettoyées pour obtenir un fichier lisible et structuré.

5. Envoi des alertes par email
   Les vulnérabilités sont classées selon leur sévérité. Lorsque certaines dépassent un seuil élevé ou critique, un message email est généré et envoyé automatiquement.

## Utilisation sous Spyder (Anaconda)

1. Ouvrir Spyder
2. Ouvrir script.py
3. Vérifier que l’arborescence du projet est conforme à la structure indiquée
4. Exécuter le script

Lors de l’exécution :
- le fichier CSV consolidé est généré ou mis à jour
- des messages d’alerte peuvent être envoyés selon les résultats

Aucune commande particulière n’est nécessaire ; tout se fait depuis l’environnement Spyder.

## Points importants

- Les dossiers alertes, avis, mitre et first doivent exister, même vides au départ.
- Le script repose sur des appels API externes. Des erreurs peuvent survenir si les services MITRE ou FIRST sont indisponibles.
- L’envoi d’emails dépend du bon paramétrage d’un compte Gmail et de l’accès au réseau.
- Des pauses sont intégrées dans le script pour éviter de surcharger les API.

## Améliorations futures possibles

- Ajout d’un mode surveillance continue
- Interface graphique ou web pour la visualisation des données
- Passage à une base de données SQL
- Téléchargement automatique des JSON MITRE et FIRST manquants
- Mise en place d’un système de filtres avancés (éditeur, produit, CVSS, EPSS, CWE)

## Licence
Projet réalisé dans un cadre étudiant. Licence recommandée : MIT.
