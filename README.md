# Koesio - Script de Préparation Post-Installation Windows (KoesioPrep)

## Table des Matières
- [À Propos du Projet](#à-propos-du-projet)
- [Fonctionnalités](#fonctionnalités)
- [Prérequis](#prérequis)
- [Installation et Utilisation](#installation-et-utilisation)
  - [Structure des Fichiers](#structure-des-fichiers)
  - [Exécution du Script](#exécution-du-script)
- [Configuration](#configuration)
  - [Fichiers de Configuration](#fichiers-de-configuration)
  - [Logiciels Optionnels](#logiciels-optionnels)
- [Journalisation](#journalisation)
- [Contribuer](#contribuer)
- [Auteur](#auteur)
- [Licence](#licence)

---

## À Propos du Projet

**KoesioPrep** est un script PowerShell conçu pour automatiser la configuration initiale des ordinateurs Windows fraîchement installés au sein de l'entreprise Koesio. L'objectif principal est de standardiser la préparation des postes clients, de réduire le temps d'intervention manuelle et d'assurer une configuration cohérente avant leur mise en service.

Ce projet est né du besoin d'optimiser les processus de déploiement et de garantir que chaque machine est prête à l'emploi avec les paramètres et logiciels essentiels définis par Koesio.

J'ai créé et fini ce projet a ma propre initiative durant mon temps libre pendant mon stage de 3e année afin de faire gagner du temps aux techniciens réseau de Koesio qui préparent les ordinateurs avant de les installer chez le client final.

---

## Fonctionnalités

Le script `KoesioPrep.ps1` réalise les actions suivantes :

*   **Configuration Utilisateur (Profil par Défaut et Utilisateur Actuel) :**
    *   Ajustement des paramètres de confidentialité (publicité, suggestions, suivi, etc.).
    *   Désactivation du Mode Jeu et de la Game Bar.
    *   Gestion des applications au démarrage (ex: OneDrive, Copilot).
*   **Configuration Système (HKLM) :**
    *   **Renommage de l'ordinateur :** Utilise le numéro de série de la machine (avec confirmation de l'opérateur).
    *   **BitLocker :** Désactivation et prévention de la réactivation automatique.
    *   **Alimentation :** Configuration des options de veille (disque, écran, ordinateur) sur "Jamais" et désactivation du démarrage rapide.
    *   **Mises à Jour Windows :**
        *   Activation de l'option "Obtenir des mises à jour pour d'autres produits Microsoft".
        *   Désactivation de l'Optimisation de la Distribution (peer-to-peer).
        *   Lancement de la recherche et de l'installation des mises à jour via le module `PSWindowsUpdate`.
    *   **Politiques Globales :** Désactivation de OneDrive et des optimisations de démarrage de Microsoft Edge.
*   **Installation de Logiciels :**
    *   **Logiciels par Défaut :** Installation silencieuse de Google Chrome, Mozilla Firefox, Adobe Acrobat Reader DC via Winget.
    *   **Logiciels Spécifiques au Constructeur :**
        *   Installation de Dell Command | Update pour les machines Dell, suivie d'un scan et d'une application automatique des mises à jour de pilotes/firmware.
        *   Installation de HP Support Assistant pour les machines HP.
    *   **Logiciels Optionnels :** Propose une liste de logiciels supplémentaires (ex: VLC, FortiClient VPN, OpenVPN, GoToAssist, suites Office via ODT) que l'opérateur peut choisir d'installer.
*   **Configuration des Logiciels Installés :**
    *   Application de configurations initiales pour Chrome (`master_preferences`) et Firefox (`policies.json`) pour skipper les écrans de premier lancement et définir des paramètres par défaut.
*   **Personnalisation du Bureau :**
    *   Suppression des raccourcis Microsoft Edge.
    *   Épinglage de Chrome, Firefox et Adobe Acrobat Reader à la barre des tâches pour les nouveaux profils utilisateurs via `LayoutModification.xml`.
*   **Journalisation :** Création d'un fichier de transcription détaillé pour chaque exécution du script.

---

## Prérequis

Avant d'exécuter le script, assurez-vous que les conditions suivantes sont remplies :

1.  **Système d'Exploitation :** Windows 10 ou Windows 11.
2.  **PowerShell :** Version 5.1 ou supérieure.
3.  **Droits Administrateur :** Le script doit impérativement être exécuté avec des privilèges d'administrateur.
4.  **Winget :** Le gestionnaire de paquets Winget doit être fonctionnel sur la machine cible. Il est généralement inclus dans les versions récentes de Windows.
5.  **Accès Internet :** Nécessaire pour le téléchargement des logiciels via Winget et pour les mises à jour Windows.
6.  **Module `PSWindowsUpdate` :** Si non présent, le script tentera de l'installer depuis la PowerShell Gallery (nécessite une connexion internet et la configuration de TLS 1.2 pour PowerShellGet).
7.  **Fichiers de Configuration (Optionnel mais Recommandé) :** Pour une personnalisation complète (Chrome, Firefox, barre des tâches), les fichiers de configuration associés doivent être présents.

---

## Installation et Utilisation

### Structure des Fichiers

Il est recommandé d'organiser les fichiers du projet comme suit :

KoesioPrep/
│
├── KoesioPrep.ps1 # Le script principal
├── LancerKoesioPrepAdmin.bat # (Optionnel) Batch pour lancer le .ps1 en admin
│
└───KoesioConfig/ # Dossier pour les fichiers de configuration
├── chrome_master_preferences.json # Configuration pour Google Chrome
├── firefox_policies.json # Configuration pour Mozilla Firefox
└── TaskbarLayout.xml # Configuration de l'épinglage à la barre des tâches
└───ODT_Office/ # (Exemple pour les installations Office)
├── setup.exe # Outil de Déploiement d'Office
├── M365Config.xml # Fichier de configuration pour Microsoft 365
└── OfficeLTSCConfig.xml # Fichier de configuration pour Office LTSC



### Exécution du Script

1.  Clonez ou téléchargez ce dépôt sur la machine cible ou sur un support amovible.
2.  Assurez-vous que la structure des fichiers (notamment le dossier `KoesioConfig` et son contenu) est correcte par rapport à l'emplacement de `KoesioPrep.ps1`.
3.  **Exécutez `KoesioPrep.ps1` avec des droits d'administrateur.**
    *   **Méthode 1 (Recommandée) :** Utilisez le fichier `LancerKoesioPrepAdmin.bat` (s'il est fourni) qui se chargera de demander l'élévation de privilèges.
    *   **Méthode 2 :** Ouvrez une session PowerShell en tant qu'administrateur, naviguez vers le répertoire du script, puis exécutez :
        ```powershell
        Set-ExecutionPolicy Bypass -Scope Process -Force
        .\KoesioPrep.ps1
        ```
4.  Suivez les invites affichées par le script (ex: confirmation pour le renommage de l'ordinateur, sélection des logiciels optionnels).
5.  Une fois le script terminé, un redémarrage sera probablement proposé ou requis.

---

## Configuration

### Fichiers de Configuration

Certains aspects du script sont personnalisables via des fichiers externes placés dans le sous-dossier `KoesioConfig` :

*   **`chrome_master_preferences.json` :** Permet de définir les paramètres par défaut de Google Chrome lors du premier lancement (page d'accueil, suppression des invites, etc.).
*   **`firefox_policies.json` :** Permet de définir les politiques de Mozilla Firefox (page d'accueil, désactivation de la télémétrie, etc.).
*   **`TaskbarLayout.xml` :** Définit les applications à épingler par défaut à la barre des tâches pour les nouveaux profils utilisateurs. Modifiez ce fichier XML pour changer les applications épinglées.

### Logiciels Optionnels

Au lancement, le script propose une liste de logiciels optionnels. Cette liste est définie directement dans le script au sein du tableau `$OptionalSoftwareList`. Pour ajouter ou modifier des logiciels :

*   **Pour les logiciels installables via Winget :** Ajoutez un nouvel objet `[PSCustomObject]` au tableau avec un `Index`, `Name` (nom affiché), et `WingetId` (ID Winget exact).
*   **Pour les logiciels nécessitant une installation personnalisée (ex: suites Office via ODT) :**
    *   Marquez l'objet avec `NeedsCustomInstall = $true` et utilisez un `WingetId` descriptif (ex: `"Custom_M365"`).
    *   Implémentez la logique d'installation correspondante dans la section `switch ($SoftwareToInstall.WingetId)` du script. Cela impliquera généralement d'appeler `setup.exe` de l'Outil de Déploiement d'Office avec le fichier de configuration XML approprié.
    *   Placez les installeurs (comme l'ODT) et les fichiers de configuration XML dans un sous-dossier accessible (par exemple, `KoesioConfig\ODT_Office\`).

---

## Journalisation

À chaque exécution, le script `KoesioPrep.ps1` crée un fichier de transcription détaillé. Ce fichier journal est stocké dans un sous-dossier `KoesioPrepLog` (créé au même niveau que le script).
Le nom du fichier journal inclut la date et l'heure de l'exécution (ex: `KoesioPrep_YYYYMMDD_HHMMSS.log`).

Consultez ces journaux pour diagnostiquer les problèmes ou vérifier les actions effectuées.

---

## Contribuer

Les contributions visant à améliorer ce script sont les bienvenues. Vous pouvez :
*   Signaler des bugs ou proposer des améliorations via les Issues GitHub.
*   Soumettre des Pull Requests avec vos modifications.

Veuillez suivre les bonnes pratiques de codage et documenter clairement vos changements.

---

## Auteur

*   **Quentin Chaillou** - *Développement initial et maintenance* - Koesio

---

## Licence

Tous droits réservés

---
