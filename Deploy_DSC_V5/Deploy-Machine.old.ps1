<#
.SYNOPSIS
Orchestre le déploiement et la configuration d'une machine Windows via DSC.
Inclut la gestion BitLocker (optionnelle), la sélection de logiciels,
le renommage, la jonction au domaine et l'installation de paquets via Chocolatey.

.DESCRIPTION
Ce script guide l'utilisateur à travers plusieurs phases :
1. Préparation : Gestion optionnelle de la suspension/désactivation de BitLocker.
2. Sélection Logiciels : Choix interactif des logiciels optionnels à installer via Chocolatey.
3. Application DSC : Génère le fichier MOF et applique la configuration DSC définie
   dans MachineConfiguration.ps1 (nom, domaine, fonctionnalités, Chocolatey, logiciels).
4. Vérification (Basique) : Affiche l'état final de la configuration DSC.

Nécessite les modules DSC : ComputerManagementDsc, ChocolateyDsc.
Doit être exécuté avec des privilèges administrateur.

.PARAMETER TargetNode
Nom ou adresse IP de la machine cible. Par défaut, la machine locale.

.PARAMETER NewComputerName
Nouveau nom à attribuer à la machine. Si non fourni, le nom actuel est conservé.

.PARAMETER DomainName
Nom de domaine Active Directory à joindre. Laisser vide pour ne pas joindre de domaine.

.PARAMETER OUPath
Chemin LDAP de l'Unité d'Organisation où placer le compte ordinateur.
Exemple : "OU=Workstations,DC=mondomaine,DC=local"
Requis si DomainName est spécifié.

.PARAMETER AdminCred
Credentials d'un compte ayant les droits pour joindre la machine au domaine
et potentiellement effectuer des tâches administratives locales (si nécessaire).
Utiliser (Get-Credential) pour une saisie sécurisée.

.PARAMETER DscModulesPath
Chemin vers les modules DSC personnalisés ou additionnels si nécessaire.

.PARAMETER SkipBitLockerDecryption
Si $true, ignore les étapes de suspension/désactivation de BitLocker.

.PARAMETER SkipReboot
Si $true, configure le LCM pour ne pas redémarrer automatiquement après la configuration.
Le redémarrage peut toujours être nécessaire pour appliquer certains changements (nom/domaine).

.PARAMETER LogPath
Chemin complet du fichier où enregistrer les logs. Par défaut dans le dossier du script.

.EXAMPLE
.\Deploy-Machine.ps1 -NewComputerName "NEWPC-01" -DomainName "Mondomaine.local" -OUPath "OU=Workstations,DC=mondomaine,DC=local" -AdminCred (Get-Credential) -Verbose

.EXAMPLE
.\Deploy-Machine.ps1 -SkipBitLockerDecryption -Verbose

.NOTES
Auteur : Votre Nom / Organisation
Date   : YYYY-MM-DD
Version: 1.1 - Correction erreurs et décompression code.
Ensure ChocolateyDsc module is installed: Install-Module -Name ChocolateyDsc -Force
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$false)]
    [string]$TargetNode = $env:COMPUTERNAME,

    [Parameter(Mandatory=$false)]
    [string]$NewComputerName,

    [Parameter(Mandatory=$false)]
    [string]$DomainName,

    [Parameter(Mandatory=$false)]
    [string]$OUPath,

    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$AdminCred,

    [Parameter(Mandatory=$false)]
    [string]$DscModulesPath,

    [Parameter(Mandatory=$false)]
    [switch]$SkipBitLockerDecryption,

    [Parameter(Mandatory=$false)]
    [switch]$SkipReboot,

    [Parameter(Mandatory=$false)]
    [string]$LogPath,
	
	[switch]$SkipWindowsUpdate

)
# Obtenir le répertoire où se trouve le script en cours d'exécution
$ScriptBaseDir = $PSScriptRoot # $PSScriptRoot est le dossier contenant Deploy-Machine.ps1 (e.g., D:\Deploy_DSC_V5)

# Définir le nom du sous-dossier pour les logs
$LogSubDirName = 'Logs' # Le nom du dossier où iront les logs

# Construire le chemin complet du répertoire des logs
$LogDir = Join-Path -Path $ScriptBaseDir -ChildPath $LogSubDirName

# S'assurer que le répertoire Logs existe (très important !)
if (-not (Test-Path -Path $LogDir -PathType Container)) {
    # Afficher un message à la console car le logging fichier n'est pas encore prêt
    Write-Host "INFO: Création du répertoire Logs : $LogDir"
    try {
        # Créer le répertoire s'il n'existe pas
        New-Item -Path $LogDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
    } catch {
        # Erreur critique si on ne peut pas créer le dossier log
        Write-Host "ERREUR CRITIQUE: Impossible de créer le répertoire Logs '$LogDir'. Vérifiez les permissions. Erreur: $($_.Exception.Message)" -ForegroundColor Red
        # On ne peut pas continuer sans pouvoir logger, donc on arrête.
        Exit 1
    }
}

# Construire le nom du fichier log dynamique
$Timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
# Utiliser $env:COMPUTERNAME par défaut. Si vous utilisez un paramètre $TargetNode, remplacez $env:COMPUTERNAME par $TargetNode
$ComputerNameForLog = $env:COMPUTERNAME # Ou $TargetNode si vous l'utilisez
$LogFileName = "Deploy-Machine_$($ComputerNameForLog)_$Timestamp.log"

# Construire le chemin complet du fichier log DANS le dossier Logs
# !! C'est LA variable que la fonction Write-Log utilisera !!
# Utiliser $Script: ou $Global: pour s'assurer qu'elle est accessible dans la fonction
$Script:LogPath = Join-Path -Path $LogDir -ChildPath $LogFileName

# --- Fin de la définition du chemin du fichier Log ---


#region Functions
#==============================================================================
# Fonction de Logging améliorée
#==============================================================================
function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,

        [Parameter(Mandatory=$false)]
        [ValidateSet('INFO', 'WARN', 'ERROR', 'STEP', 'SUCCESS', 'DEBUG')]
        [string]$Level = 'INFO',

        [Parameter(Mandatory=$false)]
        [int]$Indent = 0 # Niveau d'indentation
    )

    $timeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $indentSpaces = " " * ($Indent * 4) # 4 espaces par niveau d'indentation

    # Définir couleur en fonction du niveau
    $color = switch ($Level) {
        'WARN'    { 'Yellow' }
        'ERROR'   { 'Red' }
        'STEP'    { 'Cyan' }
        'SUCCESS' { 'Green' }
        'DEBUG'   { 'DarkGray'}
        default   { 'White' } # INFO
    }

    $logEntry = "$timeStamp [$Level] $($indentSpaces)$Message"

    # Écrire sur la console avec couleur
    Write-Host $logEntry -ForegroundColor $color

    # Ajouter au fichier log
    try {
        # Utilise la variable $Script:LogPath définie plus haut
        Add-Content -Path $Script:LogPath -Value $logEntry -ErrorAction Stop
    } catch {
        # Affiche un avertissement à la console si l'écriture fichier échoue
        Write-Warning "Impossible d'écrire dans le fichier log '$($Script:LogPath)': $($_.Exception.Message)"
    }
}
#endregion Functions

#region Initialisation & Prérequis
#==============================================================================
# Initialisation du Logging et Vérifications Préliminaires
#==============================================================================
# Définir le chemin du log par défaut si non fourni par l'utilisateur
if ([string]::IsNullOrWhiteSpace($LogPath)) {
    # Vérifier si PSScriptRoot est défini (devrait l'être si le script est exécuté correctement)
    if ($PSScriptRoot) {
        $LogPath = Join-Path $PSScriptRoot "Deploy-Machine_$($env:COMPUTERNAME)_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    } else {
        # Fallback si PSScriptRoot est vide (ex: exécution en sélection)
        Write-Warning "Impossible de déterminer le dossier du script ($PSScriptRoot est vide). Le log sera créé dans le dossier courant ($PWD)."
        $LogPath = Join-Path $PWD "Deploy-Machine_$($env:COMPUTERNAME)_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    }
     Write-Host "INFO: LogPath non fourni, utilisation du chemin par défaut : $LogPath" -ForegroundColor Gray
}
Clear-Host
Write-Host "================================================================================" -ForegroundColor Magenta
Write-Host "=                 Début du Script de Déploiement Machine                     =" -ForegroundColor Magenta
Write-Host "================================================================================" -ForegroundColor Magenta
Write-Log "Script démarré." 'STEP' 0
Write-Log "Fichier Log: $Script:LogPath" 'INFO' 1

# Vérifier si exécuté en tant qu'administrateur
$currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log "Ce script nécessite des privilèges administrateur." 'ERROR' 0
    Write-Log "Veuillez relancer PowerShell en tant qu'Administrateur." 'ERROR' 1
    Exit 1
} else {
    Write-Log "Vérification des privilèges administrateur: OK" 'SUCCESS' 1
}

# Validation des paramètres
if ($DomainName -and !$AdminCred) {
    Write-Log "Le paramètre -AdminCred est requis pour joindre le domaine '$DomainName'." 'ERROR' 0
    Exit 1
}
if ($DomainName -and !$OUPath) {
    Write-Log "Le paramètre -OUPath est requis pour joindre le domaine '$DomainName'." 'ERROR' 0
    # Alternative: Définir une OU par défaut si souhaité
    # $OUPath = "OU=Computers,DC=mondomaine,DC=local" # Exemple
    # Write-Log "OUPath non fourni, utilisation de l'OU par défaut : $OUPath" 'WARN' 1
    Exit 1
}

# --- Option de renommage par numéro de série ---
Write-Log "Vérification du numéro de série pour renommage optionnel..." 'INFO' 1
$SerialNumber = $null
try {
    # Méthode standard pour obtenir le numéro de série
    $SerialNumber = Get-CimInstance -ClassName Win32_BIOS | Select-Object -ExpandProperty SerialNumber -ErrorAction Stop
    Write-Log "Numéro de série détecté : '$SerialNumber'" 'DEBUG' 2

    # Vérification basique de la validité (non vide, pas une valeur générique commune)
    if ([string]::IsNullOrWhiteSpace($SerialNumber) -or $SerialNumber -match '^(Default string|To be filled by O.E.M.|Not Available|None|System Serial Number)$') {
        Write-Log "Numéro de série détecté non valide ou générique ('$SerialNumber'). L'option de renommage ne sera pas proposée." 'WARN' 1
        $SerialNumber = $null # Invalider pour ne pas le proposer
    }
} catch {
    Write-Log "Impossible de récupérer le numéro de série via Win32_BIOS: $($_.Exception.Message)" 'WARN' 1
    $SerialNumber = $null # Assurer qu'il est null en cas d'erreur
}

# Si un numéro de série valide a été trouvé ET qu'aucun nom n'a été forcé par paramètre
if ($SerialNumber -and [string]::IsNullOrWhiteSpace($NewComputerName)) {
    Write-Host ""
    Write-Host "Un numéro de série valide a été détecté: '$SerialNumber'" -ForegroundColor Cyan
    $renameChoice = ''
   while ($true) { # Boucle infinie, on sortira avec 'break'
        # Modifiez le prompt pour indiquer le défaut
        $rawInput = Read-Host "Voulez-vous utiliser ce numéro de série comme nouveau nom d'ordinateur ? ([O]/N)"

        if ([string]::IsNullOrEmpty($rawInput)) {
            # Cas où l'utilisateur appuie juste sur Entrée
            $renameChoice = 'o'
            break # Sortir de la boucle, choix valide (par défaut)
        } elseif ($rawInput.ToLower().Trim() -eq 'o') {
            $renameChoice = 'o'
            break # Sortir de la boucle, choix valide ('o')
        } elseif ($rawInput.ToLower().Trim() -eq 'n') {
            $renameChoice = 'n'
            break # Sortir de la boucle, choix valide ('n')
        } else {
            # Entrée invalide, on reste dans la boucle et on redemande
            Write-Warning "Réponse non valide. Veuillez entrer 'O', 'N', ou appuyer sur Entrée pour accepter le défaut ('O')."
        }
    }
    if ($renameChoice -eq 'o') {
        $NewComputerName = $SerialNumber
        Write-Log "L'utilisateur a choisi de renommer l'ordinateur avec le numéro de série: '$NewComputerName'" 'INFO' 1
        Write-Host "Le nouveau nom sera '$NewComputerName'." -ForegroundColor Green
    } else {
        Write-Log "L'utilisateur a choisi de ne PAS utiliser le numéro de série pour le renommage." 'INFO' 1
    }
} elseif (-not [string]::IsNullOrWhiteSpace($NewComputerName)) {
     Write-Log "Un nom d'ordinateur ('$NewComputerName') a été fourni via les paramètres, l'option de renommage par numéro de série est ignorée." 'INFO' 1
} else {
    # Cas où aucun S/N valide n'a été trouvé et aucun nom n'a été fourni
    Write-Log "Aucun numéro de série valide trouvé et aucun nom fourni, le nom actuel sera conservé." 'INFO' 1
}
Write-Host ""

# Définir le nom d'ordinateur cible pour DSC (si non renommé, utilise le nom actuel)
$TargetComputerNameForDSC = if ([string]::IsNullOrWhiteSpace($NewComputerName)) { $TargetNode } else { $NewComputerName }
Write-Log "Nom Cible pour DSC: $TargetComputerNameForDSC" 'INFO' 1
if ($DomainName) {
    Write-Log "Jonction au Domaine: $DomainName" 'INFO' 1
    Write-Log "Chemin OU: $OUPath" 'INFO' 1
} else {
    Write-Log "Jonction au domaine désactivée." 'INFO' 1
}

# Vérifier existence module cChoco (important pour la suite)
Write-Log "Vérification du module DSC cChoco..." 'INFO' 1
$chocoModule = Get-Module -ListAvailable -Name cChoco
if (-not $chocoModule) {
	Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
	Write-Log "Exécution de: Install-Module -Name cChoco -Force" 'INFO' 2
    # Installe le module 'cChoco' depuis la PowerShell Gallery
	Install-Module -Name cChoco -Force -ErrorAction Stop -Scope CurrentUser
    Write-Log "Module PowerShell 'cChoco' installé avec succès." 'SUCCESS' 1
} else {
    Write-Log "Module DSC 'cChoco' trouvé: $($chocoModule.Version)" 'SUCCESS' 1
}
# Vérifier existence module ComputerManagementDsc
Write-Log "Vérification du module DSC ComputerManagementDsc..." 'INFO' 1
$compMgmtModule = Get-Module -ListAvailable -Name ComputerManagementDsc
if (-not $compMgmtModule) {
     Write-Log "Module DSC 'ComputerManagementDsc' non trouvé. Tentative d'installation automatique..." 'WARN' 1
     try {
        Write-Log "Activation de TLS 1.2 pour l'installation..." 'INFO' 2
        # Assurer TLS 1.2
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        Write-Log "Exécution de: Install-Module -Name ComputerManagementDsc -Force" 'INFO' 2
        Install-Module -Name ComputerManagementDsc -Force -ErrorAction Stop -Scope AllUsers # Changé AllUsers a CurrentUser pour éviter problème de droit potentiel et simplifier
        Write-Log "Module DSC 'ComputerManagementDsc' installé avec succès." 'SUCCESS' 1

        # Optionnel : Recharger
        # $compMgmtModule = Get-Module -ListAvailable -Name ComputerManagementDsc
        # if (-not $compMgmtModule) { throw "Le module ComputerManagementDsc n'a pas pu être chargé après l'installation." }

     } catch {
        Write-Log "AVERTISSEMENT: Échec de l'installation automatique du module 'ComputerManagementDsc'." 'WARN' 1
        Write-Log "Erreur PowerShell : $($_.Exception.Message)" 'WARN' 2
        Write-Log "Certaines opérations (nom machine/domaine) pourraient échouer." 'WARN' 2
        # On n'arrête PAS le script ici, comme c'était un avertissement avant.
     }
} else {
    Write-Log "Module DSC 'ComputerManagementDsc' trouvé: $($compMgmtModule.Version)" 'SUCCESS' 1
}
# ==================================================
# VÉRIFICATION EXPLICITE que cChoco est disponible AVANT utilisation
# ==================================================
Write-Log "Vérification finale de la disponibilité du module 'cChoco'..." 'INFO' 1
$cChocoModuleCheck = Get-Module -ListAvailable -Name cChoco -ErrorAction SilentlyContinue # On vérifie s'il est listé comme dispo

if ($cChocoModuleCheck) {
    Write-Log "Module 'cChoco' version $($cChocoModuleCheck.Version) est bien disponible pour utilisation." 'SUCCESS' 1

    # Tentative d'importation pour être sûr que les ressources sont chargeables (optionnel mais recommandé)
    Write-Log "Tentative de pré-chargement du module 'cChoco'..." 'DEBUG' 2
    try {
        Import-Module -Name cChoco -Force -ErrorAction Stop
        Write-Log "Module 'cChoco' chargé avec succès dans la session." 'DEBUG' 2
    } catch {
        Write-Log "ERREUR CRITIQUE: Le module 'cChoco' est listé mais n'a pas pu être importé !" 'ERROR' 1
        Write-Log "Erreur PowerShell: $($_.Exception.Message)" 'ERROR' 2
        Write-Log "Le script ne peut pas continuer sans le module cChoco." 'ERROR' 1
        Exit 1 # Arrêt nécessaire
    }

} else {
    Write-Log "ERREUR CRITIQUE: Le module 'cChoco' n'a pas été trouvé après la tentative d'installation/vérification !" 'ERROR' 1
    Write-Log "Le script ne peut pas continuer sans le module cChoco." 'ERROR' 1
    # Le script devrait s'arrêter ici car la suite dépend de cChoco
    Exit 1
}

Write-Log "Vérification finale de la disponibilité du module 'cChoco'..." 'INFO' 1
$cChocoModuleCheck = Get-Module -ListAvailable -Name cChoco -ErrorAction SilentlyContinue

if ($cChocoModuleCheck) {
    Write-Log "Module 'cChoco' version $($cChocoModuleCheck.Version) est bien disponible pour utilisation." 'SUCCESS' 1
    Write-Log "Tentative de pré-chargement du module 'cChoco' dans la session..." 'DEBUG' 2
    try {
        Import-Module -Name cChoco -Force -ErrorAction Stop
        Write-Log "Module 'cChoco' chargé avec succès dans la session." 'SUCCESS' 2 # Changé en SUCCESS car c'est une étape clé
    } catch {
        Write-Log "ERREUR CRITIQUE: Le module 'cChoco' est listé mais n'a pas pu être importé !" 'ERROR' 1
        Write-Log "Erreur PowerShell: $($_.Exception.Message)" 'ERROR' 2
        Write-Log "Le script ne peut pas continuer sans le module cChoco." 'ERROR' 1
        Exit 1
    }
} else {
    Write-Log "ERREUR CRITIQUE: Le module 'cChoco' n'a pas été trouvé après la tentative d'installation/vérification !" 'ERROR' 1
    Write-Log "Le script ne peut pas continuer sans le module cChoco." 'ERROR' 1
    Exit 1
}
#endregion Initialisation & Prérequis

#region Phase 1: Gestion BitLocker
#==============================================================================
# Phase 1: Gestion BitLocker (Optionnel)
#==============================================================================
Write-Host "`n--------------------------------------------------------------------------------" -ForegroundColor DarkCyan
Write-Host "-                 Phase 1: Gestion BitLocker (Optionnelle)                   -" -ForegroundColor DarkCyan
Write-Host "--------------------------------------------------------------------------------`n" -ForegroundColor DarkCyan

if (-not $SkipBitLockerDecryption) {
    Write-Log "Phase 1: Démarrage de la gestion BitLocker..." 'STEP' 0
    try {
        Write-Log "Importation du module BitLocker..." 'INFO' 1
        Import-Module BitLocker -ErrorAction Stop
        Write-Log "Module BitLocker importé." 'SUCCESS' 1

        $volumes = Get-BitLockerVolume | Where-Object { $_.ProtectionStatus -ne 'Off' }

        if ($volumes) {
            Write-Log "Détection de $($volumes.Count) volume(s) BitLocker actif(s)." 'INFO' 1
            foreach ($volume in $volumes) {
                $mountPoint = $volume.MountPoint
                Write-Log "Traitement du volume : $mountPoint (Protection: $($volume.ProtectionStatus))" 'INFO' 2

                # Étape 1: Suspendre la protection si elle est active ('On')
                if ($volume.ProtectionStatus -eq 'On') {
                    Write-Log "Tentative de suspension de la protection pour $mountPoint..." 'INFO' 3
                    try {
                        Suspend-BitLocker -MountPoint $mountPoint -RebootCount 0 -ErrorAction Stop
                        Write-Log "Protection BitLocker suspendue pour $mountPoint." 'SUCCESS' 3
                    } catch {
                        Write-Log ("Échec de la suspension de la protection pour {0}: {1}" -f $mountPoint, $_.Exception.Message) 'WARN' 3
                    }
                }

                # Étape 2: Démarrer le déchiffrement (désactivation)
                Write-Log "Tentative de démarrage du déchiffrement (Disable-Bitlocker) pour $mountPoint..." 'INFO' 3
                try {
                    Disable-BitLocker -MountPoint $mountPoint -ErrorAction Stop
                    Write-Log "Déchiffrement initié pour $mountPoint. Cela peut prendre du temps en arrière-plan." 'SUCCESS' 3
                    Write-Log "Utilisez 'Get-BitLockerVolume' pour suivre la progression." 'INFO' 4
                } catch {
                    # Gérer l'erreur spécifique si le déchiffrement est déjà en cours
                    if ($_.Exception.Message -like "*decryption is already in progress*") {
                         Write-Log "Le déchiffrement est déjà en cours pour $mountPoint." 'INFO' 3
                    } else {
                        Write-Log ("ERREUR lors de la tentative de désactivation de BitLocker pour {0}: {1}" -f $mountPoint, $_.Exception.Message) 'ERROR' 3
                    }
                }
            } # Fin foreach volume

            # Étape 3: Empêcher le chiffrement automatique des périphériques (PreventDeviceEncryption)
            Write-Log "Configuration du registre pour empêcher le chiffrement automatique (PreventDeviceEncryption)..." 'INFO' 2
            try {
                $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\BitLocker"
                if (-not (Test-Path $registryPath)) {
                    Write-Log "Création de la clé de registre BitLocker..." 'INFO' 3
                    New-Item -Path $registryPath -Force | Out-Null
                }
                Set-ItemProperty -Path $registryPath -Name "PreventDeviceEncryption" -Value 1 -Type DWord -Force -ErrorAction Stop
                Write-Log "Clé de registre 'PreventDeviceEncryption' configurée avec succès." 'SUCCESS' 2
            } catch {
                Write-Log ("ERREUR lors de la configuration de la clé de registre BitLocker: {0}" -f $_.Exception.Message) 'ERROR' 2
            }

        } else {
            Write-Log "Aucun volume avec BitLocker actif détecté." 'SUCCESS' 1
        }

    } catch {
        Write-Log ("ERREUR globale lors de la gestion BitLocker: {0}" -f $_.Exception.Message) 'ERROR' 1
        Write-Log "Le script continue, mais BitLocker n'a peut-être pas été géré correctement." 'WARN' 2
    }
    Write-Log "Phase 1: Gestion BitLocker terminée." 'STEP' 0
} else {
    Write-Log "Phase 1: Gestion BitLocker ignorée (option -SkipBitLockerDecryption utilisée)." 'INFO' 0
}
#endregion Phase 1: Gestion BitLocker

#region Phase 2: Sélection Logiciels Optionnels
#==============================================================================
# Phase 2: Sélection Logiciels Optionnels (pour DSC)
#==============================================================================
Write-Host "`n--------------------------------------------------------------------------------" -ForegroundColor DarkCyan
Write-Host "-              Phase 2: Sélection Logiciels Optionnels (pour DSC)              -" -ForegroundColor DarkCyan
Write-Host "--------------------------------------------------------------------------------`n" -ForegroundColor DarkCyan

# Définir la liste des logiciels optionnels disponibles
# Assurez-vous que les IDs correspondent bien aux packages Choco existants !
$OptionalSoftwareList = @{
    1 = @{Name='MS Office 365 Business'; Type='Choco'; Id='office365business'; Note="Suite Office complète (Word, Excel, PP, Outlook, Teams...). Nécessite licence M365 Business."}
    2 = @{Name='VLC Media Player';       Type='Choco'; Id='vlc';               Note="Lecteur multimédia polyvalent."}
    3 = @{Name='Notepad++';              Type='Choco'; Id='notepadplusplus.install'; Note="Éditeur de texte avancé pour développeurs/adminsys."}
    4 = @{Name='7-Zip';                  Type='Choco'; Id='7zip.install';      Note="Utilitaire de compression/décompression (zip, 7z, rar...)."}
    # --- Ajoutez ou modifiez d'autres logiciels ici ---
    # 8 = @{Name='Autre Logiciel';      Type='Choco'; Id='autre.id.choco';   Note="Description..."}
    # 9 = @{Name='Encore un Autre';     Type='Choco'; Id='autre.package';    Note="Avec une note."}
}

# Afficher les options à l'utilisateur
Write-Log "Affichage des options logicielles disponibles..." 'INFO' 1
Write-Host "Sélectionnez les logiciels OPTIONNELS à installer (via DSC Choco):" -ForegroundColor Cyan
$OptionalSoftwareList.GetEnumerator() | Sort-Object Name | ForEach-Object {
    $item = $_.Value
    # Le format -f permet un alignement plus facile des colonnes
    Write-Host (" {0,2}: {1,-30} ({2}) - {3}" -f $_.Name, $item.Name, $item.Id, $item.Note)
}

# Récupérer le choix de l'utilisateur
$SelectedSoftwareIds = @() # Initialiser comme tableau vide
$loop = $true
while($loop) {
    $choice = Read-Host "`nChoix (numéros séparés par virgule, ex: 1,4,7 ou Entrée pour aucun)"
    if ([string]::IsNullOrWhiteSpace($choice)) {
        Write-Log "Aucun logiciel optionnel sélectionné par l'utilisateur." 'INFO' 1
        $loop = $false
    } else {
        $choices = $choice -split ',' | ForEach-Object { $_.Trim() }
        $validChoice = $true # Présumer valide jusqu'à preuve du contraire
        $tempSelectedIds = @() # Stockage temporaire pour cette tentative

        foreach ($c in $choices) {
            if ($c -match '^\d+$' -and $OptionalSoftwareList.ContainsKey([int]$c)) {
                $selectedItem = $OptionalSoftwareList[[int]$c]
                # Vérifier si le type est 'Choco' (seul type géré ici pour DSC)
                if ($selectedItem.Type -eq 'Choco') {
                    $tempSelectedIds += $selectedItem.Id
                    # Pas de log ici pour éviter la répétition si l'utilisateur se trompe et recommence
                } else {
                    Write-Warning "Logiciel '$($selectedItem.Name)' ignoré car son type '$($selectedItem.Type)' n'est pas géré par DSC dans ce script."
                    # On pourrait invalider le choix ici si on veut être strict : $validChoice = $false; break
                }
            } else {
                Write-Warning "Choix invalide : '$c'. Veuillez entrer des numéros VALIDES de la liste, séparés par des virgules."
                $validChoice = $false
                break # Sortir de la boucle foreach des choix pour redemander
            }
        } # Fin foreach ($c in $choices)

        if ($validChoice) {
            $SelectedSoftwareIds = $tempSelectedIds | Select-Object -Unique # Stocker les IDs valides et uniques
            $loop = $false # Sortir de la boucle while principale, choix valides
            # Loguer les sélections finales
            if ($SelectedSoftwareIds.Count -gt 0) {
                Write-Log "Logiciels optionnels sélectionnés par l'utilisateur:" 'INFO' 1
                foreach ($id in $SelectedSoftwareIds) {
                     $name = ($OptionalSoftwareList.GetEnumerator() | Where-Object {$_.Value.Id -eq $id}).Value.Name
                     Write-Log "- $name (ID: $id)" 'INFO' 2
                }
            }
        }
        # Si choix invalide ($validChoice est false), la boucle while recommence
    }
}

Write-Log "Phase 2 terminée. IDs Choco optionnels sélectionnés: $($SelectedSoftwareIds -join ', ')" 'STEP' 0
#endregion Phase 2: Sélection Logiciels Optionnels

#region Phase 3: Préparation et Appel DSC
#==============================================================================
# Phase 3: Préparation des Données et Appel de la Configuration DSC
#==============================================================================
Write-Host "`n--------------------------------------------------------------------------------" -ForegroundColor DarkCyan
Write-Host "-                Phase 3: Préparation et Appel de la DSC                       -" -ForegroundColor DarkCyan
Write-Host "--------------------------------------------------------------------------------`n" -ForegroundColor DarkCyan
Write-Log "Phase 3: Démarrage de la préparation et de l'appel DSC..." 'STEP' 0

# Définir les données de configuration pour DSC
# Ces données seront passées à MachineConfiguration.ps1
$ConfigurationData = @{
    AllNodes = @(
        @{
            # --- Données spécifiques au nœud ---
            ComputerName                 = $TargetComputerNameForDSC # Nouveau nom ou nom actuel
            OptionalChocoPackages        = $SelectedSoftwareIds     # Tableau des IDs Choco optionnels
            # Définir les packages Choco 'Core' (toujours installés)
            CoreChocoPackages            = @('googlechrome', 'firefox', 'adobereader', 'notepadplusplus.install') # Exemple, adaptez selon vos besoins
            # Définir les fonctionnalités Windows à activer
            WindowsFeaturesToEnsure      = @('NetFx3') # Exemple, adaptez
            # Contrôler le redémarrage via le LCM
            RebootNodeIfNeeded           = (-not $SkipReboot)
        }
        # Ajoutez d'autres nœuds ici si vous gérez plusieurs machines en parallèle
        # @{ NodeName = "Server02"; ... }
    )
    # --- Données non spécifiques à un nœud (si nécessaire) ---
    # NonNodeData = @{ GlobalSetting = "Value" }
}

Write-Log "Données de configuration préparées :" 'DEBUG' 1
Write-Log ($ConfigurationData | Out-String) 'DEBUG' 2 # Afficher les données pour le débogage

# Définir le chemin de sortie pour le fichier MOF
$MofOutputPath = Join-Path $PSScriptRoot "DSC_MOF"
Write-Log "Chemin de sortie pour le MOF: $MofOutputPath" 'INFO' 1

# Importer la définition de la configuration DSC depuis le fichier .ps1
Write-Log "Importation de la définition de configuration depuis .\MachineConfiguration.ps1..." 'INFO' 1
try {
    . (Join-Path $PSScriptRoot "MachineConfiguration.ps1") -ErrorAction Stop
    Write-Log "Définition de configuration importée avec succès." 'SUCCESS' 1
} catch {
    Write-Log "ERREUR critique lors de l'importation de MachineConfiguration.ps1:" 'ERROR' 1
    Write-Log $_.Exception.Message 'ERROR' 2
    Write-Log $_.ScriptStackTrace 'ERROR' 2
    Exit 1
}

# Générer le fichier MOF
Write-Log "Génération du fichier MOF..." 'INFO' 1
$nodeData = $ConfigurationData.AllNodes[0]

Write-Log "Paramètres pour MachineConfiguration:" 'DEBUG' 2
Write-Log "  ComputerName            : $($nodeData.ComputerName)" 'DEBUG' 3
Write-Log "  OptionalChocoPackages   : $($nodeData.OptionalChocoPackages -join ', ')" 'DEBUG' 3
Write-Log "  CoreChocoPackages       : $($nodeData.CoreChocoPackages -join ', ')" 'DEBUG' 3
Write-Log "  WindowsFeaturesToEnsure : $($nodeData.WindowsFeaturesToEnsure -join ', ')" 'DEBUG' 3
Write-Log "  RebootNodeIfNeeded      : $($nodeData.RebootNodeIfNeeded)" 'DEBUG' 3
Write-Log "  OutputPath              : $MofOutputPath" 'DEBUG' 3

try {
    # Utiliser le splatting pour passer les paramètres proprement
    $MachineConfigParams = @{
        ComputerName            = $nodeData.ComputerName
        OptionalChocoPackages   = $nodeData.OptionalChocoPackages
        CoreChocoPackages       = $nodeData.CoreChocoPackages
        WindowsFeaturesToEnsure = $nodeData.WindowsFeaturesToEnsure
        RebootNodeIfNeeded      = $nodeData.RebootNodeIfNeeded
        OutputPath              = $MofOutputPath
        ErrorAction             = 'Stop' # Important pour attraper les erreurs de compilation
    }
    if ($VerbosePreference -eq 'Continue') {
        $MachineConfigParams.Add('Verbose', $true)
    }

    # Appeler MachineConfiguration avec les paramètres individuels via splatting
    MachineConfiguration @MachineConfigParams

    Write-Log "Appel à MachineConfiguration terminé." 'DEBUG' 2

} catch {
    Write-Log "ERREUR critique lors de la génération du MOF via MachineConfiguration:" 'ERROR' 1
    Write-Log $_.Exception.Message 'ERROR' 2
    Write-Log $_.ScriptStackTrace 'ERROR' 2
    # Il est crucial de s'arrêter ici si le MOF ne peut être généré
    Exit 1
}


# Vérifier si le MOF a été généré - IMPORTANT: Utiliser le nom correct!
# $TargetNode peut être différent de $nodeData.ComputerName si -NewComputerName a été utilisé.
$MofFile = Join-Path $MofOutputPath "$($nodeData.ComputerName).mof" # Utiliser le nom passé à la config
if (Test-Path $MofFile) {
    Write-Log "Fichier MOF généré avec succès : $MofFile" 'SUCCESS' 1
} else {
    Write-Log "ERREUR critique : Le fichier MOF '$MofFile' n'a pas été trouvé après la compilation." 'ERROR' 1
    Write-Log "Vérifiez les erreurs lors de l'étape 'MachineConfiguration'. Le nom attendu est basé sur le paramètre ComputerName fourni." 'ERROR' 2
    Exit 1
}
$GeneratedMofFileName = "$($nodeData.ComputerName).mof"
$MofFileGeneratedPath = Join-Path $MofOutputPath $GeneratedMofFileName

if (Test-Path $MofFileGeneratedPath) {
    Write-Log "Fichier MOF généré avec succès : $MofFileGeneratedPath" 'SUCCESS' 1

    # Nom du MOF attendu par Start-DscConfiguration pour une application locale
    $ExpectedMofFileNameForLocalApply = "$($TargetNode).mof" 
    $MofFileExpectedPath = Join-Path $MofOutputPath $ExpectedMofFileNameForLocalApply

    # Si le nom généré (basé sur le futur nom) est différent du nom attendu (basé sur le nom actuel)
    if ($MofFileGeneratedPath -ne $MofFileExpectedPath) {
        Write-Log "Le nom du MOF généré ('$GeneratedMofFileName') doit être ajusté pour l'application locale sur '$TargetNode'." 'INFO' 2
        
        # Supprimer un ancien MOF attendu s'il existe pour éviter les conflits avec Rename-Item
        if (Test-Path $MofFileExpectedPath) {
            Write-Log "Suppression d'un fichier MOF existant avec le nom attendu: '$ExpectedMofFileNameForLocalApply'" 'DEBUG' 3
            Remove-Item -Path $MofFileExpectedPath -Force -ErrorAction SilentlyContinue
        }
        
        Write-Log "Renommage de '$GeneratedMofFileName' en '$ExpectedMofFileNameForLocalApply'." 'INFO' 2
        try {
            Rename-Item -Path $MofFileGeneratedPath -NewName $ExpectedMofFileNameForLocalApply -Force -ErrorAction Stop
            Write-Log "Fichier MOF renommé avec succès en '$MofFileExpectedPath'." 'SUCCESS' 2
        } catch {
            Write-Log "ERREUR critique lors du renommage du fichier MOF de '$MofFileGeneratedPath' en '$MofFileExpectedPath': $($_.Exception.Message)" 'ERROR' 1
            Write-Log "Stack Trace: $($_.ScriptStackTrace)" 'ERROR' 2
            Exit 1
        }
        # Vérifier que le renommage a bien eu lieu et que le fichier attendu existe
        if (-not (Test-Path $MofFileExpectedPath)) {
             Write-Log "ERREUR critique : Le fichier MOF '$MofFileExpectedPath' n'a pas été trouvé APRÈS la tentative de renommage." 'ERROR' 1
             Exit 1
        }
    }
} else {
    Write-Log "ERREUR critique : Le fichier MOF '$MofFileGeneratedPath' (basé sur le paramètre ComputerName: '$($nodeData.ComputerName)') n'a pas été trouvé après la compilation." 'ERROR' 1
    Write-Log "Vérifiez les erreurs lors de l'étape 'MachineConfiguration'." 'ERROR' 2
    Exit 1
}

# La suite du script (Configuration WinRM, etc.) continue ici...
# Start-DscConfiguration utilisera -Path $MofOutputPath et trouvera $ExpectedMofFileNameForLocalApply.
# Installer et ou lancer le service WinRM
Write-Log "Configuration et Vérification de WinRM (requis pour DSC)..." 'INFO' 1
try {
    # Assurer que le service est configuré pour démarrer automatiquement
    Write-Log "Configuration du service WinRM en démarrage automatique..." 'DEBUG' 2
    Set-Service -Name WinRM -StartupType Automatic -ErrorAction Stop

    # Démarrer le service s'il n'est pas déjà en cours d'exécution
    if ((Get-Service -Name WinRM).Status -ne 'Running') {
        Write-Log "Démarrage du service WinRM..." 'DEBUG' 2
        Start-Service -Name WinRM -ErrorAction Stop
        Write-Log "Service WinRM démarré. Attente de 5 secondes pour stabilisation..." 'DEBUG' 3
        Start-Sleep -Seconds 5
    } else {
         Write-Log "Le service WinRM est déjà en cours d'exécution." 'DEBUG' 2
    }

    # --- ÉTAPE 1: Vérifier et corriger le profil réseau ---
    Write-Log "Vérification des profils de connexion réseau..." 'INFO' 2
    $publicProfilesFound = $false
    try {
        $connectionProfiles = Get-NetConnectionProfile -ErrorAction SilentlyContinue # SilentlyContinue car il peut n'y en avoir aucun
        if ($connectionProfiles) {
            foreach ($profile in $connectionProfiles) {
                Write-Log "Profil réseau détecté: Interface '$($profile.InterfaceAlias)' (Index: $($profile.InterfaceIndex)) est '$($profile.NetworkCategory)'" 'DEBUG' 3
                if ($profile.NetworkCategory -eq 'Public') {
                    $publicProfilesFound = $true
                    Write-Log "PROFIL PUBLIC DÉTECTÉ pour l'interface '$($profile.InterfaceAlias)'. Tentative de changement en 'Privé'..." 'WARN' 3
                    try {
                        Set-NetConnectionProfile -InterfaceIndex $profile.InterfaceIndex -NetworkCategory Private -ErrorAction Stop
                        Write-Log "Profil de l'interface '$($profile.InterfaceAlias)' changé en 'Privé' avec succès." 'SUCCESS' 3
                    } catch {
                        Write-Log "ERREUR lors de la tentative de changement du profil réseau pour '$($profile.InterfaceAlias)' en 'Privé': $($_.Exception.Message)" 'ERROR' 3
                        Write-Log "Impossible de changer automatiquement le profil réseau. Le pare-feu WinRM risque de ne pas fonctionner. Veuillez le faire manuellement et relancer le script." 'ERROR' 3
                        Exit 1
                    }
                }
            }
        } else {
            Write-Log "Aucun profil de connexion réseau actif trouvé via Get-NetConnectionProfile. Cela peut être normal sur certaines configurations minimales ou si le service NLA n'est pas actif." 'WARN' 3
        }
        
        if ($publicProfilesFound) {
            Write-Log "Un ou plusieurs profils réseau ont été changés en 'Privé'. Attente de 5 secondes pour que les changements prennent effet..." 'INFO' 3
            Start-Sleep -Seconds 5
        } else {
            Write-Log "Aucun profil réseau 'Public' n'a été trouvé nécessitant un changement, ou aucun profil actif." 'INFO' 3
        }

    } catch {
        Write-Log "ERREUR lors de la gestion des profils réseau: $($_.Exception.Message)" 'ERROR' 2
        Write-Log "Impossible de vérifier ou de modifier les profils réseau. Les configurations WinRM pourraient échouer." 'ERROR' 2
        # On ne quitte pas forcément ici, on laisse winrm quickconfig tenter sa chance.
    }

    # --- ÉTAPE 2: Exécuter winrm quickconfig et analyser sa sortie ---
    Write-Log "Exécution de 'winrm quickconfig -q' pour configurer les écouteurs HTTP/pare-feu..." 'DEBUG' 2
    $quickConfigOutput = ""
    $quickConfigExitCode = 0 
    $winrmCmdPath = Join-Path -Path $env:windir -ChildPath "System32\winrm.cmd" # Chemin plus explicite

    try {
        # Utilisation de Start-Process pour une meilleure gestion
        $processArgs = "quickconfig -q"
        $process = Start-Process -FilePath $winrmCmdPath -ArgumentList $processArgs -Wait -PassThru -NoNewWindow -RedirectStandardOutput ".\winrm_stdout.log" -RedirectStandardError ".\winrm_stderr.log"
        $quickConfigExitCode = $process.ExitCode
        
        $stdOut = Get-Content ".\winrm_stdout.log" -Raw -ErrorAction SilentlyContinue
        $stdErr = Get-Content ".\winrm_stderr.log" -Raw -ErrorAction SilentlyContinue
        $quickConfigOutput = (($stdOut + $stdErr) | Out-String).Trim()
        
        Remove-Item ".\winrm_stdout.log", ".\winrm_stderr.log" -ErrorAction SilentlyContinue

    } catch {
        Write-Log "Échec de l'exécution de '$winrmCmdPath quickconfig -q': $($_.Exception.Message)" 'ERROR' 3
        $quickConfigExitCode = -1 # Indiquer un échec
        $quickConfigOutput = $_.Exception.Message
    }

    Write-Log "Sortie de '$winrmCmdPath quickconfig -q' (Code de sortie: $quickConfigExitCode):`n$quickConfigOutput" 'DEBUG' 4

    # Vérification de la sortie de quickconfig pour les erreurs spécifiques, même si le code de sortie est 0
    if ($quickConfigOutput -match "type de connexion réseau sur cet ordinateur est défini sur Public" -or $quickConfigOutput -match "network connection type on this computer is set to Public") {
        Write-Log "ERREUR CRITIQUE: La sortie de WinRM quickconfig indique TOUJOURS que le profil réseau est 'Public', MÊME APRÈS LA TENTATIVE DE CORRECTION." 'ERROR' 3
        Write-Log "Cela signifie que le changement de profil a échoué ou n'a pas été pris en compte. Le pare-feu WinRM ne fonctionnera PAS." 'ERROR' 3
        Exit 1 
    }
    if ($quickConfigExitCode -ne 0) {
        Write-Log "winrm quickconfig -q a échoué avec le code de sortie $quickConfigExitCode." 'ERROR' 3 # Changé en ERROR car c'est problématique.
        Write-Log "L'échec de 'winrm quickconfig' peut empêcher la configuration correcte de l'écouteur HTTP, ce qui peut impacter les étapes suivantes. Le script va tenter de continuer avec la configuration HTTPS, mais il y a un risque élevé d'échec." 'ERROR' 3
        # Ne pas quitter ici pour laisser la chance à la conf HTTPS, mais c'est un mauvais signe.
    } else {
        Write-Log "'winrm quickconfig -q' semble avoir terminé correctement (code de sortie 0 et pas de message de réseau Public)." 'SUCCESS' 3
    }

    # --- ÉTAPE 3: Test de l'écouteur HTTP de base (même si on vise HTTPS pour DSC) ---
    Write-Log "Test de la connexion WinRM locale sur HTTP (Test-WSMan localhost)..." 'DEBUG' 2
    try {
        Test-WSMan -ComputerName localhost -ErrorAction Stop 
        Write-Log "Test de connexion WinRM local HTTP réussi." 'SUCCESS' 2
    } catch {
        Write-Log "ÉCHEC du test de connexion WinRM local HTTP: $($_.Exception.Message)" 'ERROR' 2
        Write-Log "Cela indique un problème fondamental avec WinRM, même pour HTTP. La configuration HTTPS et DSC échoueront probablement." 'ERROR' 2
        # Si winrm quickconfig a échoué, il est probable que ce test échoue aussi.
        Exit 1 # Bloquant si même HTTP local ne fonctionne pas.
    }
    Write-Log "Configuration de base de WinRM (HTTP) et vérification réseau terminées." 'SUCCESS' 1

} catch { # Catch global pour la section de configuration HTTP et réseau
    Write-Log "ERREUR MAJEURE lors de la configuration initiale de WinRM (HTTP/Réseau)." 'ERROR' 1
    Write-Log "Erreur: $($_.Exception.Message)" 'ERROR' 2
    Write-Log $_.ScriptStackTrace 'ERROR' 2
    Exit 1
}

#region Configuration de l'écouteur WinRM HTTPS
Write-Log "Configuration de l'écouteur WinRM pour HTTPS..." 'INFO' 1
try {
    $winrmHttpsListenerExists = $false
    try {
        # On utilise winrm.cmd pour énumérer, car Get-WSManInstance peut ne pas fonctionner si WinRM est mal configuré.
        $listenerEnumOutput = Invoke-Expression "$winrmCmdPath enumerate winrm/config/Listener" | Out-String
        if ($listenerEnumOutput -match 'Transport = HTTPS') {
            $winrmHttpsListenerExists = $true
            Write-Log "Un écouteur WinRM HTTPS est déjà configuré (détecté via '$winrmCmdPath enumerate')." 'DEBUG' 2
        }
    } catch {
        Write-Log "Impossible de vérifier les écouteurs WinRM existants via '$winrmCmdPath enumerate': $($_.Exception.Message). On suppose qu'aucun écouteur HTTPS n'existe." 'WARN' 2
    }

    if (-not $winrmHttpsListenerExists) {
        Write-Log "Aucun écouteur WinRM HTTPS détecté. Tentative de configuration..." 'INFO' 2
        # ... (le reste de la création du certificat et de l'écouteur HTTPS comme avant)
        # S'assurer que $certThumbprint est bien obtenu
        # Puis winrm.cmd create ...
        $currentHostName = $env:COMPUTERNAME
        # ... (logique de Get-ChildItem Cert:\... ou New-SelfSignedCertificate pour $certThumbprint) ...
        # Supposons que $certThumbprint est obtenu correctement
        # Exemple simplifié pour la création, à adapter avec votre logique de certificat :
        $existingCert = Get-ChildItem Cert:\LocalMachine\My | 
                        Where-Object { 
                            $_.Subject -match "CN=$([regex]::Escape($currentHostName))($|,)" -and 
                            $_.Extensions | Where-Object {$_.Oid.Value -eq '2.5.29.37'} | ForEach-Object { $_.EnhancedKeyUsages } | Where-Object { $_.Oid.Value -eq '1.3.6.1.5.5.7.3.1'}
                        } |
                        Sort-Object -Property NotAfter -Descending | 
                        Select-Object -First 1
        
        $certThumbprint = $null
        if ($existingCert) {
            Write-Log "Certificat SSL existant trouvé pour '$currentHostName' (Thumbprint: $($existingCert.Thumbprint))." 'INFO' 3
            $certThumbprint = $existingCert.Thumbprint
        } else {
            Write-Log "Aucun certificat SSL existant approprié trouvé. Création d'un certificat auto-signé pour '$currentHostName'..." 'INFO' 3
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12, [Net.SecurityProtocolType]::Tls11, [Net.SecurityProtocolType]::Tls 
            
            $newCertParams = @{
                DnsName = @($currentHostName, "localhost")
                CertStoreLocation = "Cert:\LocalMachine\My"
                KeyUsage = "KeyEncipherment", "DigitalSignature"
                TextExtension = @("2.5.29.37={text}1.3.6.1.5.5.7.3.1") # Server Authentication
                NotAfter = (Get-Date).AddYears(2)
                ErrorAction = 'Stop'
            }
            $selfSignedCert = New-SelfSignedCertificate @newCertParams
            $certThumbprint = $selfSignedCert.Thumbprint
            Write-Log "Certificat auto-signé créé (Thumbprint: $certThumbprint)." 'SUCCESS' 3
        }
        # ----- DEBUT : Ajout du certificat auto-signé au magasin Root -----
        if ($selfSignedCert) { # Si nous venons de créer un nouveau certificat auto-signé
            Write-Log "Tentative d'ajout du certificat auto-signé ($($selfSignedCert.Thumbprint)) au magasin des Autorités de Certification Racines de Confiance..." 'INFO' 3
            try {
                # Ouvrir le magasin Root
                $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
                $store.Open("ReadWrite")
                
                # Vérifier s'il n'y est pas déjà (pour l'idempotence)
                $existingCertInRoot = $store.Certificates | Where-Object { $_.Thumbprint -eq $selfSignedCert.Thumbprint }
                if (-not $existingCertInRoot) {
                    $store.Add($selfSignedCert)
                    Write-Log "Certificat auto-signé ajouté au magasin Root." 'SUCCESS' 3
                } else {
                    Write-Log "Le certificat auto-signé est déjà présent dans le magasin Root." 'INFO' 3
                }
            } catch {
                Write-Log "ERREUR lors de l'ajout du certificat auto-signé au magasin Root: $($_.Exception.Message)" 'ERROR' 3
                # C'est un problème, car Test-WSMan échouera probablement.
                # On pourrait choisir de s'arrêter ici ou de continuer en sachant que Test-WSMan pourrait échouer.
                # Pour l'instant, on logue l'erreur et on continue, Test-WSMan nous dira.
            } finally {
                if ($store) { $store.Close() }
            }
        } elseif ($existingCert) { # Si on utilise un certificat existant qui pourrait aussi être auto-signé ou d'une PKI non reconnue par défaut
             Write-Log "Vérification si le certificat existant ($($existingCert.Thumbprint)) doit être ajouté au magasin Root..." 'DEBUG' 3
             # Vous pourriez ajouter une logique similaire ici si nécessaire, 
             # mais c'est moins courant si le certificat "existant" est censé être digne de confiance.
             # Pour l'instant, on se concentre sur le certificat auto-signé nouvellement créé.
        }
        # ----- FIN : Ajout du certificat auto-signé au magasin Root -----

        if ($certThumbprint) {
            Write-Log "Configuration de l'écouteur WinRM HTTPS avec le certificat (Thumbprint: $certThumbprint)..." 'INFO' 3
                    
            $winrmResourceUri = "winrm/config/Listener?Address=*+Transport=HTTPS"
            
            # Le nom d'hôte pour le certificat doit être le nom actuel de la machine
            $hostnameValueForWinrm = $currentHostName # $env:COMPUTERNAME
            $thumbprintValueForWinrm = $certThumbprint
            
            # Construction de la chaîne de valeurs EXACTEMENT comme winrm.cmd l'attend pour son argument @{...}
            # winrm.cmd attend: @{Hostname="VALEUR"; CertificateThumbprint="VALEUR"}
            # Les guillemets INTERNES sont cruciaux pour winrm.cmd.
            # Les ` (backticks) échappent les guillemets pour qu'ils soient inclus littéralement dans la chaîne PowerShell.
            $winrmValuesArgument = "@{Hostname=`"$hostnameValueForWinrm`"; CertificateThumbprint=`"$thumbprintValueForWinrm`"}"
            # $winrmValuesArgument sera, par exemple: @{Hostname="DESKTOP-UMHFA3E"; CertificateThumbprint="ABC123..."}

            # Construction du TABLEAU d'arguments pour Start-Process
            # Chaque "mot" de la commande pour winrm.cmd devient un élément du tableau.
            $argumentListArray = @(
                "create",             # Argument 1 pour winrm.cmd
                $winrmResourceUri,    # Argument 2 pour winrm.cmd
                $winrmValuesArgument  # Argument 3 pour winrm.cmd (la chaîne @{...} complète)
            )
            
            Write-Log "Valeur détaillée de l'argument @{...} construit : $winrmValuesArgument" 'DEBUG' 4
            Write-Log "Tableau d'arguments pour Start-Process (-ArgumentList): $(($argumentListArray | ForEach-Object { "'$_'" }) -join ' ')" 'DEBUG' 4
            
            # Assurez-vous que $winrmCmdPath est défini (ex: $env:SystemRoot\System32\winrm.cmd)
            # $winrmCmdPath = Join-Path -Path $env:SystemRoot -ChildPath "System32\winrm.cmd" # Si pas déjà défini

            $createProcess = Start-Process -FilePath $winrmCmdPath -ArgumentList $argumentListArray -Wait -PassThru -NoNewWindow -RedirectStandardOutput ".\winrm_create_stdout.log" -RedirectStandardError ".\winrm_create_stderr.log"
            $createExitCode = $createProcess.ExitCode
            $createStdOut = Get-Content ".\winrm_create_stdout.log" -Raw -ErrorAction SilentlyContinue
            $createStdErr = Get-Content ".\winrm_create_stderr.log" -Raw -ErrorAction SilentlyContinue
            $createOutput = (($createStdOut + $createStdErr) | Out-String).Trim()
            Remove-Item ".\winrm_create_stdout.log", ".\winrm_create_stderr.log" -ErrorAction SilentlyContinue

            Write-Log "Sortie de '$winrmCmdPath $($argumentListArray -join ' ')' (Code de sortie: $createExitCode):`n$createOutput" 'DEBUG' 4

            if ($createExitCode -ne 0) {
                # Pour le log, on va afficher la commande exacte qui a été tentée
                Write-Log "Commande échouée: $winrmCmdPath $($argumentListArray -join ' ')" 'ERROR' 4
                throw "winrm.cmd create HTTPS listener a échoué avec le code $createExitCode. Sortie: $createOutput"
            }
            Write-Log "Commande 'winrm create HTTPS listener' semble avoir réussi." 'SUCCESS' 3
            Start-Sleep -Seconds 2 
        } else {
            throw "Impossible d'obtenir un thumbprint de certificat pour configurer l'écouteur HTTPS."
        }
    } # Fin if (-not $winrmHttpsListenerExists)
    
    # --- ÉTAPE 4: Test de l'écouteur HTTPS ---
    Write-Log "Test de la connexion WinRM locale sur HTTPS (Test-WSMan $env:COMPUTERNAME -UseSsl)..." 'DEBUG' 2
    try {
        Test-WSMan -ComputerName $env:COMPUTERNAME -UseSsl -Authentication Default -ErrorAction Stop 
        Write-Log "Test de connexion WinRM local HTTPS réussi." 'SUCCESS' 2
    } catch {
        Write-Log "ÉCHEC du test de connexion WinRM local HTTPS: $($_.Exception.Message)" 'ERROR' 2
        Write-Log "Causes possibles: Certificat non approuvé (même auto-signé pour localhost peut parfois poser problème sans configuration Hosts spécifique ou si le certificat n'est pas correctement installé/reconnu par Schannel), écouteur HTTPS non démarré, problème de port 5986." 'ERROR' 2
        Write-Log "Vérifiez `winrm get winrm/config/service` (Auth, CertThumbprint) et `winrm get winrm/config/client` (TrustedHosts)." 'INFO' 2
        Exit 1 # Bloquant si HTTPS local ne fonctionne pas.
    }

    Write-Log "Configuration et vérification de l'écouteur WinRM HTTPS terminées." 'SUCCESS' 1
} catch { # Catch global pour la section de configuration HTTPS
    Write-Log "ERREUR MAJEURE lors de la configuration de l'écouteur WinRM HTTPS." 'ERROR' 1
    Write-Log "Erreur: $($_.Exception.Message)" 'ERROR' 2
    Write-Log $_.ScriptStackTrace 'ERROR' 2
    Exit 1
}
#endregion Configuration de l'écouteur WinRM HTTPS


#Application configuration DSC
Write-Log "Application de la configuration DSC sur '$TargetNode' via HTTPS..." 'INFO' 1
Write-Log "C'est normal si ça ne bouge pas pendant 15 minutes, en fonction des ressources et des installations..." 'INFO' 2
# Configuration de TrustedHosts pour permettre la communication DSC locale...
Write-Log "Configuration de TrustedHosts pour permettre la communication DSC locale..." 'INFO' 3

$currentTrustedHostsValue = ""
try {
    $currentTrustedHostsValue = (Get-Item -Path WSMan:\localhost\Client\TrustedHosts).Value
} catch {
    Write-Log "Impossible de lire la valeur actuelle de TrustedHosts. On suppose qu'elle est vide. Erreur: $($_.Exception.Message)" 'WARN' 4
    # Si la clé n'existe pas, elle sera créée par Set-Item
}

# Hôtes que nous devons absolument avoir pour une application DSC locale
$requiredLocalDscHosts = @($env:COMPUTERNAME, "localhost") | Select-Object -Unique

# Gérer le cas où TrustedHosts est déjà '*'
if ($currentTrustedHostsValue -eq '*') {
    Write-Log "TrustedHosts est déjà configuré sur '*', aucune modification nécessaire pour les hôtes locaux." 'INFO' 4
} else {
    # Construire une liste propre à partir de la valeur actuelle
    $existingHostsList = [System.Collections.Generic.List[string]]::new()
    if (-not [string]::IsNullOrWhiteSpace($currentTrustedHostsValue)) {
        $currentTrustedHostsValue -split ',' | ForEach-Object {
            $trimmedHost = $_.Trim()
            if (-not [string]::IsNullOrWhiteSpace($trimmedHost) -and -not $existingHostsList.Contains($trimmedHost) ) {
                $existingHostsList.Add($trimmedHost)
            }
        }
    }

    $updateMade = $false
    foreach ($hostToAdd in $requiredLocalDscHosts) {
        if (-not $existingHostsList.Contains($hostToAdd)) {
            Write-Log "Ajout de '$hostToAdd' à la liste TrustedHosts." 'INFO' 4
            $existingHostsList.Add($hostToAdd)
            $updateMade = $true
        } else {
            Write-Log "'$hostToAdd' est déjà dans TrustedHosts." 'INFO' 4
        }
    }

    if ($updateMade) {
        $newTrustedHostsString = $existingHostsList -join ','
        Write-Log "Nouvelle chaîne TrustedHosts à appliquer : '$newTrustedHostsString'" 'DEBUG' 4
        try {
            Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Value $newTrustedHostsString -Force -ErrorAction Stop
            $readValueAfterSet = (Get-Item -Path WSMan:\localhost\Client\TrustedHosts).Value
            Write-Log "TrustedHosts mis à jour. Nouvelle valeur lue : '$readValueAfterSet'" 'SUCCESS' 4
            if ($readValueAfterSet -ne $newTrustedHostsString) {
                Write-Log "AVERTISSEMENT: La valeur lue de TrustedHosts ('$readValueAfterSet') après la mise à jour ne correspond pas à la valeur écrite ('$newTrustedHostsString'). Cela pourrait indiquer un problème." 'WARN' 5
            }
        } catch {
            Write-Log "Échec de la mise à jour de TrustedHosts. Erreur: $($_.Exception.Message)" 'ERROR' 4
            # Il est critique de s'arrêter ici si TrustedHosts ne peut pas être configuré
            Exit 1 # Ou throw "..."
        }
    } else {
        Write-Log "TrustedHosts est déjà correctement configuré pour les hôtes requis." 'INFO' 4
    }
}
try {
    $dscParams = @{
        Path = $MofOutputPath
        Wait = $true
        Force = $true
        Verbose = ($VerbosePreference -eq 'Continue') # Assurez-vous que $VerbosePreference est bien 'Continue' si vous voulez les messages verbose de DSC
        ErrorAction = 'Stop'
        # ComputerName = $TargetNode # Inclus par défaut si Path est un dossier. Explicite si Path est un fichier MOF.
    }
    
    Write-Log "Paramètres pour Start-DscConfiguration: $($dscParams | Out-String)" 'DEBUG' 3
    $dscJob = Start-DscConfiguration @dscParams
    
    # ... (le reste de la gestion du job DSC)
    if ($dscJob.State -eq 'Failed') {
        Write-Log "La tâche DSC a échoué." 'ERROR' 1
        $errors = $dscJob.Error # PowerShell v5+
        if (!$errors -and $dscJob.PSBeginTime) { # Pour PSv4 ou si .Error est vide mais qu'il y a eu un souci
             $errors = Get-DscConfigurationStatus -CimSession $TargetNode -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Errors
        }

        if ($errors) {
            Write-Log "Erreurs de la tâche DSC:" 'ERROR' 2
            $errors | ForEach-Object { 
                Write-Log "Message: $($_.Message)" 'ERROR' 3
                Write-Log "FullyQualifiedErrorId: $($_.FullyQualifiedErrorId)" 'ERROR' 3
                if ($_.TargetObject) { Write-Log "TargetObject: $($_.TargetObject)" 'ERROR' 3 }
                if ($_.ErrorDetails) { Write-Log "ErrorDetails: $($_.ErrorDetails.Message)" 'ERROR' 3 } # Souvent plus utile
            }
        } else {
            Write-Log "Aucune erreur détaillée n'a pu être récupérée de la tâche DSC ou via Get-DscConfigurationStatus." 'WARN' 2
        }
        Exit 1
    } elseif ($dscJob.State -eq 'Completed') {
        Write-Log "Configuration DSC appliquée avec succès." 'SUCCESS' 1
    } else {
        Write-Log "État final de la tâche DSC : $($dscJob.State)" 'INFO' 1
    }

} catch {
    Write-Log "ERREUR lors du lancement ou du suivi de Start-DscConfiguration :" 'ERROR' 1
    Write-Log $_.Exception.Message 'ERROR' 2
    if ($_.Exception.InnerException) {
        Write-Log "InnerException: $($_.Exception.InnerException.Message)" 'ERROR' 2
    }
    Write-Log $_.ScriptStackTrace 'ERROR' 2 
    
    # Tentative finale de récupérer les erreurs DSC
    try {
        $dscErrors = Get-DscConfigurationStatus -ErrorAction SilentlyContinue
        if ($dscErrors.Count -gt 0 -and $dscErrors[0].Errors) { # Structure peut varier
            Write-Log "Erreurs DSC rapportées par Get-DscConfigurationStatus :" 'ERROR' 2
            $dscErrors[0].Errors | ForEach-Object { Write-Log ($PSItem | Out-String) 'ERROR' 3 }
        } elseif ($dscErrors -and $dscErrors.Status -eq 'Failure') {
             Write-Log "Get-DscConfigurationStatus indique un échec mais pas d'erreurs détaillées récupérées directement." 'WARN' 2
             Write-Log ($dscErrors | Out-String) 'DEBUG' 3
        }
    } catch {
        Write-Log "Échec de la récupération des erreurs DSC détaillées via Get-DscConfigurationStatus: $($_.Exception.Message)" 'WARN' 2
    }
    Exit 1
}


Write-Log "Phase 3: Préparation et Appel DSC terminés." 'STEP' 0
#endregion Phase 3: Préparation et Appel DSC

#region Phase 4: Vérification Post-DSC
#==============================================================================
# Phase 4: Vérification Post-DSC (Basique)
#==============================================================================
Write-Host "`n--------------------------------------------------------------------------------" -ForegroundColor DarkCyan
Write-Host "-                    Phase 4: Vérification Post-DSC                          -" -ForegroundColor DarkCyan
Write-Host "--------------------------------------------------------------------------------`n" -ForegroundColor DarkCyan
Write-Log "Phase 4: Démarrage de la vérification post-DSC..." 'STEP' 0

Write-Log "Test de l'état de la configuration DSC appliquée..." 'INFO' 1
try {
    $dscTestResult = Test-DscConfiguration -Verbose:$false -ErrorAction Stop # $false car Start-Dsc a déjà été verbeux
    if ($dscTestResult -is [bool] -and $dscTestResult -eq $true) {
        Write-Log "Test-DscConfiguration: La machine est dans l'état désiré." 'SUCCESS' 1
    } elseif ($dscTestResult -is [bool] -and $dscTestResult -eq $false) {
        Write-Log "Test-DscConfiguration: La machine N'EST PAS dans l'état désiré." 'WARN' 1
        Write-Log "Relancez Start-DscConfiguration ou investiguez les logs DSC pour les détails." 'WARN' 2
        # Tenter d'obtenir les détails des ressources non conformes
        $nonCompliantResources = Get-DscConfiguration -CimSession $TargetNode | Where-Object { $_.ResourceNotInDesiredState }
        if ($nonCompliantResources) {
            Write-Log "Ressources non conformes détectées :" 'WARN' 2
            $nonCompliantResources | Select-Object ResourceId, ModuleName, Reason | Format-List | Out-String | Write-Log -Level 'WARN' -Indent 3
        }
    } else {
        # Cas où Test-DscConfiguration retourne autre chose qu'un booléen (moins courant)
         Write-Log "Test-DscConfiguration a retourné un résultat inattendu." 'WARN' 1
         Write-Log ($dscTestResult | Out-String) 'WARN' 2
    }
} catch {
    Write-Log "ERREUR lors de l'exécution de Test-DscConfiguration :" 'ERROR' 1
    Write-Log $_.Exception.Message 'ERROR' 2
}

# Vérifications supplémentaires simples (optionnel)
try {
     $currentComputerInfo = Get-ComputerInfo -ErrorAction Stop
     Write-Log "Vérification Nom Actuel: $($currentComputerInfo.CsName)" 'INFO' 1
     Write-Log "Vérification Domaine/Groupe Actuel: $($currentComputerInfo.DomainRole)" 'INFO' 1
     if ($DomainName) {
         Write-Log "Domaine attendu: $DomainName (Rôle attendu: MemberWorkstation ou MemberServer)" 'INFO' 2
     }
     if ($NewComputerName -and $currentComputerInfo.CsName -ne $NewComputerName) {
         Write-Log "Le nom d'ordinateur actuel ne correspond pas encore au nom cible. Un redémarrage est probablement nécessaire." 'WARN' 2
     }

} catch {
     Write-Log "Impossible de récupérer les informations via Get-ComputerInfo." 'WARN' 1
}


Write-Log "Phase 4: Vérification Post-DSC terminée." 'STEP' 0
#endregion Phase 4: Vérification Post-DSC

#==============================================================================
# Phase 5.5: Épinglage des Applications (Post-DSC)
#==============================================================================
Write-Host "`n--------------------------------------------------------------------------------" -ForegroundColor Cyan
Write-Host "-         Phase 5.5: Épinglage Applications Barre des Tâches                 -" -ForegroundColor Cyan
Write-Host "--------------------------------------------------------------------------------`n" -ForegroundColor Cyan
Write-Log "Phase 5.5: Démarrage épinglage applications..." 'STEP' 0

if (-not $dscErrorOccurred) {
    Write-Log "Vérification des chemins et tentative d'épinglage (Chrome, Firefox, Adobe Reader)..." 'INFO' 1

    # Définir les chemins attendus pour les exécutables
    # On vérifie les deux emplacements Program Files (x86 et standard)
    $chromePath = Join-Path ${env:ProgramFiles} "Google\Chrome\Application\chrome.exe"
    if (-not (Test-Path $chromePath)) {
        $chromePath = Join-Path ${env:ProgramFiles(x86)} "Google\Chrome\Application\chrome.exe"
    }

    $firefoxPath = Join-Path ${env:ProgramFiles} "Mozilla Firefox\firefox.exe"
    if (-not (Test-Path $firefoxPath)) {
        $firefoxPath = Join-Path ${env:ProgramFiles(x86)} "Mozilla Firefox\firefox.exe"
    }

    # Adobe Reader est généralement en x86
    $adobePath = Join-Path ${env:ProgramFiles(x86)} "Adobe\Acrobat Reader DC\Reader\AcroRd32.exe"
    if (-not (Test-Path $adobePath)) {
         $adobePath = Join-Path ${env:ProgramFiles} "Adobe\Acrobat Reader DC\Reader\AcroRd32.exe" # Au cas où
    }

    # Appeler la fonction d'épinglage (qui contient un placeholder pour le moment)
    Pin-AppToTaskbar -ExePath $chromePath -AppNameForLog "Google Chrome"
    Pin-AppToTaskbar -ExePath $firefoxPath -AppNameForLog "Mozilla Firefox"
    Pin-AppToTaskbar -ExePath $adobePath -AppNameForLog "Adobe Acrobat Reader"

    Write-Log "Tentatives d'épinglage terminées (exécution basée sur la fonction Pin-AppToTaskbar)." 'SUCCESS' 1
    Write-Log "Note: L'épinglage réel dépend de l'implémentation dans la fonction Pin-AppToTaskbar." 'INFO' 2
} else {
    Write-Log "Phase 5.5: Épinglage ignoré car une erreur s'est produite pendant la phase DSC." 'WARN' 0
}
#endregion Phase 5.5: Épinglage des Applications

#region Phase 6: Installation Mises à Jour Windows
#==============================================================================
# Phase 6: Installation Mises à Jour Windows via PSWindowsUpdate
#==============================================================================
Write-Host "`n--------------------------------------------------------------------------------" -ForegroundColor Cyan
Write-Host "-             Phase 6: Installation Mises à Jour Windows                     -" -ForegroundColor Cyan
Write-Host "--------------------------------------------------------------------------------`n" -ForegroundColor Cyan
Write-Log "Phase 6: Démarrage vérification/installation des mises à jour Windows..." 'STEP' 0

if (-not $SkipWindowsUpdate) {
    $PSWindowsUpdateModule = "PSWindowsUpdate"
    $pswuModuleAvailable = $false

    # Étape 1: Vérifier si le module PSWindowsUpdate est disponible
    Write-Log "Vérification de la disponibilité du module '$PSWindowsUpdateModule'..." 'INFO' 1
    if (Get-Module -ListAvailable -Name $PSWindowsUpdateModule) {
        Write-Log "Module '$PSWindowsUpdateModule' trouvé." 'SUCCESS' 1
        $pswuModuleAvailable = $true
    } else {
        Write-Log "Module '$PSWindowsUpdateModule' non trouvé. Tentative d'installation..." 'INFO' 1
        try {
            # S'assurer que PSGallery est approuvé (nécessaire pour Install-Module sans confirmation)
            $repo = Get-PSRepository -Name 'PSGallery' -ErrorAction SilentlyContinue
            if ($repo -and $repo.InstallationPolicy -ne 'Trusted') {
                Write-Log "Approbation du dépôt PSGallery..." 'INFO' 2
                Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted
            }

            # Installer le module pour tous les utilisateurs
            Write-Log "Installation de '$PSWindowsUpdateModule' depuis PSGallery..." 'INFO' 2
            Install-Module -Name $PSWindowsUpdateModule -Force -Confirm:$false -Scope AllUsers -ErrorAction Stop
            Write-Log "Module '$PSWindowsUpdateModule' installé avec succès." 'SUCCESS' 2
            $pswuModuleAvailable = $true
        } catch {
            Write-Log "ERREUR lors de l'installation du module '$PSWindowsUpdateModule': $($_.Exception.Message)" 'ERROR' 2
            Write-Log "L'installation automatique des mises à jour Windows est impossible sans ce module." 'WARN' 1
        }
    }

    # Étape 2: Si le module est disponible, chercher et installer les mises à jour
    if ($pswuModuleAvailable) {
        Write-Log "Tentative de recherche et d'installation des mises à jour Windows..." 'STEP' 1
        try {
            # Importer le module (Force permet de réimporter si déjà chargé)
            Import-Module $PSWindowsUpdateModule -Force -ErrorAction Stop

            Write-Log "Recherche des mises à jour disponibles (peut prendre un moment)..." 'INFO' 2
            # Utiliser -MicrosoftUpdate pour inclure les màj pour d'autres produits MS
            $updates = Get-WindowsUpdate -MicrosoftUpdate -ErrorAction Stop

            if ($updates.Count -gt 0) {
                Write-Log "$($updates.Count) mise(s) à jour trouvée(s)." 'INFO' 2
                # Afficher les détails des MàJ en mode DEBUG
                $updates | Select-Object Title, KB, Size | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Log -Message $_ -Level 'DEBUG' -Indent 3 }

                Write-Log "Installation des mises à jour (peut prendre beaucoup de temps)..." 'INFO' 2
                # Gérer le niveau de verbosité pour la cmdlet
                $originalVerbosePreference = $VerbosePreference
                if ($VerbosePreference -ne 'Continue') { # Si le script principal n'est pas en -Verbose
                     $VerbosePreference = 'SilentlyContinue' # Rendre Install-WU moins bavard
                }

                # Paramètres pour Install-WindowsUpdate
                $installParams = @{
                    MicrosoftUpdate = $true         # Inclure produits MS
                    AcceptAll       = $true         # Accepter toutes les licences
                    IgnoreReboot    = $true         # Ne pas redémarrer automatiquement, on gérera à la fin
                    ErrorAction     = 'Stop'        # Arrêter si une erreur survient
                    Verbose         = ($VerbosePreference -eq 'Continue') # Passer la verbosité
                }
                $installResult = Install-WindowsUpdate @installParams

                $VerbosePreference = $originalVerbosePreference # Restaurer la préférence

                if ($installResult) {
                    Write-Log "Commande Install-WindowsUpdate terminée." 'SUCCESS' 2
                    # Vérifier si un redémarrage est explicitement requis par les MàJ installées
                    if ($installResult | Where-Object { $_.RebootRequired }) {
                        Write-Log "Un redémarrage est requis par les mises à jour installées." 'WARN' 3
                        $Global:RebootRequired = $true # Marquer pour la phase finale
                    } else {
                        Write-Log "Aucun redémarrage immédiat signalé par PSWindowsUpdate (vérification finale suivra)." 'INFO' 3
                    }
                } else {
                    # Parfois, Install-WindowsUpdate ne retourne rien même si ça fonctionne
                    Write-Log "Commande Install-WindowsUpdate exécutée (pas de retour spécifique)." 'INFO' 2
                    # Il est plus sûr de supposer qu'un reboot pourrait être nécessaire après des MàJ
                     # $Global:RebootRequired = $true # Optionnel: être prudent
                }
            } else {
                Write-Log "Aucune mise à jour disponible pour l'installation." 'SUCCESS' 2
            }
        } catch {
            Write-Log "ERREUR lors de la recherche ou l'installation des mises à jour Windows: $($_.Exception.Message)" 'ERROR' 1
            if ($_.Exception.InnerException) {
                Write-Log "InnerException: $($_.Exception.InnerException.Message)" 'ERROR' 2
            }
        }
    } # Fin if ($pswuModuleAvailable)

} else {
    Write-Log "Phase 6: Vérification/Installation des mises à jour Windows ignorée (option -SkipWindowsUpdate utilisée)." 'INFO' 0
}
#endregion Phase 6: Installation Mises à Jour Windows

#region Phase 7: Finalisation et Redémarrage
#==============================================================================
# Phase 7: Finalisation et Gestion du Redémarrage
#==============================================================================
Write-Host "`n================================================================================" -ForegroundColor Green
Write-Host "=                       Phase 7: Finalisation du Script                        =" -ForegroundColor Green
Write-Host "================================================================================`n" -ForegroundColor Green
Write-Log "Phase 7: Démarrage finalisation..." 'STEP' 0
Write-Log "Fin des opérations de déploiement et configuration." 'SUCCESS' 0

# Vérification supplémentaire si un redémarrage est en attente via le module PendingReboot (si installé)
try {
    # Vérifier si la commande existe avant de l'appeler
    if (Get-Command Get-PendingReboot -ErrorAction SilentlyContinue) {
        Write-Log "Vérification de l'état de redémarrage en attente avec Get-PendingReboot..." 'INFO' 1
        # Utiliser -Detailed pour plus d'infos (si disponible dans la version du module)
        $pendingRebootInfo = Get-PendingReboot -ErrorAction SilentlyContinue -WarningAction SilentlyContinue # Éviter le bruit si pas d'info détaillée
         if ($pendingRebootInfo -and ($pendingRebootInfo).IsRebootPending) { # L'objet retourné peut varier
             Write-Log "Get-PendingReboot confirme qu'un redémarrage est en attente." 'INFO' 1
             # Essayer d'afficher les raisons si la propriété existe
             if ($pendingRebootInfo.PSObject.Properties.Name -contains 'Reasons') {
                 Write-Log "Raisons possibles: $($pendingRebootInfo.Reasons -join '; ')" 'DEBUG' 2
             }
             $Global:RebootRequired = $true # Confirmer le besoin de reboot
         } else {
             Write-Log "Get-PendingReboot n'indique pas de redémarrage en attente." 'INFO' 1
         }
    } else {
        Write-Log "Module/Cmdlet 'PendingReboot' non trouvé. Impossible d'effectuer une vérification détaillée du redémarrage." 'DEBUG' 1
    }
} catch {
    Write-Log "Erreur lors de la vérification avec Get-PendingReboot: $($_.Exception.Message)" 'WARN' 1
}

# Gérer le redémarrage si nécessaire
if ($Global:RebootRequired) {
    Write-Host "`n"
    Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
    Write-Host "║                       *** REDÉMARRAGE NÉCESSAIRE ***                       ║" -ForegroundColor Yellow
    Write-Host "║ Un redémarrage est requis pour appliquer certaines modifications           ║" -ForegroundColor Yellow
    Write-Host "║ (Nom/Domaine, Mises à jour Windows, etc.).                                 ║" -ForegroundColor Yellow
    Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
    Write-Host ""

    $rebootChoice = ''
    while ($rebootChoice -notin @('o', 'n')) {
        $rebootChoice = (Read-Host "Voulez-vous redémarrer l'ordinateur maintenant ? (O/N)").ToLower().Trim()
    }

    if ($rebootChoice -eq "o") {
        Write-Log "Redémarrage initié par l'utilisateur." 'INFO' 1
        Write-Host "Redémarrage en cours..." -ForegroundColor Green
        Restart-Computer -Force
    } else {
        Write-Log "L'utilisateur a choisi de ne pas redémarrer maintenant." 'INFO' 1
        Write-Host "N'oubliez pas de redémarrer l'ordinateur manuellement dès que possible." -ForegroundColor Yellow
    }
} else {
    Write-Log "Aucun redémarrage n'a été signalé comme requis par les phases précédentes." 'INFO' 1
}

Write-Log "Script terminé." 'SUCCESS' 0

# Pause à la fin si exécuté dans une console standard pour voir les messages
if ($Host.Name -match 'Console') {
    Write-Host "`nLe script est terminé. Appuyez sur Entrée pour fermer cette fenêtre." -ForegroundColor Green
    Read-Host | Out-Null
}

Exit 0 # Termine le script proprement
#endregion Phase 7: Finalisation et Redémarrage

#region Fin du Script
#==============================================================================
# Fin du Script
#==============================================================================
Write-Host "`n================================================================================" -ForegroundColor Magenta
Write-Host "=                  Script de Déploiement Machine Terminé                     =" -ForegroundColor Magenta
Write-Host "================================================================================" -ForegroundColor Magenta
Write-Log "Fin du script." 'STEP' 0
#endregion Fin du Script
#region Phase 5.5: Épinglage des Applications