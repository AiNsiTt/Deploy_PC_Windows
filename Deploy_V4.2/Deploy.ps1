#Requires -Version 5.1
<#
.SYNOPSIS
Script de préparation et de déploiement PRO v4.2 pour Koesio Aquitaine.
Corrige erreurs logs v4.1, déplace prompt logiciels, améliore sortie console, tente config PDF par défaut & skip first run.

.DESCRIPTION
Version PRO v4.2 basée sur logs et retours v4.1.
Demande logiciels optionnels au début.
Automatise : Nommage, Config système/alim, BitLocker, Installation Choco + Logiciels Base/Optionnels (IDs vérifiés/corrigés),
Config Confidentialité/Optimisation (inclut skip first run pour navigateurs/Adobe), Outils Fabricant, GoToAssist, Infos OEM,
MàJ Windows, Raccourcis & Épinglage Tâches (OS FR requis), Tentative association PDF, Nettoyage.

.PARAMETER ComputerName
Nom spécifique à donner à l'ordinateur. Si omis ou $UseSerialNumberName est spécifié, le numéro de série sera utilisé.

.PARAMETER UseSerialNumberName
Utiliser le numéro de série comme nom d'ordinateur. Prioritaire sur ComputerName s'il est aussi fourni.

.PARAMETER SkipBitLockerDecryption
Ne pas tenter la suspension et le déchiffrement BitLocker.

.PARAMETER SkipWindowsUpdate
Ne pas lancer l'installation des mises à jour Windows via PSWindowsUpdate.

.PARAMETER LogLevel
Niveau de détail des logs console (INFO | VERBOSE). Défaut: INFO.

.NOTES
Version : 4.2.2025
Auteur  : Quentin Chaillou // Quentin.Chaillou@koesio.fr
Date    : 2025-04-26
IMPORTANT: Enregistrer ce fichier en UTF-8 avec BOM. Utiliser une police console UTF-8.
           L'épinglage à la barre des tâches nécessite un OS en Français.
           La définition du lecteur PDF par défaut est une tentative et peut ne pas fonctionner sur toutes les versions/configurations de Windows.
           L'installation de M365 et les MàJ Windows peuvent prendre beaucoup de temps.
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [string]$ComputerName,
    [switch]$UseSerialNumberName,
    [switch]$SkipBitLockerDecryption,
    [switch]$SkipWindowsUpdate,
    [ValidateSet('INFO','VERBOSE')][string]$LogLevel = 'INFO'
)

#region ===== Initialisation Globale =====
$ScriptVersion = '4.2.2025'
$CompanyName   = 'Koesio Aquitaine'
$SupportInfo   = @{ Manufacturer=$CompanyName; SupportHours='08H30-12H30|14H00-17H30'; SupportPhone='05 57 51 52 52'; SupportURL='https://www.koesio.com/' }

# --- Chemins et Logs ---
if (-not $PSScriptRoot) { $PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition }
$DataPath  = Join-Path $PSScriptRoot 'Data'
$LogPath   = Join-Path $PSScriptRoot 'Logs'
$LogFile   = Join-Path $LogPath "Deploy_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
if (-not (Test-Path $LogPath)) { New-Item $LogPath -ItemType Directory -Force | Out-Null }

# --- Configuration PowerShell Session & Logging ---
$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ProgressPreference = 'SilentlyContinue'
$Script:EffectiveLogLevel = $LogLevel
$Script:SelectedOptionalPackages = @() # Initialise la variable pour stocker la sélection

# --- Démarrage du Transcript ---
try {
    Start-Transcript -Path $LogFile -Append -Force
} catch {
    Write-Warning "Impossible de démarrer le transcript vers '$LogFile'. Les logs fichier seront incomplets. Erreur: $($_.Exception.Message)"
}

# --- Fonctions Utilitaires ---
Function Write-Log {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [ValidateSet('STEP','INFO','SUCCESS','WARN','ERROR','VERBOSE','DEBUG')]
        [string]$Level='INFO',
        [System.ConsoleColor]$ForegroundColor = $Host.UI.RawUI.ForegroundColor,
        [System.ConsoleColor]$BackgroundColor = $Host.UI.RawUI.BackgroundColor
    )
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "[$timestamp] [$Level] $Message"

    # Écriture Console (selon LogLevel) - Sera capturée par le Transcript
    $shouldWriteToHost = $false
    switch ($Script:EffectiveLogLevel) {
        'DEBUG'   { $shouldWriteToHost = $true }
        'VERBOSE' { if ($Level -in 'STEP','INFO','SUCCESS','WARN','ERROR','VERBOSE') { $shouldWriteToHost = $true } }
        'INFO'    { if ($Level -in 'STEP','INFO','SUCCESS','WARN','ERROR') { $shouldWriteToHost = $true } }
    }

    if ($shouldWriteToHost) {
        $color = $ForegroundColor
        switch ($Level) {
            'STEP'    { $color = [System.ConsoleColor]::Cyan }
            'SUCCESS' { $color = [System.ConsoleColor]::Green }
            'WARN'    { $color = [System.ConsoleColor]::Yellow }
            'ERROR'   { $color = [System.ConsoleColor]::Red }
            'DEBUG'   { $color = [System.ConsoleColor]::DarkGray }
        }
        # Écrit directement à l'hôte, le transcript le captera.
        Write-Host $logEntry -ForegroundColor $color -BackgroundColor $BackgroundColor
    } elseif ($Level -notin 'DEBUG','VERBOSE') {
         # Assure que les messages importants (INFO, WARN, ERROR, STEP, SUCCESS)
         # sont au moins dans le fichier log même si non affichés à la console.
         # Ceci est redondant si Start-Transcript fonctionne bien mais une sécurité.
         Out-File -FilePath $LogFile -Append -InputObject $logEntry -Encoding UTF8
    }
}

Function Show-Banner {
    param([string]$StepTitle)
    # Ne pas faire Clear-Host ici pour permettre de voir la sélection des logiciels optionnels
    # Clear-Host
    $bannerLine = '=' * 80
    $title = "  DEPLOY KOESIO AQUITAINE (PRO) v$ScriptVersion | Étape : $StepTitle  "
    Write-Host "`n$bannerLine" -ForegroundColor DarkCyan # Ajoute un saut de ligne avant
    Write-Host $title -ForegroundColor White -BackgroundColor DarkCyan
    Write-Host $bannerLine -ForegroundColor DarkCyan
    Write-Log "Début de l'étape : $StepTitle" 'STEP'
}

Function Check-Admin {
    Write-Log 'Vérification des droits administrateur...' 'INFO'
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Log "ERREUR FATALE: Ce script doit être exécuté avec des privilèges administrateur." 'ERROR'
        Stop-Transcript
        Exit 1
    }
    Write-Log 'Droits administrateur confirmés.' 'SUCCESS'
}

Function Set-RegValue {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)]$Value,
        [ValidateSet('String','ExpandString','Binary','DWORD','QWORD','MultiString','Unknown')]$Type = 'DWORD'
    )
    Write-Log "Registre: Tentative Set Path='$Path', Name='$Name', Value='$Value', Type='$Type'" 'VERBOSE'
    try {
        if (-not (Test-Path -Path $Path)) {
            New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
            Write-Log "Registre: Clé créée: $Path" 'VERBOSE'
        }

        $prop = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($prop -eq $null) {
            # La propriété n'existe pas, on la crée avec le type spécifié
             Write-Log "Registre: Propriété '$Name' non trouvée, création..." 'VERBOSE'
             New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force -ErrorAction Stop | Out-Null
        } else {
            # La propriété existe, on la modifie sans spécifier -Type (pour éviter l'erreur si le type existant est incompatible)
             Write-Log "Registre: Propriété '$Name' trouvée, mise à jour de la valeur..." 'VERBOSE'
             Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force -ErrorAction Stop | Out-Null
        }
        Write-Log "Registre: Set OK '$Name' = '$Value' dans '$Path'." 'VERBOSE'
        return $true
    } catch {
        Write-Log "Registre: ECHEC Set '$Name' dans '$Path'. Erreur: $($_.Exception.Message)" 'WARN'
        return $false
    }
}

Function New-Shortcut {
    param(
        [Parameter(Mandatory=$true)][string]$ShortcutPath,
        [Parameter(Mandatory=$true)][string]$TargetPath,
        [string]$Arguments,
        [string]$WorkingDirectory,
        [string]$IconLocation,
        [string]$Description
    )
    Write-Log "Création Raccourci: '$ShortcutPath' -> '$TargetPath'" 'VERBOSE'
    try {
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($ShortcutPath)
        $shortcut.TargetPath = $TargetPath
        if ($Arguments) { $shortcut.Arguments = $Arguments }
        if ($WorkingDirectory) { $shortcut.WorkingDirectory = $WorkingDirectory }
        if ($IconLocation) { $shortcut.IconLocation = $IconLocation }
        if ($Description) { $shortcut.Description = $Description }
        $shortcut.Save()
        Write-Log "Raccourci créé: '$ShortcutPath'" 'SUCCESS'
        return $true
    } catch {
        Write-Log "ECHEC Création Raccourci '$ShortcutPath'. Erreur: $($_.Exception.Message)" 'WARN'
        return $false
    }
}
#endregion

#region ===== 1. Vérifications Initiales =====
Show-Banner 'Vérifications Initiales & Sélection Logiciels' # Banner combiné
Write-Log "Démarrage du script de déploiement Koesio Aquitaine v$ScriptVersion" 'INFO'
Write-Log "Log Level: $Script:EffectiveLogLevel" 'INFO'
Write-Log "Chemin du script: $PSScriptRoot" 'VERBOSE'
Write-Log "Fichier de log: $LogFile" 'VERBOSE'
Check-Admin
#endregion

#region ===== 0. Sélection Logiciels Optionnels (Déplacé au début) =====
# Cette section demande juste la sélection, l'installation se fait à l'étape 5

# Définition des logiciels optionnels
$optionalSoftware = @{
    1 = @{ Name = 'Microsoft 365 Apps for Business'; ChocoID = 'office365business'; Note="Nécessite licence/compte M365. Installation longue." }
    # 2 = @{ Name = 'Office 2019 Famille et Petite Entreprise'; ChocoID = 'office2019homebusiness'; Note="Paquet non trouvé sur repo public. Utiliser une autre méthode." }
    # 3 = @{ Name = 'Office 2021 Famille et Petite Entreprise'; ChocoID = 'office2021homebusiness'; Note="Paquet non trouvé sur repo public. Utiliser une autre méthode." }
    4 = @{ Name = 'OpenVPN Connect'; ChocoID = 'openvpn-connect'; Note="ID Corrigé" } # ID Corrigé
    5 = @{ Name = 'FortiClient VPN'; ChocoID = 'forticlientvpn'; Note="Vérifier compatibilité version/licence." }
    6 = @{ Name = 'VLC Media Player'; ChocoID = 'vlc' }
    # GoToAssist est géré via Data
}

Write-Host "`n--- Sélection des Logiciels Optionnels (avant de continuer) ---" -ForegroundColor Cyan
Write-Host "Entrez les numéros des logiciels à installer, séparés par virgules (ex: 4,6)."
Write-Host "Laissez vide et appuyez sur Entrée pour ne rien installer."

# Affichage de la liste numérotée
foreach ($key in ($optionalSoftware.Keys | Sort-Object)) {
    $note = if ($optionalSoftware[$key].Note) { " ($($optionalSoftware[$key].Note))" } else { "" }
    Write-Host "$key. " -ForegroundColor Yellow -NoNewline
    Write-Host "$($optionalSoftware[$key].Name)" -ForegroundColor White -NoNewline
    Write-Host $note -ForegroundColor Gray
}

# Lecture de la sélection utilisateur
$userInput = Read-Host "`nVotre choix (numéros séparés par virgule)"

if (-not [string]::IsNullOrWhiteSpace($userInput)) {
    Write-Log "Sélection initiale utilisateur pour logiciels optionnels: '$userInput'" 'INFO'
    $selectedIndices = $userInput -split ',' | ForEach-Object { $_.Trim() }

    foreach ($selectedIndex in $selectedIndices) {
        if ($selectedIndex -match '^\d+$') {
            $index = [int]$selectedIndex
            if ($optionalSoftware.ContainsKey($index)) {
                # Ajoute l'ID Choco à la liste des paquets à installer plus tard
                $Script:SelectedOptionalPackages += $optionalSoftware[$index].ChocoID
                Write-Log "Logiciel optionnel pré-sélectionné: $($optionalSoftware[$index].Name) (ID: $($optionalSoftware[$index].ChocoID))" 'VERBOSE'
            } else {
                Write-Log "Numéro '$selectedIndex' invalide (non trouvé dans la liste). Ignoré pour la sélection." 'WARN'
            }
        } else {
            Write-Log "Entrée '$selectedIndex' invalide (non numérique). Ignorée pour la sélection." 'WARN'
        }
    }
    Write-Log "Logiciels optionnels à installer (IDs): $($Script:SelectedOptionalPackages -join ', ')" 'INFO'
} else {
    Write-Log "Aucun logiciel optionnel sélectionné par l'utilisateur." 'INFO'
}
Write-Host "Sélection enregistrée. Le script continue avec les autres étapes..." -ForegroundColor Green
# Pas de bannière ici, on enchaîne directement
#endregion

#region ===== 2. Configuration Nom Ordinateur =====
Show-Banner 'Configuration Nom Ordinateur'
try {
    $computerInfo = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    $biosInfo = Get-CimInstance Win32_BIOS -ErrorAction Stop
    $currentName = $computerInfo.Name
    $serialNumber = $biosInfo.SerialNumber.Trim()

    if ($UseSerialNumberName -or ([string]::IsNullOrWhiteSpace($ComputerName))) {
        if ([string]::IsNullOrWhiteSpace($serialNumber)) {
            Write-Log "Numéro de série non trouvé. Impossible de renommer automatiquement." 'WARN'
            $targetName = $currentName
        } else {
            $targetName = $serialNumber
            Write-Log "Utilisation du numéro de série comme nom cible: $targetName" 'INFO'
        }
    } else {
        $targetName = $ComputerName.Trim()
        Write-Log "Utilisation du nom fourni comme nom cible: $targetName" 'INFO'
    }

    if ($currentName -ne $targetName) {
        Write-Log "Nom actuel: '$currentName'. Nom cible: '$targetName'." 'INFO'
        if ($PSCmdlet.ShouldProcess($currentName, "Renommer l'ordinateur en '$targetName'")) {
            Write-Log "Tentative de renommage..." 'INFO'
            Rename-Computer -NewName $targetName -Force -ErrorAction Stop
            Write-Log "Renommage réussi vers '$targetName'. REDÉMARRAGE REQUIS." 'SUCCESS'
            Write-Log "NOTE: Le script continue avec l'ancien nom ('$currentName')." 'WARN'
        } else {
             Write-Log "Renommage annulé par l'utilisateur ou -WhatIf." 'INFO'
        }
    } else {
        Write-Log "Nom PC déjà correct ('$currentName')." 'INFO'
    }
} catch {
    Write-Log "Erreur config nom PC. Erreur: $($_.Exception.Message)" 'ERROR'
}
#endregion

#region ===== 3. Configuration Système de Base =====
Show-Banner 'Configuration Système de Base'

Write-Log "Configuration des icônes du bureau..." 'INFO'
$desktopIconGuids = @{
    '{20D04FE0-3AEA-1069-A2D8-08002B30309D}' = 0; # Ce PC
    '{59031a47-3f72-44a7-89c5-5595fe6b30ee}' = 0; # Fichiers Utilisateur
    '{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}' = 0; # Réseau
    '{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}' = 1; # Panneau de configuration (Masquer)
}
$hideIconRegPaths = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu'
foreach ($regPath in $hideIconRegPaths) {
    foreach ($guid in $desktopIconGuids.Keys) {
        Set-RegValue -Path $regPath -Name $guid -Value $desktopIconGuids[$guid] -Type DWORD
    }
}
Write-Log "Icônes bureau configurées." 'SUCCESS'

Write-Log "Activation NumLock au démarrage..." 'INFO'
Set-RegValue -Path 'HKCU:\Control Panel\Keyboard' -Name 'InitialKeyboardIndicators' -Value '2' -Type String

Write-Log "Configuration alimentation (Veille Moniteur=60, Disque=0, PC=0)..." 'INFO'
try {
    powercfg /change monitor-timeout-ac 60 > $null
    powercfg /change monitor-timeout-dc 60 > $null
    powercfg /change disk-timeout-ac 0 > $null
    powercfg /change disk-timeout-dc 0 > $null
    powercfg /change standby-timeout-ac 0 > $null
    powercfg /change standby-timeout-dc 0 > $null
    Write-Log "Paramètres alimentation configurés." 'SUCCESS'
} catch {
    Write-Log "Erreur config alimentation powercfg. Erreur: $($_.Exception.Message)" 'WARN'
}

Write-Log "Désactivation Démarrage Rapide (Hiberboot)..." 'INFO'
Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name 'HiberbootEnabled' -Value 0 -Type DWORD

Write-Log "Nettoyage raccourcis Edge bureaux..." 'INFO'
$edgeLinkPaths = @(
    # Utilisation de l'énumération correcte
    Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'Microsoft Edge.lnk',
    Join-Path ([Environment]::GetFolderPath('DesktopDirectory')) 'Microsoft Edge.lnk' # Bureau de l'utilisateur courant
)
foreach ($linkPath in $edgeLinkPaths) {
    if (Test-Path $linkPath) {
        try {
            Remove-Item $linkPath -Force -ErrorAction Stop
            Write-Log "Raccourci Edge supprimé: $linkPath" 'VERBOSE'
        } catch {
            Write-Log "Impossible de supprimer raccourci Edge: $linkPath. Erreur: $($_.Exception.Message)" 'WARN'
        }
    } else {
        Write-Log "Raccourci Edge non trouvé: $linkPath" 'VERBOSE'
    }
}
Write-Log "Configuration système base terminée." 'SUCCESS'
#endregion

#region ===== 4. Gestion BitLocker =====
Show-Banner 'Gestion BitLocker'
if ($SkipBitLockerDecryption) {
    Write-Log "Gestion BitLocker ignorée (-SkipBitLockerDecryption)." 'INFO'
} else {
    Write-Log "Vérification état BitLocker..." 'INFO'
    try {
        Import-Module BitLocker -ErrorAction Stop
        $bitlockerVolumes = Get-BitLockerVolume -ErrorAction SilentlyContinue

        if ($null -eq $bitlockerVolumes -or $bitlockerVolumes.Count -eq 0) {
            Write-Log "Aucun volume BitLocker détecté ou module indisponible." 'INFO'
        } else {
            foreach ($volume in $bitlockerVolumes) {
                $mountPoint = $volume.MountPoint
                $status = $volume.VolumeStatus
                Write-Log "Volume '$mountPoint': Statut='$status', Type='$($volume.VolumeType)', Chiffré=$($volume.EncryptionPercentage)%" 'INFO'

                if ($status -match 'Encrypted|EncryptionInProgress|DecryptionInProgress') {
                    Write-Log "Volume '$mountPoint' est '$status'." 'INFO'
                    try {
                        $recoveryProtector = $volume.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } | Select-Object -First 1
                        if ($recoveryProtector) {
                            Write-Host "--- ATTENTION ---" -ForegroundColor Yellow
                            Write-Host "Clé récupération BitLocker pour '$mountPoint':" -ForegroundColor Yellow
                            Write-Host $recoveryProtector.RecoveryPassword -ForegroundColor Yellow
                            Write-Host "Notez cette clé AVANT de continuer." -ForegroundColor Yellow
                            Read-Host "Appuyez sur Entrée LORSQUE LA CLÉ EST SAUVEGARDÉE..."
                            Write-Log "Clé récupération affichée et confirmée pour '$mountPoint'." 'INFO'
                        } else { Write-Log "Aucune clé récupération (Password) trouvée pour '$mountPoint'." 'INFO' }
                    } catch { Write-Log "Erreur recherche clé récupération pour '$mountPoint'. Erreur: $($_.Exception.Message)" 'WARN' }

                    if ($status -ne 'FullyDecrypted') {
                        Write-Log "Tentative désactivation permanente BitLocker pour '$mountPoint'..." 'INFO'
                        try {
                            Write-Log "Suspension protection BitLocker pour '$mountPoint'..." 'VERBOSE'
                            Suspend-BitLocker -MountPoint $mountPoint -RebootCount 0 -ErrorAction Stop
                            Write-Log "Protection BitLocker suspendue." 'SUCCESS'

                            Write-Log "Tentative nettoyage AutoUnlock (global)..." 'VERBOSE'
                            Clear-BitLockerAutoUnlock -ErrorAction SilentlyContinue | Out-Null # Peut échouer sans risque
                            Write-Log "Clear-BitLockerAutoUnlock exécutée." 'VERBOSE'

                            Write-Log "Lancement déchiffrement '$mountPoint' (Disable-BitLocker)..." 'INFO'
                            Disable-BitLocker -MountPoint $mountPoint -ErrorAction Stop
                            Write-Log "Déchiffrement INITIÉ pour '$mountPoint'. Peut prendre du temps." 'SUCCESS'
                            Write-Log "Vérifier progression avec 'manage-bde -status $mountPoint'." 'INFO'
                            Write-Log "ATTENTION: Des GPO pourraient réactiver BitLocker." 'WARN'

                        } catch { Write-Log "ECHEC désactivation BitLocker pour '$mountPoint'. Erreur: $($_.Exception.Message)" 'ERROR' }
                    } else { Write-Log "Volume '$mountPoint' déjà déchiffré." 'INFO' }
                } else { Write-Log "Volume '$mountPoint' non chiffré ($status)." 'INFO' }
                Write-Log "--- Fin traitement volume '$mountPoint' ---" 'VERBOSE'
            } # Fin foreach volume
        } # Fin else (volumes trouvés)
    } catch { Write-Log "Erreur majeure gestion BitLocker. Erreur: $($_.Exception.Message)" 'ERROR' }
} # Fin else (SkipBitLockerDecryption)
#endregion

#region ===== 5. Installation Logiciels (Chocolatey) =====
Show-Banner 'Installation Chocolatey & Logiciels'

# --- Installation/Vérification de Chocolatey ---
Write-Log "Vérification Chocolatey..." 'INFO'
if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
    Write-Log "Chocolatey non trouvé. Installation..." 'INFO'
    try {
        Set-ExecutionPolicy Bypass -Scope Process -Force
        $installScriptContent = Invoke-RestMethod -Uri 'https://community.chocolatey.org/install.ps1' -UseBasicParsing
        Invoke-Expression $installScriptContent
        if (Get-Command choco -ErrorAction SilentlyContinue) { Write-Log "Chocolatey installé avec succès." 'SUCCESS' }
        else { throw "Vérification post-installation Choco échouée." }
    } catch {
        Write-Log "ERREUR CRITIQUE installation Chocolatey. Les étapes suivantes échoueront. Erreur: $($_.Exception.Message)" 'ERROR'
        # On pourrait arrêter ici: Stop-Transcript; Exit 1
    }
} else { Write-Log "Chocolatey déjà installé." 'SUCCESS' }

# --- Installation Logiciels de Base ---
$basePackages = @('googlechrome', 'firefox', 'adobereader', '7zip.install', 'teamviewer', 'openjdk', 'dotnetfx')
Write-Log "Installation logiciels de base via Choco ($($basePackages -join ', '))..." 'INFO'
foreach ($pkg in $basePackages) {
    Write-Log "Traitement Base: $pkg..." 'VERBOSE'
    if (choco list --local-only --exact $pkg -r) {
        Write-Log "$pkg déjà installé." 'INFO'
    } else {
        Write-Log "Installation $pkg..." 'INFO'
        $chocoArgs = @($pkg, '-y', '--accept-licenses', '--no-progress', '-r', '--limit-output')
        if ($pkg -eq 'googlechrome') { $chocoArgs += '--ignore-checksums' } # Spécifique Chrome

        try {
            choco install @chocoArgs -ErrorAction Stop
            # Vérification simple si choco n'a pas levé d'exception
            if (choco list --local-only --exact $pkg -r) {
                 Write-Log "$pkg installé avec succès." 'SUCCESS'
            } else {
                # Choco n'a pas levé d'erreur mais le paquet n'est pas listé? Étrange.
                 Write-Log "$pkg installé (apparemment), mais non détecté par 'choco list'." 'WARN'
            }
        } catch {
            Write-Log "ECHEC installation $pkg. Erreur: $($_.Exception.Message | Select-Object -First 1) - Le script continue." 'WARN'
             # Log l'erreur mais continue
        }
    }
}
Write-Log "Installation logiciels base terminée (vérifiez WARN/ERROR)." 'SUCCESS'

# --- Installation Logiciels Optionnels (basée sur sélection initiale) ---
Write-Log "Installation logiciels optionnels pré-sélectionnés ($($Script:SelectedOptionalPackages -join ', '))..." 'INFO'
if ($Script:SelectedOptionalPackages.Count -gt 0) {
    foreach ($chocoID in $Script:SelectedOptionalPackages) {
         # Trouve le nom correspondant pour le log (facultatif mais sympa)
         $softwareInfo = $optionalSoftware.Values | Where-Object { $_.ChocoID -eq $chocoID } | Select-Object -First 1
         $pkgName = if ($softwareInfo) { $softwareInfo.Name } else { $chocoID }

         Write-Log "Traitement Optionnel: $pkgName ($chocoID)..." 'VERBOSE'
         if (choco list --local-only --exact $chocoID -r) {
            Write-Log "$pkgName ($chocoID) déjà installé." 'INFO'
         } else {
             Write-Log "Installation $pkgName ($chocoID)..." 'INFO'
             if ($chocoID -eq 'office365business') {
                 Write-Log "Note: L'installation de Microsoft 365 peut prendre beaucoup de temps..." 'INFO'
             }
             try {
                 choco install $chocoID -y --accept-licenses --no-progress -r --limit-output -ErrorAction Stop
                 if (choco list --local-only --exact $chocoID -r) {
                     Write-Log "$pkgName ($chocoID) installé avec succès." 'SUCCESS'
                 } else {
                     Write-Log "$pkgName ($chocoID) installé (apparemment), mais non détecté par 'choco list'." 'WARN'
                 }
             } catch {
                 Write-Log "ECHEC installation $pkgName ($chocoID). Paquet peut ne pas exister sur repo public ou erreur. Erreur: $($_.Exception.Message | Select-Object -First 1) - Le script continue." 'WARN'
             }
         }
    }
     Write-Log "Installation logiciels optionnels terminée." 'SUCCESS'
} else {
    Write-Log "Aucun logiciel optionnel à installer." 'INFO'
}
#endregion

#region ===== 6. Confidentialité & Optimisation =====
Show-Banner 'Configuration Confidentialité & Optimisation'

Write-Log "Configuration paramètres confidentialité Windows..." 'INFO'
# Publicité ID, Langue sites web, Suivi lancement apps, Contenus suggérés Paramètres
Set-RegValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo' -Name 'Enabled' -Value 0
Set-RegValue -Path 'HKCU:\Control Panel\International\User Profile' -Name 'HttpAcceptLanguageOptOut' -Value 1
Set-RegValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Privacy' -Name 'Start_TrackProgs' -Value 0
Set-RegValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SubscribedContent-338389Enabled' -Value 0
Set-RegValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SubscribedContent-310093Enabled' -Value 0
Set-RegValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SubscribedContent-338387Enabled' -Value 0
Set-RegValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SystemPaneSuggestionsEnabled' -Value 0
Write-Log "Paramètres confidentialité OK." 'SUCCESS'

Write-Log "Désactivation Fonctionnalités Jeu (Game Bar, Mode Jeu)..." 'INFO'
Set-RegValue -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'AllowAutoGameMode' -Value 0
Set-RegValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR' -Name 'AppCaptureEnabled' -Value 0
Write-Log "Fonctionnalités Jeu désactivées." 'SUCCESS'

Write-Log "Activation MàJ autres produits Microsoft & PSWindowsUpdate..." 'INFO'
# Activation 'Autres produits Microsoft' via Policy
Set-RegValue -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'AllowMUUpdateService' -Value 1
Set-RegValue -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'IncludeRecommendedUpdates' -Value 1 # Peut être redondant mais ne nuit pas
# Installation module PSWindowsUpdate
if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
    Write-Log "Installation module PSWindowsUpdate..." 'INFO'
    try {
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Confirm:$false -ErrorAction Stop | Out-Null
        Install-Module -Name PSWindowsUpdate -Force -Confirm:$false -ErrorAction Stop -Scope AllUsers | Out-Null
        Write-Log "Module PSWindowsUpdate installé." 'SUCCESS'
    } catch { Write-Log "ECHEC installation module PSWindowsUpdate. Erreur: $($_.Exception.Message)" 'ERROR' }
} else { Write-Log "Module PSWindowsUpdate déjà présent." 'INFO' }

Write-Log "Configuration Optimisation Livraison (Pas de Peer)..." 'INFO'
Set-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config' -Name 'DODownloadMode' -Value 0
Write-Log "Optimisation Livraison configurée." 'SUCCESS'

Write-Log "Désactivation apps au démarrage (OneDrive, Edge, Copilot)..." 'INFO'
# OneDrive
Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'OneDrive' -ErrorAction SilentlyContinue
Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Name 'DisableFileSyncNGSC' -Value 1
# Edge Startup Boost & Run Key
Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name 'StartupBoostEnabled' -Value 0
Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'MicrosoftEdgeAutoLaunch*' -ErrorAction SilentlyContinue
# Copilot Button & Policy
Set-RegValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'ShowCopilotButton' -Value 0
Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot' -Name 'TurnOffWindowsCopilot' -Value 1
Write-Log "Apps démarrage désactivées/limitées." 'SUCCESS'

Write-Log "Suppression 'Premier Lancement' (Chrome, Firefox, Adobe)..." 'INFO'
# Chrome First Run suppression
Set-RegValue -Path 'HKLM\SOFTWARE\Policies\Google\Chrome' -Name 'SuppressFirstRunDefaultBrowserPrompt' -Value 1
Set-RegValue -Path 'HKLM\SOFTWARE\Policies\Google\Chrome' -Name 'HideFirstRunBubble' -Value 1
# Firefox First Run suppression (about:welcome)
Set-RegValue -Path 'HKLM\SOFTWARE\Policies\Mozilla\Firefox' -Name 'DisableAppUpdate' -Value 1 # Optionnel: désactiver update interne FF
Set-RegValue -Path 'HKLM\SOFTWARE\Policies\Mozilla\Firefox' -Name 'OfferToSaveLogins' -Value 0 # Optionnel
# Adobe Reader Welcome Screen & Upsell & Services
Set-RegValue -Path 'HKLM\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown' -Name 'bShowWelcomeScreen' -Value 0
Set-RegValue -Path 'HKLM\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown' -Name 'bShowAdsAllow' -Value 0
Set-RegValue -Path 'HKLM\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices' -Name 'bToggleAdobeDocumentServices' -Value 1 # 1 = Disable
Set-RegValue -Path 'HKLM\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices' -Name 'bToggleAdobeSign' -Value 1
Set-RegValue -Path 'HKLM\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices' -Name 'bToggleSendAndTrack' -Value 1
Write-Log "Tentatives suppression 'Premier Lancement' effectuées." 'SUCCESS'

Write-Log "Configuration Confidentialité & Optimisation terminée." 'SUCCESS'
#endregion

#region ===== 7. Installation Outils Fabricant =====
Show-Banner 'Installation Outils Fabricant'
Write-Log "Vérification outils fabricant..." 'INFO'
if (Test-Path $DataPath) {
    try {
        $manufacturer = (Get-CimInstance Win32_ComputerSystem).Manufacturer
        Write-Log "Fabricant détecté: $manufacturer" 'INFO'
        $toolLaunched = $false
        switch -Wildcard ($manufacturer) {
            '*Dell*' { $toolPattern = 'DellCommandUpdate*.exe'; $toolName = "Dell Command Update" }
            '*HP*'   { $toolPattern = 'sp*.exe'; $toolName = "Outil HP" } # Adaptez le pattern si nécessaire
            # '*Lenovo*' { $toolPattern = 'LenovoVantage*.exe'; $toolName = "Lenovo Vantage" }
            default  { $toolPattern = $null; Write-Log "Aucun traitement spécifique pour '$manufacturer'." 'INFO' }
        }
        if ($toolPattern) {
            $toolPath = Get-ChildItem -Path $DataPath -Filter $toolPattern -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($toolPath) {
                Write-Log "Outil $toolName trouvé: $($toolPath.FullName). Lancement silencieux..." 'INFO'
                Start-Process -FilePath $toolPath.FullName -ArgumentList '/s','/norestart' -Wait -ErrorAction Stop
                Write-Log "Installation/MàJ $toolName terminée." 'SUCCESS'
            } else { Write-Log "Fichier $toolName ($toolPattern) non trouvé dans $DataPath." 'INFO' }
        }
    } catch { Write-Log "Erreur installation outil fabricant. Erreur: $($_.Exception.Message)" 'WARN' }
} else { Write-Log "Répertoire 'Data' non trouvé, outils fabricant ignorés." 'WARN' }
#endregion

#region ===== 8. Installation GoToAssist =====
Show-Banner 'Installation GoToAssist'
Write-Log "Installation GoToAssist depuis Data..." 'INFO'
$goToAssistSource = Join-Path $DataPath 'GoToAssist.exe'
$goToAssistDestDir = Join-Path $env:ProgramFiles 'GoToAssist'
$goToAssistDestExe = Join-Path $goToAssistDestDir 'GoToAssist.exe'
$commonDesktop = [Environment]::GetFolderPath('CommonDesktopDirectory')
$shortcutLinkPath = Join-Path $commonDesktop 'GoToAssist.lnk'

if (Test-Path $goToAssistSource) {
    try {
        if (-not (Test-Path $goToAssistDestDir)) {
            New-Item -Path $goToAssistDestDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
        Copy-Item -Path $goToAssistSource -Destination $goToAssistDestExe -Force -ErrorAction Stop
        Write-Log "GoToAssist.exe copié." 'SUCCESS'
        New-Shortcut -ShortcutPath $shortcutLinkPath -TargetPath $goToAssistDestExe -Description "Lancer GoToAssist Remote Support"
    } catch { Write-Log "Erreur installation/raccourci GoToAssist. Erreur: $($_.Exception.Message)" 'ERROR' }
} else { Write-Log "GoToAssist.exe non trouvé dans '$DataPath'. Ignoré." 'WARN' }
#endregion

#region ===== 9. Configuration Informations OEM =====
Show-Banner 'Configuration Informations OEM'
Write-Log "Configuration informations OEM..." 'INFO'
$oemRegPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation'
try {
    if (-not (Test-Path $oemRegPath)) { New-Item $oemRegPath -Force -ErrorAction Stop | Out-Null }
    foreach ($key in $SupportInfo.Keys) { Set-RegValue -Path $oemRegPath -Name $key -Value $SupportInfo[$key] -Type String }
    Write-Log "Informations OEM configurées." 'SUCCESS'
} catch { Write-Log "Erreur config infos OEM. Erreur: $($_.Exception.Message)" 'WARN' }
#endregion

#region ===== 10. Raccourcis & Épinglage Barre des Tâches =====
Show-Banner 'Création Raccourcis & Épinglage'
Write-Log "*** AVERTISSEMENT: Épinglage barre des tâches nécessite OS en Français. ***" 'WARN'

# --- Raccourci Adobe Reader sur Bureau Public ---
Write-Log "Création raccourci Adobe Reader..." 'INFO'
$adobeExePaths = @(
    "$env:ProgramFiles\Adobe\Acrobat DC\Acrobat\Acrobat.exe",
    "$env:ProgramFiles\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe", # Nom commun pour Reader DC
    "$env:ProgramFiles(x86)\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe"
)
$adobeExecutable = $adobeExePaths | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($adobeExecutable) {
    # Le nom du lien doit correspondre à ce qu'on cherche à épingler ensuite
    $adobeLinkName = "Adobe Acrobat Reader DC.lnk" # Ou "Acrobat Reader.lnk" ? Tester.
    $adobeShortcutPath = Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) $adobeLinkName
    New-Shortcut -ShortcutPath $adobeShortcutPath -TargetPath $adobeExecutable -Description "Ouvrir Adobe Acrobat Reader DC"
} else { Write-Log "EXE Adobe non trouvé. Pas de raccourci créé." 'WARN' }

# --- Épinglage Barre des Tâches (Chrome, Firefox, Adobe) ---
Write-Log "Tentative épinglage Chrome, Firefox, Adobe Reader (OS FR requis)..." 'INFO'
$programsPath = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs"
$startMenuPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs" # Aussi vérifier le menu démarrer perso
$appsToPin = @(
    @{ LinkName = 'Google Chrome.lnk'; AppName = 'Google Chrome'; SearchPaths = @($programsPath) }
    @{ LinkName = 'Firefox.lnk'; AppName = 'Mozilla Firefox'; SearchPaths = @($programsPath, "$programsPath\Mozilla Firefox") }
    @{ LinkName = 'Adobe Acrobat Reader DC.lnk'; AppName = 'Adobe Reader'; SearchPaths = @($programsPath) } # Le nom exact du .lnk peut varier
)
$pinVerb = 'Épingler à la barre des tâches'

foreach ($app in $appsToPin) {
    $foundLinkPath = $null
    foreach($searchPath in $app.SearchPaths) {
        $potentialLink = Join-Path $searchPath $app.LinkName
        if (Test-Path $potentialLink) {
            $foundLinkPath = $potentialLink
            break
        }
    }

    if ($foundLinkPath) {
        Write-Log "Lien trouvé pour $($app.AppName): '$foundLinkPath'" 'VERBOSE'
        try {
            $folder = Split-Path $foundLinkPath
            $file = Split-Path $foundLinkPath -Leaf
            $shellApp = New-Object -ComObject Shell.Application
            $folderItem = $shellApp.Namespace($folder).ParseName($file)
            $verb = $folderItem.Verbs() | Where-Object { $_.Name -eq $pinVerb }

            if ($verb) {
                $verb.DoIt()
                Write-Log "$($app.AppName) épinglé (tentative)." 'SUCCESS'
            } else { Write-Log "Verbe '$pinVerb' non trouvé pour $($app.AppName). OS non FR ou déjà épinglé?" 'WARN' }
        } catch { Write-Log "Erreur épinglage $($app.AppName). Erreur: $($_.Exception.Message)" 'WARN' }
    } else { Write-Log "Lien '$($app.LinkName)' non trouvé pour $($app.AppName) dans chemins connus. Impossible d'épingler." 'WARN' }
}
Write-Log "Épinglage terminé (vérifier WARN)." 'INFO'
#endregion

#region ===== 11. Définition PDF par Défaut (Tentative) =====
Show-Banner 'Définition PDF par défaut (Adobe)'
Write-Log "*** AVERTISSEMENT: La définition du gestionnaire PDF par défaut est une tentative et peut échouer. ***" 'WARN'
Write-Log "Tentative de définition d'Adobe Reader comme application PDF par défaut via assoc/ftype..." 'INFO'
# Méthode 1: Via assoc/ftype (plus simple, moins fiable sur Win10+)
# 1. Trouver le ProgID d'Adobe Reader (peut varier)
$adobeProgId = $null
$possibleProgIds = @('AcroExch.Document.DC', 'Acrobat.Document.DC', 'AcroExch.Document.11', 'AcroExch.Document.7') # Liste à adapter
foreach ($progId in $possibleProgIds) {
    if (Get-Item -Path "HKLM:\SOFTWARE\Classes\$progId" -ErrorAction SilentlyContinue) {
        $adobeProgId = $progId
        Write-Log "ProgID Adobe trouvé: $adobeProgId" 'VERBOSE'
        break
    }
}

if ($adobeProgId) {
    try {
        Write-Log "Association de .pdf avec $adobeProgId..." 'VERBOSE'
        cmd.exe /c "assoc .pdf=$adobeProgId"
        # Ftype n'est généralement pas nécessaire si le ProgId est correctement défini par l'installeur
        # cmd.exe /c "ftype $adobeProgId=`"$adobeExecutable`" `"%1`"" # Nécessiterait de retrouver $adobeExecutable
        Write-Log "Association .pdf effectuée (vérifier résultat manuellement)." 'SUCCESS'
    } catch {
        Write-Log "Erreur lors de l'exécution de assoc. Erreur: $($_.Exception.Message)" 'WARN'
    }
} else {
    Write-Log "ProgID Adobe non trouvé dans le registre. Impossible d'associer .pdf automatiquement." 'WARN'
}
# Méthode 2 (Commentée): Via UserChoice (plus complexe, nécessite contexte user ou droits spécifiques)
# $pdfUserChoicePath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.pdf\UserChoice"
# if ($adobeProgId -and (Test-Path $pdfUserChoicePath)) {
#     try {
#         # Calculer le Hash (complexe, spécifique à l'utilisateur/machine)
#         # ... code pour calculer le Hash ...
#         Set-ItemProperty -Path $pdfUserChoicePath -Name "ProgId" -Value $adobeProgId -Force
#         Set-ItemProperty -Path $pdfUserChoicePath -Name "Hash" -Value $calculatedHash -Force
#         Write-Log "Tentative de définition UserChoice pour .pdf (peut échouer)." 'INFO'
#     } catch { Write-Log "Erreur UserChoice .pdf. Erreur: $($_.Exception.Message)" 'WARN' }
# }
#endregion

#region ===== 12. Mises à jour Windows (via PSWindowsUpdate) =====
Show-Banner 'Mises à Jour Windows'
if ($SkipWindowsUpdate) {
    Write-Log "MàJ Windows ignorées (-SkipWindowsUpdate)." 'INFO'
} else {
    Write-Log "Recherche et installation MàJ Windows (peut être long)..." 'INFO'
    if (Get-Command Install-WindowsUpdate -ErrorAction SilentlyContinue) {
        try {
            Import-Module PSWindowsUpdate -Force -ErrorAction Stop
            Write-Log "Lancement Install-WindowsUpdate (-MicrosoftUpdate -AcceptAll -IgnoreReboot)..." 'INFO'
            $updateResult = Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot -Verbose #-ErrorAction Stop # On enlève Stop pour voir si ça log mieux l'erreur WU elle-même
            Write-Log "Commande Install-WindowsUpdate terminée." 'SUCCESS'
            Write-Log "Résultat (détaillé dans transcript): $($updateResult | Select-Object -First 5 | Out-String)" 'VERBOSE' # Log juste un extrait

            if ($updateResult | Where-Object { $_.RebootRequired }) {
                 Write-Log "ATTENTION: REDÉMARRAGE REQUIS pour finaliser les MàJ." 'WARN'
            } else {
                 Write-Log "Aucune MàJ ne signale un redémarrage requis (mais recommandé)." 'INFO'
            }
        } catch { Write-Log "Erreur pendant exécution Install-WindowsUpdate. Erreur: $($_.Exception.Message)" 'ERROR' }
    } else { Write-Log "Module PSWindowsUpdate non trouvé/importé. MàJ Windows ignorées." 'ERROR' }
}
#endregion

#region ===== Finalisation =====
Show-Banner 'Finalisation'
Write-Log "Script déploiement Koesio Aquitaine v$ScriptVersion terminé." 'SUCCESS'
Write-Log "Vérifiez les messages WARN et ERROR dans log: $LogFile" 'INFO'
Write-Log "*** REDÉMARRAGE FORTEMENT RECOMMANDÉ ***" 'WARN'

try { Stop-Transcript } catch { Write-Warning "Impossible d'arrêter transcript. Erreur: $($_.Exception.Message)" }
#endregion