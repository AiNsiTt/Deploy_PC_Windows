<#
.SYNOPSIS
Script de préparation et de déploiement initial pour les postes clients Koesio (v3.1).
Utilise Chocolatey pour l'installation des logiciels.

.DESCRIPTION
Ce script automatise les tâches suivantes :
- Vérification des droits administrateur.
- Configuration du nom de l'ordinateur.
- Application des paramètres système de base.
- Gestion de BitLocker (affichage clé, déchiffrement optionnel).
- Installation de Chocolatey (si absent).
- Installation des logiciels de base et dépendances via Chocolatey (Navigateurs, PDF, Archiveur, Runtimes).
- Installation optionnelle de Microsoft 365 Business via Chocolatey.
- Installation des outils constructeur (Dell/HP).
- Installation PRO spécifique (GoToAssist).
- Configuration des informations OEM.
- Installation des mises à jour Windows via PSWindowsUpdate.
- Nettoyage final (via RunOnce).

.PARAMETER InstallationType
Type d'installation à réaliser (PRO/PART). Obligatoire.

.PARAMETER ComputerName
Nom spécifique à donner à l'ordinateur.

.PARAMETER UseSerialNumberName
Utiliser le numéro de série comme nom d'ordinateur.

.PARAMETER SkipBitLockerDecryption
Ne pas proposer le déchiffrement BitLocker.

.PARAMETER SkipWindowsUpdate
Ne pas lancer l'installation des mises à jour Windows.

.EXAMPLE
.\Deploy.ps1 -InstallationType PRO -UseSerialNumberName

.EXAMPLE
.\Deploy.ps1 -InstallationType PART -ComputerName CLIENTPC01 -SkipWindowsUpdate

.NOTES
Version: 3.1.2025 (Chocolatey Edition)
Auteur: [Votre Nom/Équipe Koesio] & AI Assistant
Date: 2025-04-14
Requires: PowerShell 5.1+, Internet. Exécuter en admin.
Assume que l'OS Windows est en français pour que les logiciels s'installent en FR par défaut.
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$true, HelpMessage = "Type d'installation (PRO/PART)")]
    [ValidateSet("PRO", "PART")]
    [string]$InstallationType,

    [Parameter(HelpMessage = "Nom spécifique pour l'ordinateur")]
    [string]$ComputerName,

    [Parameter(HelpMessage = "Utiliser le numéro de série comme nom")]
    [switch]$UseSerialNumberName,

    [Parameter(HelpMessage = "Ne pas proposer le déchiffrement BitLocker")]
    [switch]$SkipBitLockerDecryption,

    [Parameter(HelpMessage = "Passer l'étape des mises à jour Windows")]
    [switch]$SkipWindowsUpdate
)

#region Global Variables and Initial Setup
$ScriptVersion = "3.1.2025"
$CompanyName = "Koesio Aquitaine"
$SupportInfo = @{
    Manufacturer = $CompanyName
    SupportHours = "08H30 - 12H30 | 14H00 - 17H30"
    SupportPhone = "05 57 51 52 52 - 1A Avenue Bernard Moitessier, 17180 Périgny"
    SupportURL   = "https://www.koesio.com/"
}

if ($PSScriptRoot -eq $null) { $PSScriptRoot = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition }
$DataPath = Join-Path -Path $PSScriptRoot -ChildPath "Data"
$LogPath = Join-Path -Path $PSScriptRoot -ChildPath "Logs"

if (-not (Test-Path -Path $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
}
$LogFile = Join-Path -Path $LogPath -ChildPath "Deploy_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $LogFile -Append

# --- Fonctions Utilitaires (Write-Log, Show-Banner, Check-Admin, New-ShortcutHelper, Start-SilentProcess) ---
# Reprendre les fonctions de la version 3.0 (fournies dans la réponse précédente) ici...
# ... (copier/coller les fonctions ici) ...
Function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [string]$Level = "INFO", # INFO, WARN, ERROR, SUCCESS, STEP
        [ConsoleColor]$ForegroundColor = $Host.UI.RawUI.ForegroundColor,
        [ConsoleColor]$BackgroundColor = $Host.UI.RawUI.BackgroundColor
    )
    $Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $FormattedMessage = "[$Timestamp] [$Level] $Message"
    if ($PSBoundParameters.ContainsKey('ForegroundColor') -or $PSBoundParameters.ContainsKey('BackgroundColor')) {
        Write-Host $FormattedMessage -ForegroundColor $ForegroundColor -BackgroundColor $BackgroundColor
    } else {
        switch ($Level) {
            "INFO"    { Write-Host $FormattedMessage }
            "WARN"    { Write-Host $FormattedMessage -ForegroundColor Yellow }
            "ERROR"   { Write-Host $FormattedMessage -ForegroundColor Red }
            "SUCCESS" { Write-Host $FormattedMessage -ForegroundColor Green }
            "STEP"    { Write-Host $FormattedMessage -ForegroundColor Cyan }
            default   { Write-Host $FormattedMessage }
        }
    }
}

Function Show-Banner {
    param([string]$CurrentStep = "Initialisation")
    Clear-Host
    $Line = " " * 79
    Write-Host -Object $Line -ForegroundColor Black -BackgroundColor Green
    Write-Host -Object "         PROGRAMME DE PREPARATION DE POSTE $CompanyName         " -ForegroundColor Black -BackgroundColor Green
    Write-Host -Object "                            Version $ScriptVersion                           " -ForegroundColor Black -BackgroundColor Green
    Write-Host -Object "                            Étape : $CurrentStep                            " -ForegroundColor Black -BackgroundColor Green
    Write-Host -Object $Line -ForegroundColor Black -BackgroundColor Green
    Write-Host ""
    Write-Log -Level "STEP" -Message "Début de l'étape : $CurrentStep"
}

Function Check-Admin {
    Write-Log -Level "INFO" -Message "Vérification des droits administrateur..."
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Log -Level "ERROR" -Message "Ce script doit être exécuté avec des privilèges administrateur."
        Write-Log -Level "ERROR" -Message "Veuillez relancer le script avec 'Exécuter en tant qu'administrateur'."
        Stop-Transcript
        Exit 1
    }
    Write-Log -Level "SUCCESS" -Message "Droits administrateur confirmés."
}

Function New-ShortcutHelper {
    param(
        [parameter(Mandatory=$true)][string]$ShortcutFullName,
        [parameter(Mandatory=$true)][string]$ShortcutTarget,
        [string]$WorkingDirectory,
        [string]$IconLocation,
        [string]$Description
    )
    try {
        Write-Log -Level "INFO" -Message "Création du raccourci '$ShortcutFullName' pointant vers '$ShortcutTarget'"
        $ShortcutObject = New-Object -ComObject WScript.Shell
        $Shortcut = $ShortcutObject.CreateShortcut($ShortcutFullName)
        $Shortcut.TargetPath = $ShortcutTarget
        if ($WorkingDirectory) { $Shortcut.WorkingDirectory = $WorkingDirectory }
        if ($IconLocation) { $Shortcut.IconLocation = $IconLocation }
        if ($Description) { $Shortcut.Description = $Description }
        $Shortcut.Save()
        Write-Log -Level "SUCCESS" -Message "Raccourci '$ShortcutFullName' créé."
        return $true
    } catch {
        Write-Log -Level "ERROR" -Message "Impossible de créer le raccourci '$ShortcutFullName'. Erreur : $($_.Exception.Message)"
        return $false
    }
}

Function Start-SilentProcess {
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath,
        [string]$Arguments,
        [string]$LogId # Identifiant pour les logs
    )
    Write-Log -Level "INFO" -Message "Lancement de l'installation ($LogId): $FilePath $Arguments"
    if (-not (Test-Path -Path $FilePath)) {
        Write-Log -Level "ERROR" -Message "Fichier d'installation introuvable : $FilePath"
        return $false
    }
    try {
        $Process = Start-Process -FilePath $FilePath -ArgumentList $Arguments -Wait -PassThru -ErrorAction Stop
        if ($Process.ExitCode -ne 0) {
            Write-Log -Level "WARN" -Message "L'installation ($LogId) s'est terminée avec un code de sortie non nul : $($Process.ExitCode). L'installation peut avoir échoué."
            return $true # Continuer malgré l'avertissement
        } else {
            Write-Log -Level "SUCCESS" -Message "Installation ($LogId) terminée avec succès (code de sortie 0)."
            return $true
        }
    } catch {
        Write-Log -Level "ERROR" -Message "Erreur lors du lancement de l'installation ($LogId) '$FilePath'. Erreur : $($_.Exception.Message)"
        return $false
    }
}
#endregion

#region Main Script Logic

# --- 1. Initial Checks & Banner ---
Check-Admin
Show-Banner -CurrentStep "Vérifications initiales"
Write-Log -Level "INFO" -Message "Script de déploiement Koesio v$ScriptVersion démarré."
Write-Log -Level "INFO" -Message "Type d'installation choisi : $InstallationType"

# --- 2. Computer Naming ---
Show-Banner -CurrentStep "Configuration du nom du PC"
# ... (copier/coller la section 2 de la v3.0 ici) ...
$ComputerInfo = Get-CimInstance Win32_ComputerSystem
$BiosInfo = Get-CimInstance Win32_BIOS
$SerialNumber = $BiosInfo.SerialNumber.Trim()
$Manufacturer = $BiosInfo.Manufacturer.Trim()
$CurrentName = $ComputerInfo.Name
Write-Log -Level "INFO" -Message "Nom actuel : $CurrentName | Fabricant : $Manufacturer | S/N : $SerialNumber"
$NewName = $null
$RenameNeeded = $false
if ($UseSerialNumberName) {
    if ($CurrentName -ne $SerialNumber) {
        $NewName = $SerialNumber
        $RenameNeeded = $true
        Write-Log -Level "INFO" -Message "Option -UseSerialNumberName détectée. Nouveau nom sera : $NewName"
    } else { Write-Log -Level "INFO" -Message "Le nom actuel correspond déjà au numéro de série." }
} elseif (-not [string]::IsNullOrWhiteSpace($ComputerName)) {
    if ($CurrentName -ne $ComputerName) {
        $NewName = $ComputerName
        $RenameNeeded = $true
        Write-Log -Level "INFO" -Message "Option -ComputerName fournie. Nouveau nom sera : $NewName"
    } else { Write-Log -Level "INFO" -Message "Le nom actuel correspond déjà au nom fourni." }
} else {
    $PromptTitle = "Nom de l'ordinateur"
    $PromptMsg = "Voulez-vous utiliser le numéro de série '$SerialNumber' comme nom de PC ? (O/N)"
    $Choices = [System.Management.Automation.Host.ChoiceDescription[]]@('&Oui', '&Non')
    $ChoiceResult = $Host.UI.PromptForChoice($PromptTitle, $PromptMsg, $Choices, 0)
    if ($ChoiceResult -eq 0) { # Oui
        if ($CurrentName -ne $SerialNumber) { $NewName = $SerialNumber; $RenameNeeded = $true }
    } else { # Non
        do {
            $CustomName = Read-Host "Entrez le nom souhaité pour le PC (laisser vide pour garder '$CurrentName')"
            if ([string]::IsNullOrWhiteSpace($CustomName)) { $RenameNeeded = $false; break }
            elseif ($CustomName -match '^[a-zA-Z0-9-]{1,63}$') {
                if ($CurrentName -ne $CustomName) { $NewName = $CustomName; $RenameNeeded = $true; break }
                else { $RenameNeeded = $false; break }
            } else { Write-Log -Level "WARN" -Message "Nom invalide." }
        } while ($true)
    }
}
if ($RenameNeeded -and $NewName) {
    Write-Log -Level "INFO" -Message "Tentative de renommage du PC vers '$NewName'..."
    try {
        if ($PSCmdlet.ShouldProcess($CurrentName, "Renommer en '$NewName'")) {
            Rename-Computer -NewName $NewName -Force -ErrorAction Stop
            Write-Log -Level "SUCCESS" -Message "Renommage réussi. Redémarrage nécessaire."
        } else { Write-Log -Level "INFO" -Message "Renommage annulé (-WhatIf)." }
    } catch { Write-Log -Level "ERROR" -Message "Échec du renommage. Erreur : $($_.Exception.Message)" }
} else { Write-Log -Level "INFO" -Message "Aucun renommage nécessaire." }
Pause

# --- 3. Basic System Configuration ---
Show-Banner -CurrentStep "Configuration Système de Base"
# ... (copier/coller la section 3 de la v3.0 ici) ...
Write-Log -Level "INFO" -Message "Configuration des icônes du bureau..."
$IconPaths = @("HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel", "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")
$Icons = @{ "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" = 0; "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" = 0; "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" = 0 }
foreach ($path in $IconPaths) {
    if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
    foreach ($guid in $Icons.Keys) {
        try { Set-ItemProperty -Path $path -Name $guid -Value $Icons[$guid] -Type DWORD -Force -ErrorAction Stop }
        catch { Write-Log -Level "WARN" -Message "Impossible de définir l'icône $guid dans $path. Erreur: $($_.Exception.Message)" }
    }
}
Write-Log -Level "SUCCESS" -Message "Icônes du bureau configurées."
Write-Log -Level "INFO" -Message "Activation du verrouillage du pavé numérique..."
try {
    $NumlockPath = "Registry::HKEY_USERS\.DEFAULT\Control Panel\Keyboard"
    if (-not (Test-Path $NumlockPath)) { New-Item -Path $NumlockPath -Force | Out-Null }
    Set-ItemProperty -Path $NumlockPath -Name "InitialKeyboardIndicators" -Value "2" -Type String -Force -ErrorAction Stop
    Write-Log -Level "SUCCESS" -Message "Verrouillage pavé numérique activé."
} catch { Write-Log -Level "WARN" -Message "Impossible de définir le verrouillage. Erreur: $($_.Exception.Message)" }
Write-Log -Level "INFO" -Message "Configuration des paramètres d'alimentation..."
try {
    powercfg /change monitor-timeout-ac 60
    powercfg /change monitor-timeout-dc 60
    powercfg /change standby-timeout-ac 0
    powercfg /change standby-timeout-dc 0
    Write-Log -Level "SUCCESS" -Message "Alimentation configurée (Écran: 60 min, Veille: Jamais)."
} catch { Write-Log -Level "WARN" -Message "Impossible de configurer l'alimentation. Erreur: $($_.Exception.Message)" }
Pause

# --- 4. BitLocker Management ---
Show-Banner -CurrentStep "Gestion BitLocker"
# ... (copier/coller la section 4 de la v3.0 ici) ...
$BitlockerVolumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
if ($BitlockerVolumes) {
    foreach ($Volume in $BitlockerVolumes) {
        Write-Log -Level "INFO" -Message "Volume $($Volume.MountPoint) - Statut: $($Volume.VolumeStatus)"
        if ($Volume.VolumeStatus -match "Encrypted" -or $Volume.VolumeStatus -eq "EncryptionInProgress") {
            Write-Log -Level "WARN" -Message "Volume $($Volume.MountPoint) chiffré."
            Write-Log -Level "INFO" -Message "Récupération de la clé..."
            $RecoveryKey = $null
            try {
                $Protectors = Get-BitLockerVolume -MountPoint $Volume.MountPoint | Select-Object -ExpandProperty KeyProtector
                $RecoveryProtector = $Protectors | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } | Select-Object -First 1
                if ($RecoveryProtector) {
                    $RecoveryKey = $RecoveryProtector.RecoveryPassword
                    Write-Host "`n`n-------------------------------------------------------------------------------" -BackgroundColor Black -ForegroundColor Yellow
                    Write-Host " ATTENTION : CLÉ BITLOCKER POUR $($Volume.MountPoint)" -BackgroundColor Black -ForegroundColor Yellow
                    Write-Host " SAUVEGARDER cette clé IMMÉDIATEMENT dans un endroit sûr !" -BackgroundColor Black -ForegroundColor Yellow
                    Write-Host " Clé : $RecoveryKey" -BackgroundColor Black -ForegroundColor Cyan
                    Write-Host "-------------------------------------------------------------------------------`n`n" -BackgroundColor Black -ForegroundColor Yellow
                    Read-Host "Appuyez sur ENTRÉE UNIQUEMENT après avoir sauvegardé cette clé"
                    Write-Log -Level "SUCCESS" -Message "Clé affichée pour $($Volume.MountPoint). Confirmation utilisateur."
                } else { Write-Log -Level "WARN" -Message "Clé de récupération numérique introuvable pour $($Volume.MountPoint)." }
            } catch { Write-Log -Level "ERROR" -Message "Erreur récupération clé BitLocker pour $($Volume.MountPoint). Erreur : $($_.Exception.Message)" }

            if (-not $SkipBitLockerDecryption) {
                 if ($Volume.VolumeStatus -ne "FullyDecrypted") {
                    $PromptTitle = "Déchiffrement BitLocker"
                    $PromptMsg = "Volume $($Volume.MountPoint) chiffré. Lancer le déchiffrement ? (Long)"
                    $Choices = [System.Management.Automation.Host.ChoiceDescription[]]@('&Oui', '&Non')
                    $ChoiceResult = $Host.UI.PromptForChoice($PromptTitle, $PromptMsg, $Choices, 1) # Non par défaut
                    if ($ChoiceResult -eq 0) { # Oui
                        Write-Log -Level "INFO" -Message "Lancement déchiffrement pour $($Volume.MountPoint)..."
                        try {
                            Clear-BitLockerAutoUnlock -MountPoint $Volume.MountPoint -ErrorAction SilentlyContinue
                            if ($PSCmdlet.ShouldProcess($Volume.MountPoint, "Désactiver BitLocker")) {
                                Disable-BitLocker -MountPoint $Volume.MountPoint -ErrorAction Stop
                                Write-Log -Level "SUCCESS" -Message "Déchiffrement démarré pour $($Volume.MountPoint)."
                            } else { Write-Log -Level "INFO" -Message "Déchiffrement annulé (-WhatIf)." }
                        } catch { Write-Log -Level "ERROR" -Message "Erreur déchiffrement pour $($Volume.MountPoint). Erreur : $($_.Exception.Message)" }
                    } else { Write-Log -Level "INFO" -Message "Déchiffrement ignoré pour $($Volume.MountPoint)." }
                }
            } else { Write-Log -Level "INFO" -Message "Déchiffrement non proposé (-SkipBitLockerDecryption)." }
        } elseif ($Volume.VolumeStatus -eq "FullyDecrypted") {
            Write-Log -Level "INFO" -Message "Volume $($Volume.MountPoint) déjà déchiffré."
        } else { Write-Log -Level "WARN" -Message "Statut BitLocker non géré pour $($Volume.MountPoint): $($Volume.VolumeStatus)" }
        Pause
    }
} else { Write-Log -Level "INFO" -Message "Aucun volume BitLocker détecté." }

# --- 5. Software Installation via Chocolatey ---
Show-Banner -CurrentStep "Installation Logiciels (Chocolatey)"

# Installation/Vérification Chocolatey
Write-Log -Level "INFO" -Message "Vérification/Installation de Chocolatey..."
if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
    Write-Log -Level "INFO" -Message "Chocolatey non trouvé. Installation..."
    try {
        Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
        if (Get-Command choco -ErrorAction SilentlyContinue) { Write-Log -Level "SUCCESS" -Message "Chocolatey installé." }
        else { Throw "Chocolatey n'a pas pu être installé/détecté." }
    } catch {
        Write-Log -Level "ERROR" -Message "Échec installation Chocolatey. Erreur : $($_.Exception.Message)"
        Write-Log -Level "ERROR" -Message "Les installations via Chocolatey seront ignorées."
        # Envisager d'arrêter le script ici ? Pour l'instant, on continue.
    }
} else {
    Write-Log -Level "SUCCESS" -Message "Chocolatey est déjà installé."
    # Optionnel: choco upgrade chocolatey -y
}

# Installation des logiciels via Chocolatey (si disponible)
if (Get-Command choco -ErrorAction SilentlyContinue) {
    # Liste des paquets Chocolatey OBLIGATOIRES
    $ChocoPackagesMandatory = @(
        "firefox",              # Navigateur [9]
        "googlechrome",         # Navigateur [10]
        "adobereader",          # Lecteur PDF (version MUI) [11]
        "7zip.install",         # Archiveur (ou "7zip") [12]
        "teamviewer",           # Prise en main à distance [13]
        "openjdk",              # Java Runtime (requis par certaines applis) [15]
        "dotnetfx"              # .NET Framework (dernier runtime supporté) [16]
        # Ajoutez d'autres dépendances ou utilitaires ici si besoin (ex: vcredistall)
    )

    Write-Log -Level "INFO" -Message "Installation des paquets Chocolatey requis : $($ChocoPackagesMandatory -join ', ')"
    Write-Log -Level "INFO" -Message "(Les installateurs essaieront d'utiliser la langue système [FR si OS en FR])" # [20]

    foreach ($pkg in $ChocoPackagesMandatory) {
        Write-Log -Level "INFO" -Message "Installation de $pkg..."
        $Installed = choco list --local-only --exact $pkg -r # -r pour limiter la sortie
        if ($Installed -match $pkg) {
             Write-Log -Level "INFO" -Message "$pkg est déjà installé."
        } else {
            try {
                # Paramètres: -y (accepte prompts), --accept-licenses, --no-progress (moins verbeux), -r (limite sortie), --timeout (plus long si besoin)
                choco install $pkg -y --accept-licenses --no-progress -r --execution-timeout 1800 # Timeout 30 min
                Write-Log -Level "SUCCESS" -Message "$pkg installé avec succès."
            } catch {
                # Tenter de capturer l'erreur spécifique si possible
                Write-Log -Level "ERROR" -Message "Échec de l'installation de $pkg. Erreur : $($_.Exception.Message)"
                # Vous pouvez ajouter une logique pour réessayer ou marquer comme échoué
            }
        }
    }

    # Installation OPTIONNELLE : Microsoft 365 Business
    $PromptTitle = "Installation Microsoft 365"
    $PromptMsg = "Voulez-vous installer Microsoft 365 Business ? (Nécessite une licence valide. L'installation peut être longue.)"
    $Choices = [System.Management.Automation.Host.ChoiceDescription[]]@('&Oui', '&Non')
    $DefaultChoice = 1 # Non par défaut
    $ChoiceResult = $Host.UI.PromptForChoice($PromptTitle, $PromptMsg, $Choices, $DefaultChoice)

    if ($ChoiceResult -eq 0) { # Oui
        $pkgM365 = "office365business" # [14]
        Write-Log -Level "INFO" -Message "Installation de $pkgM365 (cela peut prendre beaucoup de temps)..."
        $Installed = choco list --local-only --exact $pkgM365 -r
        if ($Installed -match $pkgM365) {
             Write-Log -Level "INFO" -Message "$pkgM365 est déjà installé."
        } else {
            try {
                # Office peut nécessiter un timeout plus long
                choco install $pkgM365 -y --accept-licenses --no-progress -r --execution-timeout 7200 # Timeout 2 heures
                Write-Log -Level "SUCCESS" -Message "$pkgM365 installé avec succès."
            } catch {
                Write-Log -Level "ERROR" -Message "Échec de l'installation de $pkgM365. Erreur : $($_.Exception.Message)"
            }
        }
    } else {
        Write-Log -Level "INFO" -Message "Installation de Microsoft 365 Business ignorée."
    }

} else {
    Write-Log -Level "WARN" -Message "Chocolatey n'est pas disponible, installation des logiciels ignorée."
}
Pause

# --- 6. Manufacturer Tools Installation ---
Show-Banner -CurrentStep "Installation Outils Fabricant"
# ... (copier/coller la section 6 de la v3.0 ici) ...
$DataPathFound = Test-Path $DataPath
if ($DataPathFound) {
    if ($Manufacturer -like "*Dell*") {
        Write-Log -Level "INFO" -Message "Dell détecté. Installation Dell Command Update..."
        $DellUpdateExe = Join-Path -Path $DataPath -ChildPath "DellCommandUpdate.exe"
        Start-SilentProcess -FilePath $DellUpdateExe -Arguments "/s /norestart" -LogId "DellCommandUpdate"
    }
    elseif ($Manufacturer -like "*HP*" -or $Manufacturer -like "*Hewlett-Packard*") {
        Write-Log -Level "INFO" -Message "HP détecté. Installation HP Support Assistant..."
        $HPSAExe = Join-Path -Path $DataPath -ChildPath "sp138267.exe"
        Start-SilentProcess -FilePath $HPSAExe -Arguments "/s /norestart" -LogId "HPSupportAssistant"
    }
    else { Write-Log -Level "INFO" -Message "Fabricant non reconnu ($Manufacturer) ou non géré." }
} else { Write-Log -Level "WARN" -Message "Dossier Data introuvable ($DataPath). Outils fabricant ignorés." }
Pause

# --- 7. Specific Software Installation (PRO/PART) ---
# Ninite a été remplacé par Chocolatey dans la section 5.
# Cette section ne contient plus que les spécificités PRO (GoToAssist)
Show-Banner -CurrentStep "Installation Logiciels Spécifiques ($InstallationType)"
if ($InstallationType -eq "PRO") {
    Write-Log -Level "INFO" -Message "Traitement spécifique PRO : Installation GoToAssist..."
    $GoToAssistSource = Join-Path -Path $DataPath -ChildPath "GoToAssist.exe"
    $GoToAssistTargetDir = Join-Path -Path $env:ProgramFiles -ChildPath "GoToAssist"
    $GoToAssistTargetExe = Join-Path -Path $GoToAssistTargetDir -ChildPath "GoToAssist.exe"
    $DesktopShortcut = Join-Path -Path $env:PUBLIC -ChildPath "Desktop\GoToAssist.lnk"
    $StartMenuShortcut = Join-Path -Path $env:ProgramData -ChildPath "Microsoft\Windows\Start Menu\Programs\GoToAssist.lnk"

    if (Test-Path -Path $GoToAssistSource) {
        try {
            if (-not (Test-Path -Path $GoToAssistTargetDir)) { New-Item -Path $GoToAssistTargetDir -ItemType Directory -Force | Out-Null }
            Copy-Item -Path $GoToAssistSource -Destination $GoToAssistTargetDir -Force -ErrorAction Stop
            Write-Log -Level "SUCCESS" -Message "GoToAssist.exe copié."
            New-ShortcutHelper -ShortcutFullName $DesktopShortcut -ShortcutTarget $GoToAssistTargetExe
            New-ShortcutHelper -ShortcutFullName $StartMenuShortcut -ShortcutTarget $GoToAssistTargetExe
        } catch { Write-Log -Level "ERROR" -Message "Échec installation GoToAssist. Erreur: $($_.Exception.Message)" }
    } else { Write-Log -Level "WARN" -Message "Fichier GoToAssist.exe introuvable dans $DataPath." }
} else {
     Write-Log -Level "INFO" -Message "Aucune action spécifique pour le type PART dans cette section."
}
Pause

# --- 8. OEM Information ---
Show-Banner -CurrentStep "Configuration Infos OEM"
# ... (copier/coller la section 8 de la v3.0 ici) ...
Write-Log -Level "INFO" -Message "Définition des informations OEM pour $CompanyName..."
$OemInfoPath = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation"
try {
    if (-not (Test-Path $OemInfoPath)) { New-Item -Path $OemInfoPath -Force | Out-Null }
    foreach ($key in $SupportInfo.Keys) {
        Set-ItemProperty -Path $OemInfoPath -Name $key -Value $SupportInfo[$key] -Type String -Force -ErrorAction Stop
    }
    Write-Log -Level "SUCCESS" -Message "Informations OEM définies."
} catch { Write-Log -Level "WARN" -Message "Impossible de définir les infos OEM. Erreur: $($_.Exception.Message)" }

# --- 9. Create Common Shortcuts ---
Show-Banner -CurrentStep "Création Raccourcis Communs"
# Adobe Reader est généralement bien géré par l'installeur/Choco.
# Juste un exemple si nécessaire :
# $AdobeReaderExePath = "C:\Program Files (x86)\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe"
# $AdobeShortcut = Join-Path -Path $env:PUBLIC -ChildPath "Desktop\Adobe Acrobat Reader DC.lnk"
# if (Test-Path $AdobeReaderExePath) { New-ShortcutHelper -ShortcutFullName $AdobeShortcut -ShortcutTarget $AdobeReaderExePath }
# else { Write-Log -Level "WARN" -Message "Adobe Reader non trouvé. Raccourci bureau non créé." }
Write-Log -Level "INFO" -Message "Les raccourcis sont généralement créés par les installateurs (via Choco) dans le menu Démarrer."
Pause

# --- 10. Windows Updates ---
Show-Banner -CurrentStep "Mises à jour Windows"
# ... (copier/coller la section 10 de la v3.0 ici) ...
if (-not $SkipWindowsUpdate) {
    Write-Log -Level "INFO" -Message "Préparation MàJ Windows..."
    $RebootRequiredByUpdate = $false
    try {
        if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
            Write-Log -Level "INFO" -Message "Installation NuGet..."
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction Stop
        } else { Write-Log -Level "INFO" -Message "NuGet présent." }
        if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
            Write-Log -Level "INFO" -Message "Installation PSWindowsUpdate..."
            Install-Module PSWindowsUpdate -Force -AcceptLicense -Confirm:$false -ErrorAction Stop
        } else { Write-Log -Level "INFO" -Message "PSWindowsUpdate présent." }
        Import-Module PSWindowsUpdate -Force
        Write-Log -Level "INFO" -Message "Recherche et installation MàJ Windows (peut être long)..."
        Install-WindowsUpdate -AcceptAll -IgnoreReboot -Verbose -ErrorAction Stop
        if (Test-WUReboot) {
            Write-Log -Level "WARN" -Message "Redémarrage requis pour finaliser les MàJ."
            $RebootRequiredByUpdate = $true
        } else { Write-Log -Level "SUCCESS" -Message "MàJ Windows terminées. Pas de redémarrage signalé." }
    } catch {
        Write-Log -Level "ERROR" -Message "Erreur MàJ Windows. Erreur: $($_.Exception.Message)"
         if (Test-WUReboot -ErrorAction SilentlyContinue) { $RebootRequiredByUpdate = $true }
    }
} else { Write-Log -Level "INFO" -Message "MàJ Windows ignorées (-SkipWindowsUpdate)." }
Pause

# --- 11. Final Cleanup (Scheduled via RunOnce) ---
Show-Banner -CurrentStep "Planification du Nettoyage"
# ... (copier/coller la section 11 de la v3.0 ici) ...
Write-Log -Level "INFO" -Message "Configuration nettoyage dossier déploiement au prochain démarrage..."
$RunOnceKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
$CleanupCommand = "cmd.exe /c rmdir /s /q `"$PSScriptRoot`""
$CleanupEntryName = "KoesioDeployCleanup"
try {
    Set-ItemProperty -Path $RunOnceKey -Name $CleanupEntryName -Value $CleanupCommand -Type String -Force -ErrorAction Stop
    Write-Log -Level "SUCCESS" -Message "Nettoyage programmé via RunOnce pour '$PSScriptRoot'."
} catch {
     Write-Log -Level "ERROR" -Message "Impossible de programmer le nettoyage via RunOnce. Erreur : $($_.Exception.Message)"
     Write-Log -Level "WARN" -Message "Suppression manuelle de '$PSScriptRoot' peut être nécessaire."
}

# --- 12. Final Messages & Exit ---
Show-Banner -CurrentStep "Terminé"
# ... (copier/coller la section 12 de la v3.0 ici, attention à la variable $RebootRequired) ...
Write-Log -Level "SUCCESS" -Message "Script déploiement Koesio v$ScriptVersion terminé."
$RebootRequiredOverall = $false
# Vérifier si renommage a demandé un redémarrage
$ComputerInfoAfter = Get-CimInstance Win32_ComputerSystem
if ($RenameNeeded -and ($ComputerInfoAfter.Name -ne $NewName)) { # Si on a voulu renommer ET que le nom n'a pas encore changé
     Write-Log -Level "WARN" -Message "Un redémarrage est nécessaire pour appliquer le nouveau nom d'ordinateur."
     $RebootRequiredOverall = $true
}
# Vérifier si Windows Update a demandé un redémarrage
if ($RebootRequiredByUpdate) { $RebootRequiredOverall = $true }

if ($RebootRequiredOverall) {
     Write-Log -Level "WARN" -Message "Un REDÉMARRAGE est nécessaire pour finaliser la configuration."
     $PromptTitle = "Redémarrage Requis"
     $PromptMsg = "Le script est terminé, mais un redémarrage est nécessaire. Redémarrer maintenant ?"
     $Choices = [System.Management.Automation.Host.ChoiceDescription[]]@('&Oui', '&Non')
     $ChoiceResult = $Host.UI.PromptForChoice($PromptTitle, $PromptMsg, $Choices, 0) # Oui par défaut
     if ($ChoiceResult -eq 0) {
         Write-Log -Level "INFO" -Message "Redémarrage de l'ordinateur..."
         Stop-Transcript
         Restart-Computer -Force
         Exit 0
     } else { Write-Log -Level "INFO" -Message "Redémarrage manuel requis." }
} else { Write-Log -Level "INFO" -Message "Aucun redémarrage immédiat ne semble requis par le script." }

Write-Host "Appuyez sur Entrée pour fermer..." -ForegroundColor Cyan
Read-Host
Stop-Transcript
Exit 0

#endregion
