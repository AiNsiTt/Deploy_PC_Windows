<#
.SYNOPSIS
    Script de préparation et de configuration post-installation pour les ordinateurs Windows déployés chez Koesio.
    Ce script automatise plusieurs tâches répétitives afin d'assurer une configuration standardisée et efficace
    des postes clients avant leur mise en service.

.DESCRIPTION
    Le script KoesioPrep.ps1 effectue les opérations suivantes :
    - Applique les paramètres de confidentialité et d'ergonomie utilisateur recommandés (pour l'utilisateur actuel et le profil par défaut).
    - Configure les paramètres système HKLM (Contrôle de compte d'utilisateur (UAC) (commenté par défaut), BitLocker, alimentation, démarrage rapide).
    - Optimise les paramètres de mise à jour	Windows (activation des mises à jour pour d'autres produits Microsoft, configuration de l'Optimisation de la Distribution).
    - Gère le nom de l'ordinateur en utilisant son numéro de série (avec confirmation).
    - Installe une suite de logiciels standards (ex: Google Chrome, Mozilla Firefox, Adobe Acrobat Reader DC) via Winget.
    - Configure certains aspects des logiciels installés (ex: page d'accueil, suppression des invites de premier lancement).
    - Personnalise l'environnement de bureau (suppression de raccourcis, épinglage à la barre des tâches pour les nouveaux profils).
    - Gère les applications au démarrage.
    - Lance la recherche et l'installation des mises à jour Windows via le module PSWindowsUpdate.

    Le script est conçu pour être exécuté avec des privilèges d'administrateur et génère un journal de transcription détaillé.
    Certaines modifications peuvent nécessiter un redémarrage du système pour une prise d'effet complète.

.NOTES
    Auteur     : Quentin Chaillou, Koesio
    Date       : 21/05/2025
    Version    : 1.0
	Mail       : quentin.chaillou@koesio.com
    Prérequis  : PowerShell 5.1 ou supérieur. Winget doit être fonctionnel.
                 Le script doit être exécuté en tant qu'administrateur.
                 Les fichiers de configuration optionnels (pour Chrome, Firefox, barre des tâches)
                 doivent être placés dans un sous-dossier "KoesioConfig".

.EXAMPLE
    .\KoesioPrep.ps1
    Exécute le script avec les droits administrateur pour préparer le poste.
#>

#region Script Setup and Admin Check
#====================================================================================
# Koesio - Script de Préparation Post-Installation Windows (KoesioPrep.ps1)
# Auteur     : Quentin Chaillou, Koesio
# Date       : 21/05/2025
# Version    : 1.0
#====================================================================================

# Forcer TLS 1.2 pour les connexions web (PowerShellGet, etc.)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Global:RebootRequired = $false # Initialiser la variable globale

#region Script Setup and Admin Check
#====================================================================================
# Koesio - Script de Préparation Post-Installation Windows
# Auteur: Votre Nom / Koesio
# Date: $(Get-Date -Format dd/MM/yyyy)
# Version: 1.5 (Intégration HKCU Default et Current User)
# Description: Automatise la configuration initiale des postes Windows.
#====================================================================================

# Forcer TLS 1.2 pour les connexions web (PowerShellGet, etc.)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Vérifier si le script est exécuté en tant qu'administrateur
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Ce script doit être exécuté en tant qu'administrateur."
    Write-Host "Veuillez relancer PowerShell en tant qu'administrateur et exécuter à nouveau le script."
    If ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
        $CommandLine = "-NoProfile -ExecutionPolicy Bypass -File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
        Start-Process PowerShell -Verb RunAs -ArgumentList $CommandLine
        Exit
    }
    Read-Host "Appuyez sur Entrée pour quitter."
    Exit
}

# Démarrer la journalisation des logs
$ScriptRoot = Split-Path -Path $MyInvocation.MyCommand.Path
$LogPath = Join-Path -Path $ScriptRoot -ChildPath "KoesioPrepLog"
If (-not (Test-Path $LogPath)) { New-Item -ItemType Directory -Path $LogPath -Force }
Start-Transcript -Path "$LogPath\KoesioPrep_$(Get-Date -Format 'yyyyMMdd_HHmmss').log" -Force

Write-Host "-----------------------------------------------------"
Write-Host "Début du script de préparation PC Windows Koesio..."
Write-Host "Chemin du script: $ScriptRoot"
Write-Host "Utilisateur exécutant le script: $($env:USERNAME)"
Write-Host "-----------------------------------------------------"

$ConfigFolderPath = Join-Path -Path $ScriptRoot -ChildPath "KoesioConfig"
If (-not (Test-Path $ConfigFolderPath)) {
    Write-Warning "Le dossier de configuration '$ConfigFolderPath' est introuvable."
}
#endregion

#region HKCU Settings Application Functions

function Apply-HkcuSettingsToDefaultProfile {
    param (
        [scriptblock]$SettingsToApply
    )
    $DefaultUserHive = "C:\Users\Default\NTUSER.DAT"
    $TempHiveKeyName = "TempDefaultUserHiveForKoesio" 

    Write-Host "`n--- Application des paramètres HKCU au Profil Utilisateur par Défaut ---"
    
    if (Test-Path "Registry::HKLM\$TempHiveKeyName") {
        Write-Warning "La ruche temporaire '$TempHiveKeyName' semble déjà montée. Tentative de démontage..."
        try { [gc]::Collect(); reg unload "HKLM\$TempHiveKeyName"; Start-Sleep -Seconds 1 }
        catch { Write-Error "Impossible de démonter '$TempHiveKeyName' existante. Les modifications du profil par défaut pourraient échouer. $($_.Exception.Message)"; return }
    }
    if (-not (Test-Path $DefaultUserHive)) { Write-Error "La ruche NTUSER.DAT du profil par défaut est introuvable à $DefaultUserHive."; return }

    Write-Host "Chargement de la ruche du profil utilisateur par défaut : $DefaultUserHive"
    try {
        reg load "HKLM\$TempHiveKeyName" "$DefaultUserHive"
        Start-Sleep -Seconds 1 
        Write-Host "Ruche chargée sous HKLM:\$TempHiveKeyName"
    } catch {
        Write-Error "Échec du chargement de la ruche du profil par défaut. $($_.Exception.Message)"; return
    }

    Write-Host "Application des modifications au profil par défaut chargé..."
    try {
        Invoke-Command -ScriptBlock $SettingsToApply -ArgumentList "Registry::HKLM\$TempHiveKeyName"
        Write-Host "Modifications pour le profil par défaut appliquées."
    } catch {
        Write-Warning "Une erreur s'est produite lors de l'application des paramètres au profil par défaut chargé: $($_.Exception.Message)"
    } finally {
        Write-Host "Démontage de la ruche du profil utilisateur par défaut..."
        [gc]::Collect(); Start-Sleep -Seconds 1
        try {
            reg unload "HKLM\$TempHiveKeyName"
            Write-Host "Ruche '$TempHiveKeyName' démontée."
        } catch {
            Write-Error "ÉCHEC CRITIQUE du démontage de la ruche '$TempHiveKeyName'. Le profil par défaut pourrait être corrompu ou verrouillé ! $($_.Exception.Message)"
        }
    }
}

function Apply-HkcuSettingsToCurrentUser {
    param (
        [scriptblock]$SettingsToApply
    )
    Write-Host "`n--- Application des paramètres HKCU à l'Utilisateur Actuel ($($env:USERNAME)) ---"
    try {
        Invoke-Command -ScriptBlock $SettingsToApply -ArgumentList "HKCU:"
        Write-Host "Modifications pour l'utilisateur actuel ($($env:USERNAME)) appliquées."
        Write-Host "Une déconnexion/reconnexion ou un redémarrage de l'explorateur peut être nécessaire pour cet utilisateur."
    } catch {
        Write-Warning "Erreur lors de l'application des paramètres à l'utilisateur actuel ($($env:USERNAME)): $($_.Exception.Message)"
    }
}

#endregion

# --- Définition du ScriptBlock pour les Paramètres Utilisateur ---
$UserSettingsScriptBlock = {
    param($HivePathPrefix) 

    Write-Host "  Début des configurations pour la ruche : '$HivePathPrefix'"

    Write-Host "    Configuration des paramètres de confidentialité..."
    Set-ItemProperty -Path "$HivePathPrefix\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue 
    Set-ItemProperty -Path "$HivePathPrefix\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue # 1 = Désactivé
    Set-ItemProperty -Path "$HivePathPrefix\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
    $ContentDeliveryKey = "$HivePathPrefix\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    Set-ItemProperty -Path $ContentDeliveryKey -Name "SubscribedContent-338393Enabled" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue 
    Set-ItemProperty -Path $ContentDeliveryKey -Name "SubscribedContent-353694Enabled" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue 
	Set-ItemProperty -Path $ContentDeliveryKey -Name "SubscribedContent-353696Enabled" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue 
    Set-ItemProperty -Path $ContentDeliveryKey -Name "SubscribedContent-338389Enabled" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue 
    Set-ItemProperty -Path $ContentDeliveryKey -Name "SoftLandingEnabled" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue 
	Set-ItemProperty -Path "$HivePathPrefix\Software\Microsoft\Windows\CurrentVersion\CPSS\Store\UserLocationOverridePrivacySetting" -Name "Value" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "$HivePathPrefix\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "ShowGlobalPrompts" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $ContentDeliveryKey -Name "RotatingLockScreenOverlayEnabled" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
	Set-ItemProperty -Path $ContentDeliveryKey -Name "SubscribedContent-310093Enabled" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
	$NotifPath = "$HivePathPrefix\Software\Microsoft\Windows\CurrentVersion\SystemSettings\AccountNotifications"
    $TestPathForNotif = $NotifPath
    if ($HivePathPrefix.StartsWith("Registry::")) { $TestPathForNotif = $NotifPath.Substring("Registry::".Length) }
    if (-not (Test-Path $TestPathForNotif)) { 
        try { New-Item -Path $NotifPath -Force -ItemType Directory -ErrorAction Stop | Out-Null }
        catch { Write-Warning "Impossible de créer le chemin $NotifPath : $($_.Exception.Message)"}
    }
    if (Test-Path $TestPathForNotif) { # S'assurer que le chemin a été créé ou existait
        Set-ItemProperty -Path $NotifPath -Name "EnableAccountNotifications" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
    }

    Write-Host "    Configuration du Mode Jeu et Game Bar..."
     # Clés pour la Game Bar elle-même
    Set-ItemProperty -Path "$HivePathPrefix\Software\Microsoft\GameBar" -Name "UseNexusForGameBarEnabled" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "$HivePathPrefix\Software\Microsoft\GameBar" -Name "AutoGameModeEnabled" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "$HivePathPrefix\Software\Microsoft\GameBar" -Name "ShowStartupPanel" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "$HivePathPrefix\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue 
    Set-ItemProperty -Path "$HivePathPrefix\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue

    Write-Host "    Désactivation de OneDrive au démarrage..."
    Remove-ItemProperty -Path "$HivePathPrefix\Software\Microsoft\Windows\CurrentVersion\Run" -Name "OneDrive" -ErrorAction SilentlyContinue

    Write-Host "    Désactivation de Copilot (via stratégie utilisateur)..."
    $CopilotRegPath = "$HivePathPrefix\Software\Policies\Microsoft\Windows\WindowsCopilot"
    # Test-Path avec le chemin complet de la ruche (ex: HKLM\TempHive\Software...)
    $TestPathForCopilot = $CopilotRegPath
    if ($HivePathPrefix.StartsWith("Registry::")) { # Pour les ruches chargées manuellement
        $TestPathForCopilot = $CopilotRegPath.Substring("Registry::".Length)
    }
    if (-not (Test-Path $TestPathForCopilot)) {
         New-Item -Path $CopilotRegPath -Force -ItemType Directory | Out-Null
    }
    Set-ItemProperty -Path $CopilotRegPath -Name "TurnOffWindowsCopilot" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    
    Write-Host "  Fin des configurations pour la ruche : '$HivePathPrefix'."
	Write-Host "Configuration des icônes du Bureau sous '$HivePathPrefix'..."
	
	$DesktopIconsPath = "$HivePathPrefix\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
	# S'assurer que la clé parente existe
	$TestPathForDesktopIcons = $DesktopIconsPath
	if ($HivePathPrefix.StartsWith("Registry::")) { $TestPathForDesktopIcons = $DesktopIconsPath.Substring("Registry::".Length) }
	if (-not (Test-Path $TestPathForDesktopIcons)) { 
		try { New-Item -Path $DesktopIconsPath -Force -ItemType Directory -ErrorAction Stop | Out-Null }
		catch { Write-Warning "Impossible de créer le chemin $DesktopIconsPath : $($_.Exception.Message)"}
	}

	if (Test-Path $TestPathForDesktopIcons) { # Si le chemin existe ou a été créé
		# Afficher Ordinateur (Ce PC)
		Set-ItemProperty -Path $DesktopIconsPath -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
		# Afficher Fichiers de l'utilisateur
		Set-ItemProperty -Path $DesktopIconsPath -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
		# Afficher Panneau de configuration
		Set-ItemProperty -Path $DesktopIconsPath -Name "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
		# Optionnel: Afficher Réseau
		# Set-ItemProperty -Path $DesktopIconsPath -Name "{F02C1A0D-BE21-4350-88B0-7367FC96EF7A}" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
		# Optionnel: S'assurer que la Corbeille est affichée (généralement par défaut)
		# Set-ItemProperty -Path $DesktopIconsPath -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
		Write-Host "Icônes du Bureau (Ordinateur, Fichiers Utilisateur, Panneau de Config) configurées pour être affichées."
	}
}


	
# --- Fin du ScriptBlock ---

#region Script Execution Order

# == ÉTAPE 1: Configurations Utilisateur (HKCU) ==
# Appliquer au profil utilisateur par défaut (pour les futurs utilisateurs)
Apply-HkcuSettingsToDefaultProfile -SettingsToApply $UserSettingsScriptBlock

# Appliquer à l'utilisateur actuel (celui dont le contexte PowerShell est élevé)
Apply-HkcuSettingsToCurrentUser -SettingsToApply $UserSettingsScriptBlock

# == ÉTAPE 2: Configurations Système (HKLM et autres actions globales) ==
Write-Host "`n--- Modifications Système Globales (HKLM et autres) ---"

# --- Computer Rename ---
Write-Host "`n  --- Configuration du Nom de l'Ordinateur ---"
try {
    $SerialNumber = (Get-CimInstance Win32_BIOS).SerialNumber.Trim()
    $CurrentName = $env:COMPUTERNAME
    if (-not [string]::IsNullOrWhiteSpace($SerialNumber)) {
        Write-Host "  Numéro de série détecté : $SerialNumber"
        Write-Host "  Nom actuel de l'ordinateur : $CurrentName"
        if ($CurrentName -ne $SerialNumber) {
            $choice = Read-Host "  Voulez-vous renommer l'ordinateur en '$SerialNumber' ? [O/n]"
            if ($choice -eq '' -or $choice -eq 'o' -or $choice -eq 'O') {
                Write-Host "  Renommage de l'ordinateur en '$SerialNumber'..."
                Rename-Computer -NewName $SerialNumber -Force -ErrorAction Stop
                Write-Host "  Le nom de l'ordinateur sera changé en '$SerialNumber' après le prochain redémarrage."
                $Global:RebootRequired = $true
            } else { Write-Host "  Renommage annulé." }
        } else { Write-Host "  L'ordinateur est déjà nommé avec son numéro de série." }
    } else { Write-Warning "  Impossible de récupérer le numéro de série." }
} catch { Write-Warning "  Erreur lors du renommage: $($_.Exception.Message)" }

# --- System Tweaks (HKLM) ---
Write-Host "`n  --- Modifications Système (HKLM) ---"
Write-Host "    Désactivation de BitLocker..."
try {
    $BitlockerRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\BitLocker"
    If (!(Test-Path $BitlockerRegPath)) { New-Item -Path $BitlockerRegPath -Force | Out-Null }
    Set-ItemProperty -Path $BitlockerRegPath -Name "PreventDeviceEncryption" -Value 1 -Type DWord -Force
    Get-BitLockerVolume | ForEach-Object {
        If ($_.ProtectionStatus -eq "On") {
            Write-Host "    Désactivation de BitLocker pour $($_.MountPoint)..."
            Suspend-BitLocker -MountPoint $_.MountPoint -RebootCount 0 -ErrorAction SilentlyContinue
            Disable-BitLocker -MountPoint $_.MountPoint -ErrorAction SilentlyContinue
        }
    }
} catch { Write-Warning "    Erreur BitLocker : $($_.Exception.Message)" }

Write-Host "    Configuration des paramètres d'alimentation..."
powercfg /change disk-timeout-ac 0
powercfg /change disk-timeout-dc 0
powercfg /change monitor-timeout-ac 0
powercfg /change monitor-timeout-dc 0
powercfg /change standby-timeout-ac 0
powercfg /change standby-timeout-dc 0
powercfg /hibernate off 

Write-Host "    Activation des mises à jour pour d'autres produits Microsoft..."
$UpdateUXSettingsPath = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"
$UpdatePolicySettingsPath = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\Settings" # Pour PausedStatus
$UpdatePolicyAUPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
$UpdateCurrentVersionAUPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"
# $WaaSSelfhostPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WaaS\Selfhost"

# Clé principale identifiée par ProcMon
try {
    If (!(Test-Path $UpdateUXSettingsPath)) { New-Item -Path $UpdateUXSettingsPath -Force -ErrorAction Stop | Out-Null }
    Set-ItemProperty -Path $UpdateUXSettingsPath -Name "IsContinuousInnovationOptedIn" -Value 1 -Type DWord -Force -ErrorAction Stop
	Set-ItemProperty -Path $UpdateUXSettingsPath -Name "AllowMUUpdateService" -Value 1 -Type DWord -Force -ErrorAction Stop
    Write-Host "        IsContinuousInnovationOptedIn (UX\Settings) positionné à 1."
} catch { Write-Warning "        Échec de la configuration de IsContinuousInnovationOptedIn: $($_.Exception.Message)" }

# S'assurer que les mises à jour ne sont pas en pause
try {
    If (!(Test-Path $UpdatePolicySettingsPath)) { New-Item -Path $UpdatePolicySettingsPath -Force -ErrorAction Stop | Out-Null }
    Set-ItemProperty -Path $UpdatePolicySettingsPath -Name "PausedFeatureStatus" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $UpdatePolicySettingsPath -Name "PausedQualityStatus" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
    Write-Host "        PausedFeatureStatus et PausedQualityStatus positionnés à 0."
} catch { Write-Warning "        Échec de la configuration des PausedStatus: $($_.Exception.Message)" }

# Clés traditionnelles (bonnes à avoir comme fallback ou complément)
try {
    If (!(Test-Path $UpdatePolicyAUPath)) { New-Item -Path $UpdatePolicyAUPath -Force -ErrorAction Stop | Out-Null }
    Set-ItemProperty -Path $UpdatePolicyAUPath -Name "IncludeRecommendedUpdates" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    Write-Host "        IncludeRecommendedUpdates (Policies) positionné à 1."
} catch { Write-Warning "        Échec de la configuration de IncludeRecommendedUpdates (Policies): $($_.Exception.Message)" }

try {
    If (!(Test-Path $UpdateCurrentVersionAUPath)) { New-Item -Path $UpdateCurrentVersionAUPath -Force -ErrorAction Stop | Out-Null }
    Set-ItemProperty -Path $UpdateCurrentVersionAUPath -Name "IncludeRecommendedUpdates" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    Write-Host "        IncludeRecommendedUpdates (CurrentVersion) positionné à 1."
} catch { Write-Warning "        Échec de la configuration de IncludeRecommendedUpdates (CurrentVersion): $($_.Exception.Message)" }

Write-Host "    Désactivation de l'optimisation de la distribution (peer-to-peer)..."
$NetworkServiceSID = "S-1-5-20" # SID du compte Service Réseau
$DOSettingsPathUnderNetworkService = "Registry::HKEY_USERS\$NetworkServiceSID\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings"

# D'abord, la politique (car elle a souvent priorité)
$DOPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
Write-Host "      Configuration via HKEY_LOCAL_MACHINE (Policies)..."
try {
    If (!(Test-Path $DOPolicyPath)) { 
        New-Item -Path $DOPolicyPath -Force -ErrorAction Stop | Out-Null
        Write-Host "        Clé de stratégie $DOPolicyPath créée."
    }
    Set-ItemProperty -Path $DOPolicyPath -Name "DODownloadMode" -Value 0 -Type DWord -Force -ErrorAction Stop
    Write-Host "        Stratégie DODownloadMode (Policies) positionnée à 0 (HTTP uniquement)."
} catch {
    Write-Warning "        Échec de la configuration de la stratégie DODownloadMode: $($_.Exception.Message)"
}

# Ensuite, la configuration spécifique observée sous le compte Service Réseau
Write-Host "      Configuration via HKEY_USERS pour le compte Service Réseau (SID: $NetworkServiceSID)..."
if (Test-Path $DOSettingsPathUnderNetworkService) {
    try {
        Set-ItemProperty -Path $DOSettingsPathUnderNetworkService -Name "DownloadMode" -Value 0 -Type DWord -Force -ErrorAction Stop
        # Optionnel : Définir aussi DownloadModeProvider si vous le souhaitez, mais DownloadMode est le plus important.
        # Set-ItemProperty -Path $DOSettingsPathUnderNetworkService -Name "DownloadModeProvider" -Value 8 -Type DWord -Force -ErrorAction SilentlyContinue
        Write-Host "        DownloadMode pour Service Réseau positionné à 0."
    } catch {
        Write-Warning "        Échec de la configuration de DownloadMode pour Service Réseau: $($_.Exception.Message)"
    }
} else {
    Write-Warning "        Le chemin de registre pour DeliveryOptimization sous le SID $NetworkServiceSID ($DOSettingsPathUnderNetworkService) n'a pas été trouvé."
    Write-Warning "        Cela peut signifier que le profil du compte Service Réseau n'est pas (encore) complètement initialisé ou que la ruche n'est pas chargée."
    Write-Warning "        La configuration via Policies (HKLM) devrait tout de même s'appliquer si le service la lit."
}

# Optionnel mais recommandé: redémarrer le service pour qu'il prenne en compte les modifications
# Si le service est en cours d'exécution, il ne relira peut-être pas le registre immédiatement.
Write-Host "      Redémarrage du service d'Optimisation de la Distribution (DoSvc)..."
try {
    Get-Service DoSvc | Set-Service -StartupType Automatic -PassThru -ErrorAction SilentlyContinue | Restart-Service -Force -ErrorAction Stop
    Write-Host "        Service DoSvc redémarré."
} catch {
    Write-Warning "        Impossible de redémarrer le service DoSvc. Un redémarrage du PC peut être nécessaire. Erreur: $($_.Exception.Message)"
}

Write-Host "    Désactivation de OneDrive (politique HKLM)..."
$OneDrivePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"
If (!(Test-Path $OneDrivePolicyPath)) { New-Item -Path $OneDrivePolicyPath -Force | Out-Null }
Set-ItemProperty -Path $OneDrivePolicyPath -Name "DisableFileSyncNGSC" -Value 1 -Type DWord -Force

Write-Host "    Désactivation de Edge Startup Boost et Prelaunch (politique HKLM)..."
$EdgePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge" 
If (!(Test-Path $EdgePolicyPath)) { New-Item -Path $EdgePolicyPath -Force | Out-Null }
Set-ItemProperty -Path $EdgePolicyPath -Name "StartupBoostEnabled" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $EdgePolicyPath -Name "AllowPrelaunch" -Value 0 -Type DWord -Force
# Redémarrage des services Windows Update
Write-Host "      Redémarrage des services Windows Update pour appliquer les modifications..."
try {
    Get-Service wuauserv, UsoSvc | Restart-Service -Force -ErrorAction Stop
    Write-Host "        Services wuauserv et UsoSvc redémarrés."
} catch {
    Write-Warning "        Impossible de redémarrer les services Windows Update. Un redémarrage du PC peut être nécessaire. Erreur: $($_.Exception.Message)"
}
#region Optional Software Installation
#====================================================================================
Write-Host "`n--- Installation de Logiciels Optionnels ---"

# Définir la liste des logiciels optionnels
# Chaque objet a un 'Name' (pour l'affichage) et un 'WingetId'
# Pour les logiciels nécessitant une installation personnalisée, WingetId peut être 'Custom' ou un identifiant spécial.
$OptionalSoftwareList = @(
    [PSCustomObject]@{ Index = 1; Name = "VLC Media Player"; WingetId = "VideoLAN.VLC"; Install = $false }
    [PSCustomObject]@{ Index = 2; Name = "FortiClient VPN (VPN Only)"; WingetId = "Fortinet.FortiClientVPN"; Install = $false }
    [PSCustomObject]@{ Index = 3; Name = "OpenVPN Connect"; WingetId = "OpenVPNTechnologies.OpenVPNConnect"; Install = $false }
    [PSCustomObject]@{ Index = 4; Name = "GoToAssist Customer (Attended)"; WingetId = "GoTo.GoToAssistAgentDesktopConsole"; Install = $false }
    #[PSCustomObject]@{ Index = 5; Name = "Microsoft 365 Apps"; WingetId = "Custom_M365"; Install = $false; NeedsCustomInstall = $true }
    #[PSCustomObject]@{ Index = 6; Name = "Office 2019/LTSC 2021"; WingetId = "Custom_OfficeLTSC"; Install = $false; NeedsCustomInstall = $true }
    #[PSCustomObject]@{ Index = 7; Name = "Office 2016"; WingetId = "Custom_Office2016"; Install = $false; NeedsCustomInstall = $true }
    # Office 2022 n'est pas un produit standard, Office LTSC 2021 est son équivalent perpétuel.
)

#Install-SoftwareWithWinget fonction définie
function Install-SoftwareWithWinget {
    param (
        [string]$AppName,
        [string]$AppId
    )
    Write-Host "`nInstallation de $AppName (ID: $AppId) via Winget..."
    
    # Vérification si déjà installé (inchangé)
    $isInstalled = $false
    try {
        $installedOutput = winget list --id $AppId -n 1 --accept-source-agreements
        if ($installedOutput -match $AppId) {
            Write-Host "$AppName est déjà installé."
            $isInstalled = $true
        }
    } catch {
        Write-Warning "Impossible de vérifier si $AppName est installé via Winget (winget list a échoué). Tentative d'installation. Erreur: $($_.Exception.Message)"
    }
    if ($isInstalled) { return }
    
    # Vérifier et ajouter les sources Winget si elles manquent APRÈS la tentative de reset
    # (Cette vérification est faite une fois au début de la section Software Installation maintenant)

    # Gestion des logs Winget (inchangé)
    $LogWingetDir = Join-Path -Path $LogPath -ChildPath "WingetLogs"
    If (-not (Test-Path $LogWingetDir)) {
        try { New-Item -ItemType Directory -Path $LogWingetDir -Force -ErrorAction Stop | Out-Null }
        catch { Write-Warning "Impossible de créer le dossier de logs Winget: $LogWingetDir. Erreur: $($_.Exception.Message)"; $LogWingetDir = $null }
    }
    $CleanAppIdForLog = $AppId -replace '[^a-zA-Z0-9.-]','_' 
    $WingetLogFile = ""
    if ($LogWingetDir) {
        $WingetLogFile = Join-Path -Path $LogWingetDir -ChildPath "$($CleanAppIdForLog)_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    }

    # Construction de la liste d'arguments pour Start-Process
    # Start-Process -ArgumentList préfère une chaîne unique, où les arguments avec espaces sont entre guillemets.
    $Args = "install --id ""$AppId"" -e --accept-package-agreements --accept-source-agreements --silent --source winget --verbose-logs"
    if ($WingetLogFile) {
         $Args += " --log ""$WingetLogFile""" # Guillemets autour du chemin du log
    } else {
        Write-Warning "L'option --log pour Winget ne sera pas utilisée car le dossier de logs n'a pas pu être créé."
    }

    Write-Host "Commande Winget en cours d'exécution: winget.exe $Args"

    try {
        # On passe la chaîne $Args directement
        $process = Start-Process winget.exe -ArgumentList $Args -Wait -PassThru -WindowStyle Minimized 
        $exitCode = $process.ExitCode

        if ($exitCode -eq 0) {
            Write-Host "$AppName installé avec succès."
        } else {
            Write-Warning "$AppName n'a pas pu être installé. Code de sortie Winget: $exitCode."
            if ($WingetLogFile -and (Test-Path $WingetLogFile)) {
                Write-Warning "Consultez les logs Winget spécifiques : $WingetLogFile"
                Write-Host "Dernières lignes du log Winget ($AppName):"
                Get-Content $WingetLogFile -Tail 20 | ForEach-Object {Write-Host "  $_"}
            } elseif ($WingetLogFile) {
                Write-Warning "Le fichier de log Winget $WingetLogFile n'a pas été trouvé ou créé."
            } else {
                Write-Warning "Aucun fichier de log Winget n'a été spécifié pour cette tentative."
            }
        }
    } catch {
        Write-Warning "Échec critique du lancement de Winget pour $AppName. Erreur PowerShell: $($_.Exception.Message)."
    }
}


Write-Host "Logiciels optionnels disponibles pour l'installation :"
$OptionalSoftwareList | ForEach-Object {
    $Suffix = ""
    if ($_.NeedsCustomInstall) { $Suffix = " (Installation personnalisée requise)" }
    Write-Host ("  {0}. {1}{2}" -f $_.Index, $_.Name, $Suffix)
}

[string]$UserChoices = Read-Host "`nEntrez les numéros des logiciels à installer, séparés par des virgules (ex: 1,3,5), ou laissez vide pour ne rien installer"

if (-not [string]::IsNullOrWhiteSpace($UserChoices)) {
    $SelectedIndices = $UserChoices -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match "^\d+$" } | ForEach-Object { [int]$_ }

    if ($SelectedIndices.Count -gt 0) {
        Write-Host "`n--- Installation des logiciels optionnels sélectionnés ---"
        foreach ($index in $SelectedIndices) {
            $SoftwareToInstall = $OptionalSoftwareList | Where-Object { $_.Index -eq $index } | Select-Object -First 1
            if ($SoftwareToInstall) {
                Write-Host ("`nTraitement de : {0}" -f $SoftwareToInstall.Name)
                if ($SoftwareToInstall.NeedsCustomInstall) {
                    # --- Point d'extension pour les installations personnalisées ---
                    switch ($SoftwareToInstall.WingetId) {
                        "Custom_M365" {
                            Write-Warning "  L'installation de Microsoft 365 Apps nécessite l'Outil de Déploiement d'Office (ODT)."
                            Write-Host "    Veuillez implémenter la fonction Install-M365AppsWithODT ici."
                            # Exemple d'appel: Install-M365AppsWithODT -ConfigurationXmlPath "C:\Path\To\M365Config.xml"
                        }
                        "Custom_OfficeLTSC" {
                            Write-Warning "  L'installation d'Office LTSC 2021/2019 nécessite l'Outil de Déploiement d'Office (ODT)."
                            Write-Host "    Veuillez implémenter la fonction Install-OfficeLTSCWithODT ici."
                        }
                        "Custom_Office2016" {
                            Write-Warning "  L'installation d'Office 2016 nécessite l'Outil de Déploiement d'Office (ODT) ou un installeur MSI/EXE."
                            Write-Host "    Veuillez implémenter la fonction Install-Office2016 ici."
                        }
                        default {
                            Write-Warning "  Méthode d'installation personnalisée non définie pour $($SoftwareToInstall.Name)."
                        }
                    }
                } elseif ($SoftwareToInstall.WingetId) {
                    # Utiliser votre fonction existante Install-SoftwareWithWinget
                    # Assurez-vous que cette fonction est définie AVANT cette section ou globalement.
                    Install-SoftwareWithWinget -AppName $SoftwareToInstall.Name -AppId $SoftwareToInstall.WingetId
                } else {
                    Write-Warning "  ID Winget non défini pour $($SoftwareToInstall.Name)."
                }
            } else {
                Write-Warning "  Numéro de sélection invalide ignoré : $index"
            }
        }
    } else {
        Write-Host "Aucune sélection valide de logiciels optionnels."
    }
} else {
    Write-Host "Aucun logiciel optionnel sélectionné pour l'installation."
}
#endregion Optional Software Installation
#region Software Installation
#====================================================================================
Write-Host "`n--- Installation des Logiciels ---"

Write-Host "Informations Winget :"
winget --info # Pour voir la version et les chemins des logs par défaut de Winget

Write-Host "Tentative de réinitialisation des sources Winget (msstore et winget)..."
try {
    Write-Host "Réinitialisation de la source winget..."
    winget source reset --force
    Start-Sleep -Seconds 2
    Write-Host "Liste des sources Winget après réinitialisation:"
    winget source list
} catch {
    Write-Warning "Erreur lors de la réinitialisation des sources Winget: $($_.Exception.Message)"
}
Start-Sleep -Seconds 3


function Install-SoftwareWithWinget {
    param (
        [string]$AppName,
        [string]$AppId
    )
    Write-Host "`nInstallation de $AppName (ID: $AppId) via Winget..."
    
    # Vérification si déjà installé (inchangé)
    $isInstalled = $false
    try {
        $installedOutput = winget list --id $AppId -n 1 --accept-source-agreements
        if ($installedOutput -match $AppId) {
            Write-Host "$AppName est déjà installé."
            $isInstalled = $true
        }
    } catch {
        Write-Warning "Impossible de vérifier si $AppName est installé via Winget (winget list a échoué). Tentative d'installation. Erreur: $($_.Exception.Message)"
    }
    if ($isInstalled) { return }
    
    # Vérifier et ajouter les sources Winget si elles manquent APRÈS la tentative de reset
    # (Cette vérification est faite une fois au début de la section Software Installation maintenant)

    # Gestion des logs Winget (inchangé)
    $LogWingetDir = Join-Path -Path $LogPath -ChildPath "WingetLogs"
    If (-not (Test-Path $LogWingetDir)) {
        try { New-Item -ItemType Directory -Path $LogWingetDir -Force -ErrorAction Stop | Out-Null }
        catch { Write-Warning "Impossible de créer le dossier de logs Winget: $LogWingetDir. Erreur: $($_.Exception.Message)"; $LogWingetDir = $null }
    }
    $CleanAppIdForLog = $AppId -replace '[^a-zA-Z0-9.-]','_' 
    $WingetLogFile = ""
    if ($LogWingetDir) {
        $WingetLogFile = Join-Path -Path $LogWingetDir -ChildPath "$($CleanAppIdForLog)_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    }

    # Construction de la liste d'arguments pour Start-Process
    # Start-Process -ArgumentList préfère une chaîne unique, où les arguments avec espaces sont entre guillemets.
    $Args = "install --id ""$AppId"" -e --accept-package-agreements --accept-source-agreements --silent --source winget --verbose-logs"
    if ($WingetLogFile) {
         $Args += " --log ""$WingetLogFile""" # Guillemets autour du chemin du log
    } else {
        Write-Warning "L'option --log pour Winget ne sera pas utilisée car le dossier de logs n'a pas pu être créé."
    }

    Write-Host "Commande Winget en cours d'exécution: winget.exe $Args"

    try {
        # On passe la chaîne $Args directement
        $process = Start-Process winget.exe -ArgumentList $Args -Wait -PassThru -WindowStyle Minimized 
        $exitCode = $process.ExitCode

        if ($exitCode -eq 0) {
            Write-Host "$AppName installé avec succès."
        } else {
            Write-Warning "$AppName n'a pas pu être installé. Code de sortie Winget: $exitCode."
            if ($WingetLogFile -and (Test-Path $WingetLogFile)) {
                Write-Warning "Consultez les logs Winget spécifiques : $WingetLogFile"
                Write-Host "Dernières lignes du log Winget ($AppName):"
                Get-Content $WingetLogFile -Tail 20 | ForEach-Object {Write-Host "  $_"}
            } elseif ($WingetLogFile) {
                Write-Warning "Le fichier de log Winget $WingetLogFile n'a pas été trouvé ou créé."
            } else {
                Write-Warning "Aucun fichier de log Winget n'a été spécifié pour cette tentative."
            }
        }
    } catch {
        Write-Warning "Échec critique du lancement de Winget pour $AppName. Erreur PowerShell: $($_.Exception.Message)."
    }
}

# Logiciels standards
Install-SoftwareWithWinget -AppName "Google Chrome" -AppId "Google.Chrome"
Install-SoftwareWithWinget -AppName "Mozilla Firefox" -AppId "Mozilla.Firefox"
Write-Host "Cette partie peut prendre un peu plus de temps, Acrobat est long a installer"
Install-SoftwareWithWinget -AppName "Adobe Acrobat Reader DC (64-bit)" -AppId "Adobe.Acrobat.Reader.64-bit"

# Logiciels spécifiques au constructeur
$Manufacturer = (Get-CimInstance Win32_ComputerSystem).Manufacturer
Write-Host "`nFabricant détecté : $Manufacturer"

if ($Manufacturer -like "*Dell*") {
    Install-SoftwareWithWinget -AppName "Dell Command Update" -AppId "Dell.CommandUpdate.Universal" 

    Write-Host "  Tentative de lancement des mises à jour Dell Command Update v5.x..."
    $dcuCliExecutable = "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe"
    $dcuScanLogParentFolder = Join-Path -Path $LogPath -ChildPath "DCUScanLogs" 
    $dcuApplyLogParentFolder = Join-Path -Path $LogPath -ChildPath "DCUApplyLogs"
    $dcuScanLogFile = Join-Path -Path $dcuScanLogParentFolder -ChildPath "dcu_scan_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    $dcuApplyLogFile = Join-Path -Path $dcuApplyLogParentFolder -ChildPath "dcu_apply_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

    if (-not (Test-Path $dcuScanLogParentFolder)) { try { New-Item -ItemType Directory -Path $dcuScanLogParentFolder -Force -ErrorAction Stop | Out-Null } catch {} }
    if (-not (Test-Path $dcuApplyLogParentFolder)) { try { New-Item -ItemType Directory -Path $dcuApplyLogParentFolder -Force -ErrorAction Stop | Out-Null } catch {} }

    if (Test-Path $dcuCliExecutable) {
        Write-Host "    Utilisation de : $dcuCliExecutable"
        
        # Phase 1: Scan des mises à jour
        Write-Host "    Scan des mises à jour Dell en cours... (cela peut prendre du temps)"
        $scanSuccess = $false
        $updatesAvailable = $false
        try {
            $scanArgs = "/scan -silent -outputLog=`"$dcuScanLogFile`""
            Write-Host "      Exécution: $dcuCliExecutable $scanArgs"
            $scanProcess = Start-Process -FilePath $dcuCliExecutable -ArgumentList $scanArgs -Wait -PassThru -WindowStyle Minimized -ErrorAction Stop
            $scanExitCode = $scanProcess.ExitCode
            Write-Host "    Scan Dell terminé. Code de sortie: $scanExitCode."

            # Interprétation des codes de sortie du scan
            # Code général '0' = Succès (peut signifier aucune MAJ ou MAJ trouvées sans erreur spécifique de scan)
            # Code général '2' = Mises à jour disponibles (selon ancienne doc, mais on va se fier aux codes v5.x s'ils sont précis)
            # Code spécifique v5.x '500' = Aucune MAJ trouvée
            # Autres codes spécifiques v5.x (501, 502, 503) = Erreurs de scan
            # Code général '1' = Reboot requis (peu probable après juste un scan, mais on le note)

            if ($scanExitCode -eq 0) { # Succès général
                Write-Host "    Scan réussi (code 0). Il se peut que des MAJ soient disponibles ou que le système soit à jour."
                # DCU v5.x ne semble pas avoir un code spécifique pour "MAJ disponibles" après /scan,
                # donc on suppose que le code 0 peut couvrir cela et on procède à /applyUpdates.
                # /applyUpdates gérera le cas où il n'y a rien à appliquer.
                $scanSuccess = $true
                $updatesAvailable = $true # On suppose que si le scan est 0, on tente d'appliquer
            } elseif ($scanExitCode -eq 500) { # Spécifique v5.x: Aucune mise à jour trouvée
                Write-Host "    Scan réussi: Aucune mise à jour Dell applicable trouvée."
                $scanSuccess = $true
                $updatesAvailable = $false
            } elseif ($scanExitCode -eq 2) { # Code général pour "Succès, Reboot peut être requis OU MAJ Appliquées/Disponibles"
                                           # Pour un /scan, cela signifie probablement "MAJ disponibles"
                Write-Host "    Scan réussi: Des mises à jour Dell sont disponibles."
                $scanSuccess = $true
                $updatesAvailable = $true
            } else { # Tout autre code est considéré comme une erreur de scan
                Write-Warning "    Le scan des mises à jour Dell a échoué ou s'est terminé avec un code d'erreur inattendu: $scanExitCode."
                $scanSuccess = $false
            }
        } catch {
            Write-Warning "    Erreur lors de l'exécution de la phase de scan de Dell Command Update CLI : $($_.Exception.Message)"
            $scanSuccess = $false
        }

        # Phase 2: Application des mises à jour (si le scan a réussi et qu'on suppose des MAJ ou qu'on veut laisser /applyUpdates décider)
        if ($scanSuccess -and $updatesAvailable) {
            Write-Host "    Tentative d'application des mises à jour Dell en cours... (sans redémarrage auto)"
            try {
                $applyArgs = "/applyUpdates -reboot=disable -silent -outputLog=`"$dcuApplyLogFile`""
                Write-Host "      Exécution: $dcuCliExecutable $applyArgs"
                $applyProcess = Start-Process -FilePath $dcuCliExecutable -ArgumentList $applyArgs -Wait -PassThru -WindowStyle Minimized -ErrorAction Stop
                $applyExitCode = $applyProcess.ExitCode
                Write-Host "    Application des mises à jour Dell terminée. Code de sortie: $applyExitCode."

                # Interprétation des codes de sortie de /applyUpdates
                # Code général '0' = Succès, aucune action de reboot requise par DCU (mais le système peut en avoir besoin)
                # Code général '1' = Reboot requis explicitement par DCU
                # Codes spécifiques v5.x (1000, 1001, 1002) = Erreurs d'application
                
                if ($applyExitCode -eq 0) {
                    Write-Host "      Mises à jour Dell appliquées avec succès (code 0)."
                    # Vérifier si un reboot est quand même en attente à cause des MAJ
                    # Test-PendingReboot (si dispo) ou $Global:RebootRequired = $true après cette section
                } elseif ($applyExitCode -eq 1) { # Reboot Requis général
                    Write-Warning "      Mises à jour Dell appliquées, un redémarrage EST REQUIS par Dell Command Update (code 1)."
                    $Global:RebootRequired = $true
                } elseif ($applyExitCode -eq 2) { # Code général pour "Succès, Reboot peut être requis OU MAJ Appliquées/Disponibles"
                                               # Pour /applyUpdates, cela signifie souvent "MAJ appliquées, Reboot peut être requis"
                    Write-Warning "      Mises à jour Dell appliquées (code 2), un redémarrage peut être requis."
                    $Global:RebootRequired = $true # Prudence
                } else { # Codes d'erreur spécifiques (1000-1002) ou autres codes généraux d'erreur
                    Write-Warning "    L'application des mises à jour Dell a échoué ou s'est terminée avec un code d'erreur: $applyExitCode."
                }
            } catch {
                 Write-Warning "    Erreur lors de l'exécution de la phase d'application de Dell Command Update CLI : $($_.Exception.Message)"
            }
        } elseif ($scanSuccess -and (-not $updatesAvailable)) {
            Write-Host "    Aucune mise à jour Dell à appliquer suite au scan."
        }
        
    } else {
        Write-Warning "  $dcuCliExecutable non trouvé. Impossible de lancer les mises à jour des pilotes Dell automatiquement."
    }
} elseif ($Manufacturer -like "*HP*") {
    Install-SoftwareWithWinget -AppName "HP Support Assistant" -AppId "HP.SupportAssistant"
    Write-Host "  HP Support Assistant installé. Les mises à jour de pilotes HP devront être lancées manuellement ou via une autre solution (ex: HP Image Assistant)."
}

# Configurer Chrome (master_preferences)
$ChromeInstallPath1 = "C:\Program Files\Google\Chrome\Application"
$ChromeInstallPath2 = "C:\Program Files (x86)\Google\Chrome\Application"
$ChromeMasterPrefsFile = Join-Path -Path $ConfigFolderPath -ChildPath "chrome_master_preferences.json"

if (Test-Path $ChromeMasterPrefsFile) {
    if (Test-Path $ChromeInstallPath1) {
        Write-Host "Copie de master_preferences pour Chrome (64-bit)..."
        Copy-Item -Path $ChromeMasterPrefsFile -Destination $ChromeInstallPath1 -Force
    } elseif (Test-Path $ChromeInstallPath2) {
        Write-Host "Copie de master_preferences pour Chrome (32-bit)..."
        Copy-Item -Path $ChromeMasterPrefsFile -Destination $ChromeInstallPath2 -Force
    } else {
        Write-Warning "Dossier d'installation de Chrome non trouvé. master_preferences non appliqué."
    }
} else {
    Write-Warning "Fichier chrome_master_preferences.json non trouvé dans $ConfigFolderPath."
}

# Configurer Firefox (policies.json)
$FirefoxInstallPath1 = "C:\Program Files\Mozilla Firefox"
$FirefoxInstallPath2 = "C:\Program Files (x86)\Mozilla Firefox"
$FirefoxPoliciesFile = Join-Path -Path $ConfigFolderPath -ChildPath "firefox_policies.json"

if (Test-Path $FirefoxPoliciesFile) {
    $FirefoxDistributionFolder = ""
    if (Test-Path $FirefoxInstallPath1) { $FirefoxDistributionFolder = Join-Path $FirefoxInstallPath1 "distribution" }
    elseif (Test-Path $FirefoxInstallPath2) { $FirefoxDistributionFolder = Join-Path $FirefoxInstallPath2 "distribution" }

    if ($FirefoxDistributionFolder) {
        Write-Host "Copie de policies.json pour Firefox..."
        If (-not (Test-Path $FirefoxDistributionFolder)) { New-Item -ItemType Directory -Path $FirefoxDistributionFolder -Force | Out-Null }
        Copy-Item -Path $FirefoxPoliciesFile -Destination (Join-Path $FirefoxDistributionFolder "policies.json") -Force
    } else {
        Write-Warning "Dossier d'installation de Firefox non trouvé. policies.json non appliqué."
    }
} else {
    Write-Warning "Fichier firefox_policies.json non trouvé dans $ConfigFolderPath."
}

#endregion

# == ÉTAPE 4: Personnalisation Post-Installation ==
# --- Desktop and Taskbar Customization ---
Write-Host "`n  --- Personnalisation Bureau et Barre des Tâches ---"
# Supprimer les raccourcis Bureau
Write-Host "Suppression des raccourcis Microsoft Edge du bureau..."
$PublicDesktop = "$env:PUBLIC\Desktop"
$UserDesktop = "$($env:USERPROFILE)\Desktop" # S'applique à l'utilisateur admin qui exécute. Pour l'utilisateur final, faire sur son profil.

Remove-Item "$PublicDesktop\Microsoft Edge.lnk" -Force -ErrorAction SilentlyContinue
Remove-Item "$UserDesktop\Microsoft Edge.lnk" -Force -ErrorAction SilentlyContinue

# Le Panneau de configuration n'est généralement pas un .lnk simple à supprimer.
# Masquer l'icône du Panneau de config du bureau (pour utilisateur courant, nécessite déco/reco ou redémarrage explorer):
# Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue

# Épingler à la barre des tâches (Méthode LayoutModification.xml - la plus fiable)
# S'applique aux NOUVEAUX profils utilisateurs. Pour l'utilisateur actuel, c'est plus complexe.
$TaskbarLayoutFile = Join-Path -Path $ConfigFolderPath -ChildPath "TaskbarLayout.xml"
$DefaultUserProfile = "C:\Users\Default\AppData\Local\Microsoft\Windows\Shell"

if (Test-Path $TaskbarLayoutFile) {
    Write-Host "Application de la configuration de la barre des tâches pour les nouveaux profils..."
    If (-not (Test-Path $DefaultUserProfile)) { New-Item -ItemType Directory -Path $DefaultUserProfile -Force -Recurse | Out-Null }
    Copy-Item -Path $TaskbarLayoutFile -Destination (Join-Path $DefaultUserProfile "LayoutModification.xml") -Force
} else {
    Write-Warning "Fichier TaskbarLayout.xml non trouvé dans $ConfigFolderPath. Épinglage non configuré pour les nouveaux profils."
}
# Remove-Item "$UserDesktop\Microsoft Edge.lnk" -Force -ErrorAction SilentlyContinue

$TaskbarLayoutFile = Join-Path -Path $ConfigFolderPath -ChildPath "TaskbarLayout.xml"
$DefaultUserProfileShell = "C:\Users\Default\AppData\Local\Microsoft\Windows\Shell"
if (Test-Path $TaskbarLayoutFile) {
    Write-Host "    Application de la configuration de la barre des tâches pour les nouveaux profils..."
    If (-not (Test-Path $DefaultUserProfileShell)) { New-Item -ItemType Directory -Path $DefaultUserProfileShell -Force -Recurse | Out-Null }
    Copy-Item -Path $TaskbarLayoutFile -Destination (Join-Path $DefaultUserProfileShell "LayoutModification.xml") -Force
} else { Write-Warning "    Fichier TaskbarLayout.xml non trouvé dans $ConfigFolderPath." }

# == ÉTAPE 5: Mises à Jour Windows ==
Write-Host "Installation du module PSWindowsUpdate si nécessaire..."
$PSWindowsUpdateModule = Get-Module -ListAvailable -Name PSWindowsUpdate | Sort-Object Version -Descending | Select-Object -First 1

if (-not $PSWindowsUpdateModule) {
    try {
		Write-Host "Vérification/Installation du fournisseur NuGet requis..."
		Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser -ErrorAction SilentlyContinue
        Write-Host "Module PSWindowsUpdate non trouvé localement. Tentative d'installation depuis PSGallery..."
        Install-Module PSWindowsUpdate -Force -SkipPublisherCheck -Confirm:$false -Scope CurrentUser -ErrorAction Stop
        Write-Host "Module PSWindowsUpdate installé. Tentative d'importation..."
        Import-Module PSWindowsUpdate -Force -ErrorAction Stop
        $PSWindowsUpdateModule = Get-Module -Name PSWindowsUpdate # Mettre à jour la variable
    } catch {
        Write-Error "Échec de l'installation ou de l'importation du module PSWindowsUpdate: $($_.Exception.Message)"
    }
} else {
     Write-Host "Module PSWindowsUpdate trouvé (Version: $($PSWindowsUpdateModule.Version)). Tentative d'importation..."
     Import-Module $PSWindowsUpdateModule -Force -ErrorAction SilentlyContinue # Importer l'objet module directement
     # Vérifier si réellement importé
     if (-not (Get-Module -Name PSWindowsUpdate)) {
         Write-Warning "L'importation du module PSWindowsUpdate existant a échoué."
         $PSWindowsUpdateModule = $null # Réinitialiser pour que la condition suivante échoue
     } else {
         $PSWindowsUpdateModule = Get-Module -Name PSWindowsUpdate # S'assurer d'avoir l'objet du module chargé
         Write-Host "Module PSWindowsUpdate importé avec succès."
     }
}
if ($PSWindowsUpdateModule) {
    Write-Host "Module PSWindowsUpdate est chargé. Version: $($PSWindowsUpdateModule.Version)" # Corrigé pour afficher la version
    Write-Host "Recherche et installation des mises à jour Windows..."
    try {
        # AJOUTER -IgnoreReboot ici
        Get-WindowsUpdate -Install -AcceptAll -MicrosoftUpdate -Verbose -IgnoreReboot 
        
        # La vérification de redémarrage en attente reste importante
        if (Get-Command Test-PendingReboot -ErrorAction SilentlyContinue) {
            if (Test-PendingReboot) {
                Write-Host "Un redémarrage est en attente pour appliquer les mises à jour (détecté par Test-PendingReboot)."
                $Global:RebootRequired = $true # S'assurer de le signaler pour la fin du script
            } else {
                Write-Host "Aucun redémarrage en attente détecté par Test-PendingReboot."
            }
        } else {
            # ... (votre logique de fallback pour Test-PendingReboot) ...
            # Assurez-vous de mettre $Global:RebootRequired = $true ici aussi si un redémarrage est détecté
            $PendingFileRename = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
            $RebootPendingWU = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -ErrorAction SilentlyContinue
            if ($PendingFileRename.PendingFileRenameOperations -or $RebootPendingWU) {
                 Write-Host "Un redémarrage semble nécessaire (indicateurs du registre)."
                 $Global:RebootRequired = $true
            }
        }
    } catch {
        Write-Warning "Erreur lors de la recherche/installation des mises à jour Windows: $($_.Exception.Message)"
    }
} else {
    Write-Warning "Module PSWindowsUpdate non chargé. Impossible de lancer les mises à jour Windows."
}
#endregion

#region Finalization
Write-Host "`n-----------------------------------------------------"
Write-Host "Script de préparation Koesio terminé."
Stop-Transcript
$Global:RebootRequired = $true
if ($Global:RebootRequired) {
    Write-Warning "Un redémarrage est nécessaire pour que toutes les modifications prennent effet."
    $choiceReboot = Read-Host "Voulez-vous redémarrer l'ordinateur maintenant ? [O/n]"
    if ($choiceReboot -eq '' -or $choiceReboot -eq 'o' -or $choiceReboot -eq 'O') {
        Restart-Computer -Force
    } else {
        Write-Host "Veuillez redémarrer l'ordinateur manuellement plus tard."
    }
} else {
    Write-Host "Certaines modifications peuvent nécessiter une déconnexion/reconnexion ou un redémarrage d'explorer.exe pour être visibles."
}
Read-Host "Appuyez sur Entrée pour fermer cette fenêtre."
#endregion

#endregion