#Requires -Version 5.1
<#
.SYNOPSIS
Script de préparation et de déploiement PRO v4.0 pour Koesio Aquitaine.
Intègre corrections critiques (BitLocker, Registre, PSWindowsUpdate), sélection logiciels, épinglage.

.DESCRIPTION
Version PRO avec corrections majeures basées sur logs v3.6, v3.7 et retours utilisateurs.
Automatise : Nommage, Config système/alim, BitLocker, Installation Choco + Logiciels Base/Optionnels,
Config Confidentialité/Optimisation, Outils Fabricant, GoToAssist, Infos OEM, MàJ Windows,
Épinglage Tâches, Nettoyage (préserve Logs).

.PARAMETER ComputerName
Nom spécifique à donner à l'ordinateur.

.PARAMETER UseSerialNumberName
Utiliser le numéro de série comme nom d'ordinateur.

.PARAMETER SkipBitLockerDecryption
Ne pas proposer le déchiffrement BitLocker.

.PARAMETER SkipWindowsUpdate
Ne pas lancer l'installation des mises à jour Windows.

.PARAMETER LogLevel
Niveau de détail des logs console (INFO | VERBOSE). Défaut: INFO.

.NOTES
Version : 4.0.2025
Auteur  : Quentin Chaillou // Quentin.Chaillou@koesio.fr
Date    : 2025-04-25
IMPORTANT: Enregistrer ce fichier en UTF-8 avec BOM pour gérer correctement les accents.
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [string]$ComputerName,
    [switch]$UseSerialNumberName,
    [switch]$SkipBitLockerDecryption,
    [switch]$SkipWindowsUpdate,
    [ValidateSet('INFO','VERBOSE')][string]$LogLevel = 'INFO'
)

#region Initialisation globale
$ScriptVersion = '4.0.2025'
$CompanyName   = 'Koesio Aquitaine'
$SupportInfo   = @{ Manufacturer=$CompanyName; SupportHours='08H30-12H30|14H00-17H30'; SupportPhone='05 57 51 52 52'; SupportURL='https://www.koesio.com/' }
if (-not $PSScriptRoot) { $PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition }
$DataPath  = Join-Path $PSScriptRoot 'Data'
$LogPath   = Join-Path $PSScriptRoot 'Logs'
$LogFile   = Join-Path $LogPath "Deploy_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
if (-not (Test-Path $LogPath)) { New-Item $LogPath -ItemType Directory -Force | Out-Null }
Start-Transcript -Path $LogFile -Append
$Script:EffectiveLogLevel = $LogLevel

# --- Fonctions utilitaires ---
Function Write-Log {
    param([string]$Message, [string]$Level='INFO', [ConsoleColor]$ForegroundColor, [ConsoleColor]$BackgroundColor)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry = "[$ts] [$Level] $Message"

    $show = $false
    switch ($Script:EffectiveLogLevel) {
        'VERBOSE' { $show = $true }
        'INFO'    { if ($Level -in 'INFO','STEP','SUCCESS','WARN','ERROR') { $show = $true } }
    }
    if ($show) {
        switch ($Level) {
            'STEP'    { Write-Host $entry -ForegroundColor Cyan }
            'SUCCESS' { Write-Host $entry -ForegroundColor Green }
            'WARN'    { Write-Host $entry -ForegroundColor Yellow }
            'ERROR'   { Write-Host $entry -ForegroundColor Red }
            default   { Write-Host $entry }
        }
    }
}

Function Show-Banner { param([string]$Step) ; Clear-Host ; Write-Host ('='*80) ; Write-Host "  DEPLOY KOESIO AQUITAINE (PRO)  Version $ScriptVersion  Étape : $Step  " ; Write-Host ('='*80) ; Write-Log "Début de l'étape : $Step" 'STEP' }

Function Check-Admin { Write-Log 'Vérification droits admin...' 'INFO' ; if (-not ( [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Write-Log 'Drois admin requis.' 'ERROR'; Stop-Transcript; Exit 1 } ; Write-Log 'Droits admin ok.' 'SUCCESS' }

Function Set-RegValue {
    param(
        [string]$Path,
        [string]$Name,
        [Parameter(Mandatory)]$Value,
        [ValidateSet('String','DWORD','QWORD')][string]$Type = 'DWORD'
    )
    try {
        if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null ; Write-Log "Création clé registre: $Path" 'VERBOSE' }
        if (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue) {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -ErrorAction Stop
        } else {
            New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force -ErrorAction Stop
        }
        return $true
    } catch {
        Write-Log "Erreur clé registre '$Name' dans '$Path': $_" 'WARN'
        return $false
    }
}
#endregion

#region 1. Vérifications initiales
Check-Admin
Show-Banner 'Vérifications initiales'
Write-Log "Démarrage script v$ScriptVersion" 'INFO'
#endregion

#region 2. Configuration nom PC
Show-Banner 'Nom PC'
$sys = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS
$serial = $bios.SerialNumber.Trim()
$current = $sys.Name
if ($UseSerialNumberName -or -not $ComputerName) {
    $target = $serial
} else {
    $target = $ComputerName
}
if ($current -ne $target) {
    if ($PSCmdlet.ShouldProcess($current, "Renommer en $target")) { Rename-Computer -NewName $target -Force -ErrorAction Stop ; Write-Log "Renommage OK: $target" 'SUCCESS' }
} else { Write-Log 'Nom PC inchangé.' 'INFO' }
#endregion

#region 3. Config système de base
Show-Banner 'Config Système Base'
# Icônes bureau
$hidePaths = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel','HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu'
foreach ($p in $hidePaths) {
    foreach ($id in @('{20D04FE0-3AEA-1069-A2D8-08002B30309D}','{59031a47-3f72-44a7-89c5-5595fe6b30ee}')) {
        Set-RegValue -Path $p -Name $id -Value 0 -Type DWORD
    }
}
# NumLock
Set-RegValue -Path 'HKCU:\Control Panel\Keyboard' -Name 'InitialKeyboardIndicators' -Value '2' -Type String
# Alimentation & démarrage rapide
powercfg /change monitor-timeout-ac 60
powercfg /change monitor-timeout-dc 60
powercfg /change disk-timeout-ac 0
powercfg /change disk-timeout-dc 0
powercfg /change standby-timeout-ac 0
powercfg /change standby-timeout-dc 0
Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name 'HiberbootEnabled' -Value 0 -Type DWORD
# Nettoyage raccourcis Edge
Remove-Item "$env:PUBLIC\Desktop\Microsoft Edge.lnk" -Force -ErrorAction SilentlyContinue
Remove-Item "$env:USERPROFILE\Desktop\Microsoft Edge.lnk" -Force -ErrorAction SilentlyContinue
Write-Log 'Config système base terminée.' 'SUCCESS'
#endregion

#region 4. BitLocker
Show-Banner 'Gestion BitLocker'
Import-Module BitLocker -ErrorAction SilentlyContinue
$vols = Get-BitLockerVolume -ErrorAction SilentlyContinue
if ($vols) {
    foreach ($vol in $vols) {
        Write-Log "Volume $($vol.MountPoint) statut $($vol.VolumeStatus)" 'INFO'
        if ($vol.VolumeStatus -match 'Encrypted|EncryptionInProgress') {
            # Affichage clé de récupération
            $rec = $vol.KeyProtector | Where KeyProtectorType -eq 'RecoveryPassword' | Select -First 1
            if ($rec) {
                Write-Host "Clé BitLocker $($vol.MountPoint) : $($rec.RecoveryPassword)" -ForegroundColor Yellow
                Read-Host 'Appuyez sur Entrée après sauvegarde'
            }
            if (-not $SkipBitLockerDecryption -and $vol.VolumeStatus -ne 'FullyDecrypted') {
                if ($PSCmdlet.ShouldProcess($vol.MountPoint, 'Disable-BitLocker permanent')) {
                    Clear-BitLockerAutoUnlock -MountPoint $vol.MountPoint
                    Disable-BitLocker -MountPoint $vol.MountPoint
                    Write-Log "Déchiffrement lancé." 'SUCCESS'
                }
            }
        }
    }
} else { Write-Log 'Aucun volume BitLocker.' 'INFO' }
#endregion

#region 5. Installation logiciels (Choco)
Show-Banner 'Choco & Base'
if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
    Set-ExecutionPolicy Bypass -Scope Process -Force
    Invoke-Expression ((New-Object Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
}
$base = 'firefox','adobereader','7zip.install','teamviewer','openjdk','dotnetfx'
choco install googlechrome -y --ignore-checksums --accept-licenses --no-progress
foreach ($pkg in $base) {
    if (choco list --local-only --exact $pkg -r) { Write-Log "$pkg déjà installé" 'INFO' } else { choco install $pkg -y --accept-licenses --no-progress }
}
Write-Log 'Base terminée.' 'SUCCESS'

# Optionnels
Show-Banner 'Logiciels Optionnels'
$opt = @{
    1=@{N='Microsoft 365 Business'; ID='office365business'};
    2=@{N='Office 2019 Famille/PME'; ID='office2019homebusiness'};
    3=@{N='Office 2021 Famille/PME'; ID='office2021homebusiness'};
    4=@{N='OpenVPN Connect'; ID='openvpn'};
    5=@{N='FortiClient VPN'; ID='forticlientvpn'};
    6=@{N='VLC Media Player'; ID='vlc'}
}
Write-Host '--- Logiciels Optionnels ---' -ForegroundColor Cyan
foreach ($i in $opt.Keys) { Write-Host "$i. $($opt[$i].N)" -ForegroundColor Yellow }
$user = Read-Host 'Numéros à installer (ex:1,3,6)' 
if ($user) {
    $sel = $user -split ',' | ForEach-Object { $_.Trim() }
    foreach ($n in $sel) {
        if ($opt.ContainsKey([int]$n)) { choco install $opt[[int]$n].ID -y --accept-licenses --no-progress }
    }
}
Write-Log 'Optionnels terminés.' 'SUCCESS'
#endregion

#region 6. Confidentialité & Optimisation
Show-Banner 'Confidentialité & Optimisation'
Set-RegValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo' -Name 'Enabled' -Value 0
Set-RegValue -Path 'HKCU:\Control Panel\International\User Profile' -Name 'HttpAcceptLanguageOptOut' -Value 1
Set-RegValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Privacy' -Name 'Start_TrackProgs' -Value 0
Set-RegValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SubscribedContent-338389Enabled' -Value 0
Set-RegValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SubscribedContent-310093Enabled' -Value 0
Set-RegValue -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'AllowAutoGameMode' -Value 0
Set-RegValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR' -Name 'AppCaptureEnabled' -Value 0
# Autres produits MS
try { Install-PackageProvider NuGet -Force -Confirm:$false; Install-Module PSWindowsUpdate -Force -Confirm:$false; Import-Module PSWindowsUpdate -Force }
catch { Write-Log 'Erreur PSWindowsUpdate' 'WARN' }
Set-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config' -Name 'DODownloadMode' -Value 0
Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'OneDrive' -ErrorAction SilentlyContinue
Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Name 'DisableFileSyncNGSC' -Value 1
Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name 'StartupBoostEnabled' -Value 0
Set-RegValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'ShowCopilotButton' -Value 0
Write-Log 'Confidentialité & Optimisation terminée.' 'SUCCESS'
#endregion

#region 7. Outils Fabricant
Show-Banner 'Outils Fabricant'
if (Test-Path $DataPath) {
    switch -Wildcard ($sys.Manufacturer) {
        '*Dell*' { Start-Process "$DataPath\DellCommandUpdate.exe" -ArgumentList '/s','/norestart' -Wait }
        '*HP*'   { Start-Process "$DataPath\sp138267.exe" -ArgumentList '/s','/norestart' -Wait }
        default  { Write-Log 'Fabricant non géré.' 'INFO' }
    }
}
#endregion

#region 8. GoToAssist
Show-Banner 'GoToAssist'
$src = Join-Path $DataPath 'GoToAssist.exe'; $dest = Join-Path $env:ProgramFiles 'GoToAssist'
if (Test-Path $src) {
    Copy-Item $src $dest -Force
    $link = Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'GoToAssist.lnk'
    (New-Object -Com Shell.Application).CreateShortcut($link).TargetPath = "$dest\GoToAssist.exe"
}
#endregion

#region 9. Infos OEM
Show-Banner 'Infos OEM'
$oem = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation'
if (-not (Test-Path $oem)) { New-Item $oem -Force | Out-Null }
foreach ($k in $SupportInfo.Keys) { Set-RegValue -Path $oem -Name $k -Value $SupportInfo[$k] -Type String }
#endregion

#region 10. Raccourcis & Épinglage
Show-Banner 'Raccourcis & Épinglage'
Function New-Shortcut { param($Path,$Target) $sh=New-Object -Com WScript.Shell; $sc=$sh.CreateShortcut($Path); $sc.TargetPath=$Target; $sc.Save(); }
# Adobe desktop
$paths=@(
    "$env:ProgramFiles\Adobe\Acrobat DC\Acrobat\Acrobat.exe",
    "$env:ProgramFiles(x86)\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe"
)
$exe=$paths | Where Test-Path | Select -First 1
if ($exe) { New-Shortcut (Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'Adobe Acrobat Reader DC.lnk') $exe }
# Épingler Chrome & Acrobat
$all=@(
    'Google Chrome.lnk','Adobe Acrobat Reader DC.lnk'
)
foreach ($ln in $all) {
    $full=Join-Path "$env:ProgramData\Microsoft\Windows\Start Menu\Programs" $ln
    if (Test-Path $full) { (New-Object -Com Shell.Application).Namespace((Split-Path $full)).ParseName((Split-Path $full -Leaf)).Verbs() | Where Name -eq 'Épingler à la barre des tâches' | ForEach-Object DoIt }
}
Write-Log 'Raccourcis & épinglage terminés.' 'SUCCESS'
#endregion

#region 11. Mises à jour Windows
Show-Banner 'MàJ Windows'
if (-not $SkipWindowsUpdate) {
    try {
        Write-Log 'Lancement MàJ Windows...' 'INFO'
        Install-WindowsUpdate -AcceptAll -AutoReboot -IgnoreReboot -ErrorAction Stop
    } catch { Write-Log "Erreur MàJ Windows: $_" 'ERROR' }
}
#endregion

Stop-Transcript
Write-Log 'Script terminé.' 'SUCCESS'
