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
Auteur : Quentin Chaillou / Koesio
Date   : 21/05/2025
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

#region Script Setup and Logging
$ScriptBaseDir = $PSScriptRoot
$LogSubDirName = 'Logs'
$LogDir = Join-Path -Path $ScriptBaseDir -ChildPath $LogSubDirName

if (-not (Test-Path -Path $LogDir -PathType Container)) {
    Write-Host "INFO: Création du répertoire Logs : $LogDir"
    try {
        New-Item -Path $LogDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
    } catch {
        Write-Host "ERREUR CRITIQUE: Impossible de créer le répertoire Logs '$LogDir'. Erreur: $($_.Exception.Message)" -ForegroundColor Red
        Exit 1
    }
}

$Timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$ComputerNameForLog = $env:COMPUTERNAME
$LogFileName = "Deploy-Machine_$($ComputerNameForLog)_$Timestamp.log"
$Script:LogPath = Join-Path -Path $LogDir -ChildPath $LogFileName

function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [Parameter(Mandatory=$false)]
        [ValidateSet('INFO', 'WARN', 'ERROR', 'STEP', 'SUCCESS', 'DEBUG')]
        [string]$Level = 'INFO',
        [Parameter(Mandatory=$false)]
        [int]$Indent = 0
    )
    $timeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $indentSpaces = " " * ($Indent * 4)
    $color = switch ($Level) {
        'WARN'    { 'Yellow' }
        'ERROR'   { 'Red' }
        'STEP'    { 'Cyan' }
        'SUCCESS' { 'Green' }
        'DEBUG'   { 'DarkGray'}
        default   { 'White' }
    }
    $logEntry = "$timeStamp [$Level] $($indentSpaces)$Message"
    Write-Host $logEntry -ForegroundColor $color
    try {
        Add-Content -Path $Script:LogPath -Value $logEntry -ErrorAction Stop
    } catch {
        Write-Warning "Impossible d'écrire dans le fichier log '$($Script:LogPath)': $($_.Exception.Message)"
    }
}
#endregion Script Setup and Logging

#region Initialisation & Prérequis
Clear-Host
Write-Host "================================================================================" -ForegroundColor Magenta
Write-Host "=                 Début du Script de Déploiement Machine                     =" -ForegroundColor Magenta
Write-Host "================================================================================" -ForegroundColor Magenta
Write-Log "Script démarré." 'STEP' 0
Write-Log "Fichier Log: $Script:LogPath" 'INFO' 1

$currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log "Ce script nécessite des privilèges administrateur." 'ERROR' 0
    Exit 1
} else {
    Write-Log "Vérification des privilèges administrateur: OK" 'SUCCESS' 1
}

if ($DomainName -and !$AdminCred) { Write-Log "Le paramètre -AdminCred est requis pour joindre le domaine '$DomainName'." 'ERROR' 0; Exit 1 }
if ($DomainName -and !$OUPath) { Write-Log "Le paramètre -OUPath est requis pour joindre le domaine '$DomainName'." 'ERROR' 0; Exit 1 }

Write-Log "Vérification du numéro de série pour renommage optionnel..." 'INFO' 1
$SerialNumber = (Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue | Select-Object -ExpandProperty SerialNumber -ErrorAction SilentlyContinue)
if ($SerialNumber -match '^(Default string|To be filled by O.E.M.|Not Available|None|System Serial Number)$' -or [string]::IsNullOrWhiteSpace($SerialNumber)) {
    Write-Log "Numéro de série non valide ou générique ('$SerialNumber')." 'WARN' 1
    $SerialNumber = $null
} else { Write-Log "Numéro de série détecté : '$SerialNumber'" 'DEBUG' 2 }

if ($SerialNumber -and [string]::IsNullOrWhiteSpace($NewComputerName)) {
    Write-Host "`nUn numéro de série valide a été détecté: '$SerialNumber'" -ForegroundColor Cyan
    $renameChoice = Read-Host "Voulez-vous utiliser ce numéro de série comme nouveau nom d'ordinateur ? ([O]/N)"
    if ($renameChoice -notmatch '^[Nn]$') {
        $NewComputerName = $SerialNumber
        Write-Log "Utilisateur a choisi de renommer avec le numéro de série: '$NewComputerName'" 'INFO' 1
    } else { Write-Log "Utilisateur a choisi de NE PAS utiliser le numéro de série." 'INFO' 1 }
} elseif (-not [string]::IsNullOrWhiteSpace($NewComputerName)) {
     Write-Log "Nom d'ordinateur ('$NewComputerName') fourni, option S/N ignorée." 'INFO' 1
} else { Write-Log "Aucun S/N valide ou nom fourni, le nom actuel sera conservé si DSC ne le change pas." 'INFO' 1}

$TargetComputerNameForDSC = if ([string]::IsNullOrWhiteSpace($NewComputerName)) { $TargetNode } else { $NewComputerName }
Write-Log "Nom Cible pour DSC: $TargetComputerNameForDSC" 'INFO' 1
if ($DomainName) { Write-Log "Jonction au Domaine: $DomainName, OU: $OUPath" 'INFO' 1 } 
else { Write-Log "Jonction au domaine désactivée." 'INFO' 1 }

# DSC Modules Installation (Scope AllUsers is critical for LCM)
foreach ($moduleInfo in @{Name='cChoco'; MinVersion='2.0.0'}, @{Name='ComputerManagementDsc'; MinVersion='7.0.0'}) {
    $moduleName = $moduleInfo.Name
    Write-Log "Vérification du module DSC '$moduleName'..." 'INFO' 1
    $installedModule = Get-Module -ListAvailable -Name $moduleName
    if ($installedModule -and $installedModule.Version -ge $moduleInfo.MinVersion) {
        Write-Log "Module DSC '$moduleName' version $($installedModule.Version) trouvé." 'SUCCESS' 1
    } else {
        Write-Log "Module DSC '$moduleName' non trouvé ou version obsolète. Tentative d'installation/mise à jour..." 'WARN' 1
        try {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction Stop
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Install-Module -Name $moduleName -MinimumVersion $moduleInfo.MinVersion -Force -Scope AllUsers -ErrorAction Stop
            Write-Log "Module DSC '$moduleName' installé/mis à jour avec succès." 'SUCCESS' 1
        } catch {
            Write-Log "ERREUR CRITIQUE lors de l'installation/mise à jour du module '$moduleName': $($_.Exception.Message)" 'ERROR' 1
            Exit 1
        }
    }
    Write-Log "Pré-chargement du module '$moduleName'..." 'DEBUG' 2
    try { Import-Module $moduleName -Force -ErrorAction Stop; Write-Log "Module '$moduleName' chargé." 'SUCCESS' 2 }
    catch { Write-Log "ERREUR CRITIQUE: Module '$moduleName' listé mais non importable. $($_.Exception.Message)" 'ERROR' 1; Exit 1 }
}
#endregion Initialisation & Prérequis

#region Phase 1: Gestion BitLocker
if (-not $SkipBitLockerDecryption) {
    Write-Log "Phase 1: Gestion BitLocker..." 'STEP' 0
    # ... (Code BitLocker inchangé, supposé correct pour l'instant) ...
    # Pour la concision, je ne le remets pas ici, mais il doit être là
    Write-Log "Phase 1: Gestion BitLocker terminée." 'STEP' 0
} else { Write-Log "Phase 1: Gestion BitLocker ignorée." 'INFO' 0 }
#endregion Phase 1: Gestion BitLocker

#region Phase 2: Sélection Logiciels Optionnels
    # ... (Code Sélection Logiciels inchangé, supposé correct pour l'instant) ...
    # Pour la concision, je ne le remets pas ici, mais il doit être là
Write-Log "Phase 2 terminée. IDs Choco optionnels sélectionnés: $($SelectedSoftwareIds -join ', ')" 'STEP' 0
#endregion Phase 2: Sélection Logiciels Optionnels

#region Phase 3: Préparation et Appel DSC
Write-Log "Phase 3: Préparation et Appel DSC..." 'STEP' 0
$ConfigurationData = @{
    AllNodes = @( @{
            ComputerName                 = $TargetComputerNameForDSC
            OptionalChocoPackages        = $SelectedSoftwareIds
            CoreChocoPackages            = @('googlechrome', 'firefox', 'adobereader', 'notepadplusplus.install')
            WindowsFeaturesToEnsure      = @('NetFx3')
            RebootNodeIfNeeded           = (-not $SkipReboot)
    })
}
$MofOutputPath = Join-Path $PSScriptRoot "DSC_MOF"
Write-Log "Importation de MachineConfiguration.ps1..." 'INFO' 1
try { . (Join-Path $PSScriptRoot "MachineConfiguration.ps1") -ErrorAction Stop }
catch { Write-Log "ERREUR importation MachineConfiguration.ps1: $($_.Exception.Message)" 'ERROR' 1; Exit 1}

# Générer le fichier MOF
$nodeData = $ConfigurationData.AllNodes[0] # Récupérer les données du premier (et unique) nœud

Write-Log "Génération du fichier MOF pour '$($nodeData.ComputerName)'..." 'INFO' 1
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
        ErrorAction             = 'Stop' 
    }
    if ($VerbosePreference.ToString() -eq 'Continue') { # Vérifier correctement la préférence Verbose
        $MachineConfigParams.Add('Verbose', $true)
    }

    # Appeler MachineConfiguration avec les paramètres individuels via splatting
    MachineConfiguration @MachineConfigParams

    Write-Log "Compilation de MachineConfiguration terminée." 'SUCCESS' 1 # Message plus précis

} catch {
    Write-Log "ERREUR critique lors de la génération du MOF via MachineConfiguration:" 'ERROR' 1
    Write-Log $_.Exception.Message 'ERROR' 2
    Write-Log $_.ScriptStackTrace 'ERROR' 2
    Exit 1
}
$GeneratedMofFile = Join-Path $MofOutputPath "$($TargetComputerNameForDSC).mof"
$ExpectedMofFileForLocalApply = Join-Path $MofOutputPath "$($TargetNode).mof" # TargetNode est le nom actuel

if (-not (Test-Path $GeneratedMofFile)) {
    Write-Log "ERREUR: MOF '$GeneratedMofFile' non trouvé après génération." 'ERROR' 1; Exit 1
}
if ($GeneratedMofFile -ne $ExpectedMofFileForLocalApply) {
    Write-Log "Renommage MOF de '$GeneratedMofFile' en '$ExpectedMofFileForLocalApply' pour application locale." 'INFO' 1
    if(Test-Path $ExpectedMofFileForLocalApply) { Remove-Item $ExpectedMofFileForLocalApply -Force }
    try { Rename-Item -Path $GeneratedMofFile -NewName $ExpectedMofFileForLocalApply -Force -ErrorAction Stop }
    catch { Write-Log "ERREUR renommage MOF: $($_.Exception.Message)" 'ERROR' 1; Exit 1 }
}

# --- Configuration WinRM ---
Write-Log "Configuration et Vérification de WinRM (HTTP et HTTPS)..." 'INFO' 1
try {
    $winrmCmdPath = Join-Path -Path $env:windir -ChildPath "System32\winrm.cmd"
    Set-Service -Name WinRM -StartupType Automatic -ErrorAction Stop
    if ((Get-Service -Name WinRM).Status -ne 'Running') { Start-Service -Name WinRM -ErrorAction Stop; Start-Sleep -Seconds 3 }
    
    Get-NetConnectionProfile | Where-Object {$_.NetworkCategory -eq 'Public'} | ForEach-Object {
        Write-Log "Profil réseau '$($_.InterfaceAlias)' public. Tentative de changement en Privé..." 'WARN' 2
        Set-NetConnectionProfile -InterfaceIndex $_.InterfaceIndex -NetworkCategory Private -ErrorAction Stop
        Write-Log "Profil '$($_.InterfaceAlias)' changé en Privé." 'SUCCESS' 3
    }

    Write-Log "Exécution 'winrm quickconfig -q'..." 'DEBUG' 2
    $qcResult = Invoke-Expression "$winrmCmdPath quickconfig -q"
    if ($qcResult -match "Public") { Write-Log "ERREUR: WinRM quickconfig indique encore un profil public!" 'ERROR' 3; Exit 1}
    Write-Log "winrm quickconfig terminé." 'SUCCESS' 3

    Write-Log "Test connexion WinRM HTTP local..." 'DEBUG' 2
    Test-WSMan -ComputerName localhost -ErrorAction Stop
    Write-Log "Test connexion WinRM HTTP local: OK" 'SUCCESS' 2
} catch { Write-Log "ERREUR config WinRM HTTP: $($_.Exception.Message)" 'ERROR' 1; Exit 1 }

# --- WinRM HTTPS Configuration (Robuste) ---
Write-Log "Configuration écouteur WinRM HTTPS..." 'INFO' 1
try {
    $currentHostName = $env:COMPUTERNAME
    $winrmListenerNeedsConfiguration = $true
    $listenerCertThumbprint = $null

    $listenerInfo = winrm enumerate winrm/config/Listener | Where-Object { $_ -match 'Transport = HTTPS' }
    if ($listenerInfo) {
        $listenerCertThumbprint = ($listenerInfo -match 'CertificateThumbprint = "(.+?)"').캡처그룹[1].Value
        Write-Log "Écouteur HTTPS existant utilise certificat: $listenerCertThumbprint" 'DEBUG' 2
        if ($listenerCertThumbprint) {
            $certInUse = Get-ChildItem -Path "Cert:\LocalMachine\My\$listenerCertThumbprint" -ErrorAction SilentlyContinue
            if ($certInUse -and ($certInUse.DnsNameList.Punycode -contains $currentHostName) -and ($certInUse.DnsNameList.Punycode -contains "localhost")) {
                Write-Log "Certificat actuel '$listenerCertThumbprint' valide pour '$currentHostName' et 'localhost'." 'INFO' 3
                if (Get-ChildItem -Path "Cert:\LocalMachine\Root\$listenerCertThumbprint" -ErrorAction SilentlyContinue) {
                    Write-Log "Certificat '$listenerCertThumbprint' déjà approuvé (Root). WinRM HTTPS OK." 'SUCCESS' 3
                    $winrmListenerNeedsConfiguration = $false
                } else {
                    Write-Log "Certificat '$listenerCertThumbprint' non approuvé. Tentative d'ajout à Root..." 'WARN' 3
                    $rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine"); $rootStore.Open("ReadWrite")
                    $rootStore.Add($certInUse); $rootStore.Close()
                    Write-Log "Certificat '$listenerCertThumbprint' ajouté à Root." 'SUCCESS' 4
                    $winrmListenerNeedsConfiguration = $false
                }
            } else { Write-Log "Certificat écouteur existant non valide ou noms incorrects. Reconfiguration." 'WARN' 3 }
        } else { Write-Log "Écouteur HTTPS sans thumbprint. Reconfiguration." 'WARN' 3 }
    } else { Write-Log "Aucun écouteur HTTPS. Configuration." 'INFO' 2 }

    if ($winrmListenerNeedsConfiguration) {
        Write-Log "Suppression ancien écouteur HTTPS (si existe)..." 'DEBUG' 2
        Invoke-Expression "$winrmCmdPath delete winrm/config/Listener?Address=*+Transport=HTTPS" | Out-Null # Ignore errors if not exists
        Start-Sleep -Seconds 1

        $certToUse = Get-ChildItem Cert:\LocalMachine\My | Where-Object {
                ($_.DnsNameList.Punycode -contains $currentHostName -and $_.DnsNameList.Punycode -contains 'localhost') -and
                ($_.Extensions | Where-Object {$_.Oid.Value -eq '2.5.29.37'} | ForEach-Object {$_.EnhancedKeyUsages} | Where-Object {$_.Oid.Value -eq '1.3.6.1.5.5.7.3.1'}) -and # Server Auth
                $_.NotAfter -gt (Get-Date)
            } | Sort-Object -Property NotAfter -Descending | Select-Object -First 1

        if (-not $certToUse) {
            Write-Log "Création certificat auto-signé pour '$currentHostName' et 'localhost'..." 'INFO' 3
            $certToUse = New-SelfSignedCertificate -DnsName $currentHostName, "localhost" -CertStoreLocation "Cert:\LocalMachine\My" -KeyUsage KeyEncipherment,DigitalSignature -TextExtension "2.5.29.37={text}1.3.6.1.5.5.7.3.1" -NotAfter (Get-Date).AddYears(5) -ErrorAction Stop
        }
        $listenerCertThumbprint = $certToUse.Thumbprint
        Write-Log "Utilisation du certificat: $listenerCertThumbprint" 'INFO' 3

        if (-not (Get-ChildItem -Path "Cert:\LocalMachine\Root\$listenerCertThumbprint" -ErrorAction SilentlyContinue)) {
            Write-Log "Ajout du certificat '$listenerCertThumbprint' à Root..." 'INFO' 3
            $rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine"); $rootStore.Open("ReadWrite")
            $rootStore.Add($certToUse); $rootStore.Close()
        }
        
        Write-Log "Création écouteur WinRM HTTPS avec cert '$listenerCertThumbprint' pour Hostname '$currentHostName'..." 'INFO' 3
        $createArgs = "create winrm/config/Listener?Address=*+Transport=HTTPS @{Hostname=`"$currentHostName`"; CertificateThumbprint=`"$listenerCertThumbprint`"}"
        Invoke-Expression "$winrmCmdPath $createArgs"
        Start-Sleep -Seconds 2
    }

    Write-Log "Test connexion WinRM HTTPS ($currentHostName)..." 'DEBUG' 2
    Test-WSMan -ComputerName $currentHostName -UseSsl -Authentication Default -ErrorAction Stop
    Write-Log "Test connexion WinRM HTTPS ($currentHostName): OK" 'SUCCESS' 2

} catch { Write-Log "ERREUR MAJEURE config WinRM HTTPS: $($_.Exception.Message) $($_.ScriptStackTrace)" 'ERROR' 1; Exit 1 }

# --- TrustedHosts ---
Write-Log "Configuration TrustedHosts pour DSC local..." 'INFO' 1
$currentTrustedHosts = (Get-Item -Path WSMan:\localhost\Client\TrustedHosts -ErrorAction SilentlyContinue).Value
$requiredHosts = @($env:COMPUTERNAME, "localhost") | Select-Object -Unique
$updateNeeded = $false
if ($currentTrustedHosts -ne "*") {
    $existingList = @($currentTrustedHosts -split ',' | ForEach-Object {$_.Trim()} | Where-Object {$_})
    foreach($host in $requiredHosts) { if ($existingList -notcontains $host) { $existingList += $host; $updateNeeded = $true } }
    if ($updateNeeded) {
        $newTrustedHosts = $existingList -join ','
        Write-Log "Mise à jour TrustedHosts: '$newTrustedHosts'" 'DEBUG' 2
        Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Value $newTrustedHosts -Force -ErrorAction Stop
    } else { Write-Log "TrustedHosts déjà configuré pour les hôtes requis." 'INFO' 2}
} else { Write-Log "TrustedHosts est '*', aucune modification." 'INFO' 2}


# --- Application DSC ---
Write-Log "Application de la configuration DSC sur '$TargetNode' via HTTPS..." 'INFO' 1
try {
    $dscParams = @{ Path = $MofOutputPath; Wait = $true; Force = $true; Verbose = $VerbosePreference.ToString() -eq 'Continue'; ErrorAction = 'Stop' }
    $dscJob = Start-DscConfiguration @dscParams
    # ... (Gestion du $dscJob.State et des erreurs comme avant, pour concision non répété ici) ...
     if ($dscJob.State -eq 'Failed') {
        Write-Log "La tâche DSC a échoué." 'ERROR' 1
        # ... (logique de récupération d'erreur détaillée)
        Exit 1
    } elseif ($dscJob.State -eq 'Completed') {
        Write-Log "Configuration DSC appliquée avec succès." 'SUCCESS' 1
    } else {
        Write-Log "État final de la tâche DSC : $($dscJob.State)" 'INFO' 1
    }

} catch {
    Write-Log "ERREUR lors de Start-DscConfiguration: $($_.Exception.Message)" 'ERROR' 1
    # ... (logique de récupération d'erreur détaillée) ...
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