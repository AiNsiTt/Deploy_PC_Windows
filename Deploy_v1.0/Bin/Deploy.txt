#  Script de prep de poste informatique

Clear-Host
Function Get-Head{
    
    Write-Host -Object "                                                                       " -ForegroundColor "black"  -BackgroundColor "green"
    Write-Host -Object "         PROGRAMME DE PREPARATION DE POSTE KOESIO AQUITAINE         " -ForegroundColor "black"  -BackgroundColor "green"
    Write-Host -Object "                            Version 2.2.2025                           " -ForegroundColor "black"  -BackgroundColor "green"
    Write-Host -Object "                                                                       " -ForegroundColor "black"  -BackgroundColor "green"
    Write-Host -Object "                                                                       " -ForegroundColor "black" 
}

Get-Head

#=============================================================================================
# Type d'installation

    Write-Host -Object " Installation PRO ou PART " -ForegroundColor "green" 
    $choix = read-host 

    Clear-Host
    Get-Head
#=============================================================================================
# Recuperation numeros de serie dans le BIOS

    $SN = Get-CimInstance Win32_BIOS
    $SN = $SN.serialnumber

#=============================================================================================
# Recuperation du Nom du fabricant dans le BIOS

    $Fab = Get-CimInstance Win32_BIOS
    $Fab = $Fab.Manufacturer

#=============================================================================================
# Proposition du numero de serie comme nom de poste

    Write-Host -Object " Voulez vous utiliser $SN comme nom de PC (O/N) " -ForegroundColor "green" 
    $choix2 = read-host 

    Clear-host
    Get-Head

    If ($choix2 -like "O"){ 

        Rename-Computer -NewName $SN 

    }else {

        # Proposition de choix de nom de poste
            Write-Host -Object " Quel nom voulez vous utiliser (entre pour Default) " -ForegroundColor "green" 
            $choix3 = Read-Host 

            If($choix3 -notlike $null){
                Rename-Computer -NewName $choix3 
            }
    }

    Clear-host  
    Get-Head

#=============================================================================================
# Ajout des icones de base windows

    Write-Host -Object " Ajout des icones de base windows " -ForegroundColor "black"  -BackgroundColor "green" 

    # Declaration des variables des emplacements de cle de registre

        $NSP = "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
        $CSM = "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu"

    # Ce PC

        Write-Host -Object " Ajout de l'icone Ce PC sur le bureau " -ForegroundColor "black"  -BackgroundColor "green" 
        
        REG ADD $NSP /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 0 /f
        REG ADD $CSM /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 0 /f

    # Panneau de configuration

        Write-Host -Object " Ajout de l'icone Panneau de configuration sur le bureau " -ForegroundColor "black"  -BackgroundColor "green" 
        
        REG ADD $NSP /v "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" /t REG_DWORD /d 0 /f
        REG ADD $CSM /v "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" /t REG_DWORD /d 0 /f

    # Utilisateur

        Write-Host -Object " Ajout de l'icone Utilisateur sur le bureau " -ForegroundColor "black"  -BackgroundColor "green"  
        
        REG ADD $NSP /v "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" /t REG_DWORD /d 0 /f
        REG ADD $CSM /v "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" /t REG_DWORD /d 0 /f

    # Definition de la cle de registre du verouillage du pave numerique

        Write-Host -Object " Definition de la cle de registre du verouillage du pave numerique " -ForegroundColor "black"  -BackgroundColor "green" 
        
        REG ADD "HKEY_USERS\.DEFAULT\Control Panel\Keyboard" /v "InitialKeyboardIndicators" /d 2 /f

#=============================================================================================
# Reglage extinction de l'ecran

    Write-Host -Object " Modification des reglages d'extinction de l'ecran " -ForegroundColor "black"  -BackgroundColor "green" 

    powercfg /change monitor-timeout-ac 60 # Sur alimentation
    powercfg /change monitor-timeout-dc 60 # Sur Batterie

    Start-Sleep -Seconds 5 

    Write-Host -Object " Modification des reglages d'extinction de l'ecran TERMINER " -ForegroundColor "White"  -BackgroundColor "red" 

# Reglage Veille

    Write-Host -Object " Reglage Veille " -ForegroundColor "black"  -BackgroundColor "green" 

    powercfg /change standby-timeout-ac 0 # Sur alimentation
    powercfg /change standby-timeout-dc 0 # Sur Batterie

    Start-Sleep -Seconds 5  

    Write-Host -Object " Reglage Veille TERMINER " -ForegroundColor "White"  -BackgroundColor "red"

#=============================================================================================
# Reglage du chiffrage des disques

    $BitlockerS = Get-BitLockerVolume

    ForEach ($Bitlocker in $BitlockerS) {

        $BitlockerStatus = $Bitlocker.VolumeStatus
        $BitLockerMountpoint = $Bitlocker.Mountpoint

        Write-Host -Object " Le disque $BitLockerMountpoint est $BitlockerStatus " -ForegroundColor "black"  -BackgroundColor "green"

            If ($BitlockerStatus -like "FullyDecrypted" ){

                Write-Host -Object " Pas d'action requise sur le disque $BitLockerMountpoint TERMINER " -ForegroundColor "White"  -BackgroundColor "red"

            }

            If ($BitlockerStatus -like "FullyEncrypted" -or $BitlockerStatus -like "EncryptionInProgress"){

                new-item -type Directory -name "KeyProtector_Bitlocker" -Path "C:\" -ErrorAction Silentlycontinue

                Write-Host -Object " Recuperation des cles de chiffrement bitlocker du volume $BitLockerMountpoint " -ForegroundColor "black"  -BackgroundColor "green"

                $Lecteur = $BitLockerMountpoint.substring(0,$BitLockerMountpoint.Length-1)

                manage-bde -protectors -get $BitLockerMountpoint > C:\KeyProtector_Bitlocker\Recovery_Key_Volume_$Lecteur.txt

                Write-Host -Object " Cle sauvegarde dans C:\KeyProtector_Bitlocker\Recovery_Key_Volume_$Lecteur.txt TERMINER " -ForegroundColor "White"  -BackgroundColor "red"

                Write-Host -Object " Le disk $BitLockerMountpoint est chiffre via Bitlocker voulez vous le dechiffrer (O / N) " -ForegroundColor "black"  -BackgroundColor "green"
                $ChoixBitlocker = read-host

                    If ($ChoixBitlocker -like "O"){

                    Write-Host -Object " Dechiffrage du disque $BitLockerMountpoint en cours " -ForegroundColor "black"  -BackgroundColor "green"

                    Clear-BitLockerAutoUnlock
                    Disable-BitLocker -mountpoint $BitLockerMountpoint

                    Write-Host -Object " Le dechiffrement est en cours vous pouvez continuer a utiliser l'ordinateur TERMINER " -ForegroundColor "White"  -BackgroundColor "red"

                    }else{}
            }
    }
#=============================================================================================
# CHOLOLATEY AdobeReader Googlechrome Firefox

    Write-Host -Object " AdobeAcrobatReader et Google Chrome " -ForegroundColor "black"  -BackgroundColor "green"

    # Installation de Chocolatey

        Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

    # Lance l'installation de AdobeReader Googlechrome et firefox en mode Silentieux

        choco install adobereader googlechrome -y 

        Write-Host -Object " AdobeAcrobatReader et Google Chrome TERMINER " -ForegroundColor "black"  -BackgroundColor "green"

#=============================================================================================
# Declaration des variables utiles

    $Location = "C:\Deploy\Data"  
    $Info = "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" 

#=============================================================================================
#Creation de la fonction New-Shortcut

    Function New-Shortcut{

        param(
            [parameter(Mandatory=$true)][string]$ShortcutFullName,
            [parameter(Mandatory=$true)][string]$ShortcutTarget
            )

        $ShortcutObject = New-Object -comObject WScript.Shell
        $Shortcut = $ShortcutObject.CreateShortcut($ShortcutFullName)
        $Shortcut.TargetPath = $ShortcutTarget
        $Shortcut.Save()

    }

#=============================================================================================
#Installation des Supports

    #DellCommandUpdate

        If ($Fab -like "Dell Inc."){ 

            Write-Host -Object " DellCommandUpdate " -ForegroundColor "black"  -BackgroundColor "green"
            Set-Location $Location
            Start-Process DellCommandUpdate.exe /s

            Wait-Process "*DellCommandUpdate*"

            Start-Process "C:\Program Files (x86)\Dell\CommandUpdate\DellCommandUpdate.exe"
            Write-Host -Object " DellCommandUpdate TERMINER " -ForegroundColor "black"  -BackgroundColor "green"

        }

    #Hp Support Assistant

        If ($Fab -like "HP" -or $Fab -like "Hewlett-Packard"){

            Write-Host -Object " HP Support Assistant " -ForegroundColor "black"  -BackgroundColor "green"
            Set-Location $Location
            Start-Process sp138267.exe /s

            Wait-Process "*sp138267*"
            Write-Host -Object " HP Support Assistant TERMINER " -ForegroundColor "black"  -BackgroundColor "green"
        }

#=============================================================================================
# Partie PRO

    If ($choix -like "PRO"){

        Write-Host -Object " Parametrage PRO " -ForegroundColor "black"  -BackgroundColor "green"

        # Installation go to assist

            # Cmd qui creer un nouvel objet dans C:\Program Files de type dossier qui a pour nom GoToAssist

                New-item  -Path "C:\Program Files" -type Directory -Name "GoToAssist" 

            # Copie de l'objet GoToAssist.exe situe dans C:\Deploy\ dans C:\Program Files\GoToAssist\

                Copy-item -Path "C:\Deploy\Data\GoToAssist.exe" -Destination "C:\Program Files\GoToAssist\" 

            # Creation d'un nouveau raccourci sur le bureau de l'utilisateur actif

                New-Shortcut -ShortcutFullName "C:\Users\$Env:USERNAME\Desktop\GoToAssist.lnk" -ShortcutTarget "C:\Program Files\GoToAssist\GoToAssist.exe" 

            # Creation d'un nouveau raccourci dans le menu demarrer

                New-Shortcut -ShortcutFullName "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\GoToAssist.lnk" -ShortcutTarget "C:\Program Files\GoToAssist\GoToAssist.exe" 
                Write-Host -Object " GoToAssist TERMINER " -ForegroundColor "black"  -BackgroundColor "green"

        #=============================================================================================

            # Creation des cles de registre des informations de contact

                # Efface le contenu de la variable $ERROR

                    $error.Clear()

                # Nouvelle cle de registre (provoque une erreur si deja existant)

                    New-ItemProperty -Path $Info -name "Manufacturer" -value "KOESIO AQUITAINE"

                # Si $Error n'est pas vide alors on modIfie la cle de registre au lieu de la creer

                    If ($Error -notlike $Null){
                        Set-ItemProperty -Path $Info -name "Manufacturer" -value "KOESIO AQUITAINE"
                    }

                # Ajout des nouvelles cles de registre 

                    New-ItemProperty -Path $Info -name "SupportHours" -value "08H30 - 12H30 | 14H00 - 17H30"
                    New-ItemProperty -Path $Info -name "SupportPhone" -value "05 57 51 52 52 - 1A Avenue Bernard Moitessier, 17180 Périgny - www.koesio.com/"

                # Efface le contenu de la variable $ERROR

                    $error.Clear()

                # Nouvelle cle de registre (provoque une erreur si deja existant)

                    New-ItemProperty -Path $Info -name "SupportURL" -value "www.koesio.com"

                # Si $Error n'est pas vide alors on modIfie la cle de registre au lieux de la creer 

                    If ($Error -notlike $Null){
                        Set-ItemProperty -Path $Info -name "SupportURL" -value "www.koesio.com"
                    }

                Write-Host -Object " Cles de registre TERMINER " -ForegroundColor "black"  -BackgroundColor "green"

       
        #=============================================================================================
        # Execution de Ninite_PRO.exe

            Set-Location -Path $Location
            Start-Process Ninite_pro.exe
            Wait-Process -Name "Ninite*"
            Write-Host -Object " Ninite TERMINER " -ForegroundColor "black"  -BackgroundColor "green" 

        #=============================================================================================
            Write-Host -Object " Parametrage PRO TERMINER " -ForegroundColor "black"  -BackgroundColor "green"
    }
#=============================================================================================
# Partie PART

    If ($choix -like "PART"){

            Write-Host -Object " Parametrage PART " -ForegroundColor "black"  -BackgroundColor "green"
        #=============================================================================================
        # Installation Firefox

            choco install firefox -y
            Write-Host -Object " Firefox TERMINER " -ForegroundColor "black"  -BackgroundColor "green"

        #=============================================================================================
        # Execution de Ninite_PART.exe

            Set-Location -Path $Location
            Start-Process Ninite_part.exe
            Wait-Process -Name "Ninite*"
            Write-Host -Object " Ninite TERMINER " -ForegroundColor "black"  -BackgroundColor "green"

        #=============================================================================================
        # Verification de l'instalation de vlc

            $VLC = test-path -path "C:\Program Files\VideoLAN\VLC"

            If ($VLC -like "False"){

                Set-Location -Path "C:\Users\Utilisateur\Desktop\Script\Deploy\Data"#$Location
                msiexec /quiet /norestart /i vlc.msi
                Write-Host -Object " Installation de VLC avec le pakage locale TERMINER " -ForegroundColor "black"  -BackgroundColor "green"

            }

            Write-Host -Object " Parametrage PART TERMINER " -ForegroundColor "black"  -BackgroundColor "green"
    }

#=============================================================================================
# Raccourci Adobe Acrobat Reader sur le bureau

    New-Shortcut -ShortcutFullName "C:\Users\$Env:USERNAME\Desktop\AcrobatReader.lnk" -ShortcutTarget "C:\Program Files (x86)\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe" 
    Write-Host -Object " Creation de l icone d Adobe Acrobat Reader TERMINER " -ForegroundColor "black"  -BackgroundColor "green" 

#=============================================================================================
#Creation d'une tache planifier a l ouverture de session

Copy-Item -Path "C:\Deploy\bin\Remove.bat" -Destination "C:\"

SCHTASKS /Create /TN "RemovePrep" /SC ONLOGON /TR "C:\Remove.bat"  /RL HIGHEST

# Installation du module mises a jour en ligne de commande 
    
    Write-Host -Object " MISE A JOUR WINDOWS " -ForegroundColor "black"  -BackgroundColor "green"
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Start-Sleep -Seconds 15
    Install-Module PSWindowsUpdate -force 
    Start-Sleep -Seconds 15  

# Installation des mises a jour

    Install-WindowsUpdate -ForceDownload -ForceInstall -AcceptAll -AutoReboot

#=============================================================================================
