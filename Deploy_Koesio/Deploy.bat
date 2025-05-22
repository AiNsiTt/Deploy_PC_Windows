@echo off
REM Script pour lancer KoesioPrep.ps1 en tant qu'administrateur

REM Obtient le chemin du dossier où se trouve ce fichier .bat
SET "SCRIPT_DIR=%~dp0"

REM Chemin complet vers le script PowerShell
SET "POWERSHELL_SCRIPT=%SCRIPT_DIR%KoesioPrep.ps1"

REM Vérifie si le script PowerShell existe
IF NOT EXIST "%POWERSHELL_SCRIPT%" (
    echo Erreur: Le script PowerShell "%POWERSHELL_SCRIPT%" est introuvable.
    pause
    exit /b 1
)

REM Lance PowerShell pour exécuter le script avec élévation de privilèges
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& {Start-Process PowerShell.exe -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File ""%POWERSHELL_SCRIPT%""' -Verb RunAs}"

REM Optionnel: petite pause pour voir les messages si PowerShell se ferme trop vite en cas d'erreur de lancement
REM timeout /t 5 /nobreak >nul