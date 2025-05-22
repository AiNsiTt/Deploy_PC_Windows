@echo off
REM Lance le script orchestrateur PowerShell DSC avec droits admin et bypass.
REM Doit être exécuté par un utilisateur pouvant obtenir les droits administrateur. V5.0
REM Auteur: Quentin Chaillou // Quentin.Chaillou@koesio.fr

echo Tentative de lancement du script de deploiement Koesio (via DSC)...
echo.
echo Une fenetre de Controle de Compte d'Utilisateur peut apparaitre.
echo Veuillez confirmer l'elevation des droits administrateur.
echo.

REM Trouve le repertoire où se trouve ce batch
SET "ThisScriptsDirectory=%~dp0"
REM Assure que le chemin se termine par un backslash pour PowerShell
IF NOT "%ThisScriptsDirectory:~-1%"=="\" SET "ThisScriptsDirectory=%ThisScriptsDirectory%\"
SET "PowerShellScriptPath=%ThisScriptsDirectory%Deploy-Machine.ps1"

REM Verifie si le script PS1 principal existe
IF NOT EXIST "%PowerShellScriptPath%" (
    echo ERREUR: Le fichier Deploy-Machine.ps1 n'a pas ete trouve dans :
    echo %ThisScriptsDirectory%
    echo.
    pause
    exit /b 1
)

REM Verifie si le fichier de Configuration DSC existe (dependance critique)
IF NOT EXIST "%ThisScriptsDirectory%MachineConfiguration.ps1" (
    echo ERREUR: Le fichier MachineConfiguration.ps1 n'a pas ete trouve dans :
    echo %ThisScriptsDirectory%
    echo Il est requis pour le fonctionnement de Deploy-Machine.ps1.
    echo.
    pause
    exit /b 1
)


REM Lance PowerShell en lui demandant de démarrer un nouveau processus PowerShell élevé
REM qui exécutera le script orchestrateur .ps1. Gère les chemins avec espaces.
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "& {Start-Process PowerShell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"%PowerShellScriptPath%\"' -Verb RunAs}"

REM Verifie le code de sortie de la commande PowerShell
IF %ERRORLEVEL% NEQ 0 (
    echo ERREUR: La commande PowerShell n'a pas pu démarrer le processus eleve (code %ERRORLEVEL%).
    echo Verifiez les droits, l'UAC ou une erreur potentielle dans le script de base PowerShell.
    echo.
    pause
    exit /b %ERRORLEVEL%
) ELSE (
    echo Script PowerShell (Deploy-Machine.ps1) lance dans une nouvelle fenetre administrateur...
    echo Cette fenetre va se fermer dans quelques secondes.
)

REM Petite pause pour lire le message avant fermeture
timeout /t 5 /nobreak > nul

exit /b 0