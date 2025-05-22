@echo off
REM Lance le script PowerShell principal avec les droits admin et bypass de la policy.
REM Doit être exécuté en tant qu'administrateur. V4.1
REM Auteur: Quentin Chaillou // Quentin.Chaillou@koesio.fr

echo Tentative de lancement du script de déploiement PowerShell...
echo Une fenêtre de Contrôle de Compte d'Utilisateur (UAC) peut apparaître pour demander les droits admin.

REM Trouve le répertoire où se trouve ce batch
SET "ThisScriptsDirectory=%~dp0"
REM Assure que le chemin se termine par un backslash pour Join-Path implicite
IF NOT "%ThisScriptsDirectory:~-1%"=="\" SET "ThisScriptsDirectory=%ThisScriptsDirectory%\"
SET "PowerShellScriptPath=%ThisScriptsDirectory%Deploy.ps1"

REM Vérifie si le script PS1 existe
IF NOT EXIST "%PowerShellScriptPath%" (
    echo ERREUR: Le fichier Deploy.ps1 n'a pas été trouvé dans le même répertoire que ce batch.
    echo Chemin cherché: %PowerShellScriptPath%
    pause
    exit /b 1
)

REM Lance PowerShell en lui demandant de démarrer un nouveau processus PowerShell élevé qui exécutera le script .ps1
REM Méthode robuste pour éviter l'erreur d'interprétation CMD et gérer les chemins avec espaces.
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "& {Start-Process PowerShell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"%PowerShellScriptPath%\"' -Verb RunAs}"

REM Vérifie le code de sortie de la commande PowerShell précédente
IF %ERRORLEVEL% NEQ 0 (
    echo ERREUR: La commande PowerShell n'a pas pu démarrer le processus élevé. Vérifiez les droits ou les erreurs UAC.
    pause
    exit /b %ERRORLEVEL%
) ELSE (
    echo Script PowerShell lancé dans une nouvelle fenêtre administrateur... Cette fenêtre va se fermer.
)

REM Petite pause pour laisser l'utilisateur lire le message avant fermeture auto éventuelle
timeout /t 3 /nobreak > nul

exit /b 0