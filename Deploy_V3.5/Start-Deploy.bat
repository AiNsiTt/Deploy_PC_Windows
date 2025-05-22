@echo off
REM Lance le script PowerShell principal avec les droits admin et bypass de la policy.
REM Doit être exécuté en tant qu'administrateur. V3.6 (Correction erreur '{' non reconnu)

REM Trouve le répertoire où se trouve ce batch
SET ThisScriptsDirectory=%~dp0
SET PowerShellScriptPath=%ThisScriptsDirectory%Deploy.ps1

REM Lance PowerShell en lui demandant de démarrer un nouveau processus PowerShell élevé qui exécutera le script .ps1
REM Méthode robuste pour éviter l'erreur d'interprétation CMD.
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "& {Start-Process PowerShell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File ""%PowerShellScriptPath%""' -Verb RunAs}"

echo Script PowerShell lancé dans une nouvelle fenêtre administrateur...
exit /b
