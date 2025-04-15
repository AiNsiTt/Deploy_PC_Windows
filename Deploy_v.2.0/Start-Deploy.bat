@echo off
REM Lance le script PowerShell principal avec les droits admin et bypass de la policy pour ce processus.
REM Doit être exécuté en tant qu'administrateur.

REM Trouve le répertoire où se trouve ce batch
set SCRIPTDIR=%~dp0

REM Lance PowerShell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& { Start-Process powershell.exe -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File ""%SCRIPTDIR%Deploy.ps1""' -Verb RunAs}"

echo Script PowerShell lancé dans une nouvelle fenêtre administrateur...
pause
exit /b
