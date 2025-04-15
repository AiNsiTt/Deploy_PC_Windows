rmdir /s /q C:\Deploy
rmdir /s /q C:\Users\Utilisateur\Documents\WindowsPowerShell

Schtasks /delete /TN RemovePrep /f

IF EXIST "C:\Program Files (x86)\Dell\CommandUpdate\DellCommandUpdate.exe" "C:\Program Files (x86)\Dell\CommandUpdate\DellCommandUpdate.exe"

Control Update 

Erase C:\Remove.bat
