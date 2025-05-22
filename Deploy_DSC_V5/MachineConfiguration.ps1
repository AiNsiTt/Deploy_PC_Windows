#Requires -Modules PSDesiredStateConfiguration
#Requires -Modules ComputerManagementDsc # Toujours nécessaire pour la ressource 'Computer' (renommage)
#Requires -Modules cChoco

Configuration MachineConfiguration
{
    # Paramètres requis pour la configuration de base et l'installation de logiciels
    param
    (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName, # Nom cible de la machine (utilisé pour le renommage et l'identification du nœud)

        [Parameter(Mandatory=$false)] # Peut être un tableau vide
        [string[]]$OptionalChocoPackages = @(),

        [Parameter(Mandatory=$false)] # Peut être un tableau vide
        [string[]]$CoreChocoPackages = @(),

        [Parameter(Mandatory=$false)] # Peut être un tableau vide
        [string[]]$WindowsFeaturesToEnsure = @(),

        [Parameter(Mandatory=$false)]
        [bool]$RebootNodeIfNeeded = $true # Contrôle le redémarrage via LCM
    )

    # Importer les ressources DSC nécessaires
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'ComputerManagementDsc'
    Import-DscResource -ModuleName 'cChoco' # Assurez-vous que ce module est bien installé sur le nœud cible ou transféré

    # Configuration pour le nœud spécifié par $ComputerName
    Node $ComputerName
    {
        #------------------------------------------------------
        # Gestion du Nom de l'Ordinateur (Uniquement)
        #------------------------------------------------------

        # S'assure que l'ordinateur a le nom désiré.
        # La jonction au domaine a été retirée de cette configuration.
        Computer 'ComputerNameOnly' # Nom de ressource ajusté
        {
            Name = $ComputerName # Applique le nom désiré
            # Les propriétés DomainName, Credential, JoinOU ont été supprimées
            # La ressource gère le renommage et le redémarrage potentiel associé.
        }

        #------------------------------------------------------
        # Installation des Fonctionnalités Windows
        #------------------------------------------------------
        if ($WindowsFeaturesToEnsure) {
            foreach ($featureName in $WindowsFeaturesToEnsure) {
                WindowsFeature "InstallFeature_$($featureName -replace '[^a-zA-Z0-9]','_')"
                {
                    Ensure    = 'Present'
                    Name      = $featureName
                    DependsOn = '[Computer]ComputerNameOnly' # Dépend toujours du renommage potentiel
                }
            }
        }

        #------------------------------------------------------
        # Installation de Chocolatey (si nécessaire)
        # Doit être présent implicitement ou explicitement avant les packages
        # (Note: cChocoPackageInstaller inclut une dépendance implicite sur l'installation de Choco)
        # Si vous avez besoin de forcer l'installation ou des options spécifiques :
        # cChocoInstaller 'InstallChoco'
        # {
        #     InstallDir = 'C:\ProgramData\chocolatey'
        # }
        # Il faut alors ajouter DependsOn = '[cChocoInstaller]InstallChoco' aux ressources cChocoPackageInstaller
        # Pour simplifier, on suppose que cChocoPackageInstaller gère l'installation si absent.
        #------------------------------------------------------

        #------------------------------------------------------
        # Installation des Packages Chocolatey (Core)
        #------------------------------------------------------
        if ($CoreChocoPackages) {
            foreach ($corePkgName in $CoreChocoPackages) {
                $resourceName = "InstallCoreChoco_$($corePkgName -replace '[^a-zA-Z0-9]','_')"
                cChocoPackageInstaller $resourceName
                {
                    Ensure = 'Present'
                    Name   = $corePkgName
                    # DependsOn = '[cChocoInstaller]InstallChoco' # Ajouter si InstallChoco est explicite
                }
            }
        }

        #------------------------------------------------------
        # Installation des Packages Chocolatey (Optionnels)
        #------------------------------------------------------
        if ($OptionalChocoPackages) {
            foreach ($optionalPkgName in $OptionalChocoPackages) {
                $resourceName = "InstallOptionalChoco_$($optionalPkgName -replace '[^a-zA-Z0-9]','_')"
                cChocoPackageInstaller $resourceName
                {
                    Ensure = 'Present'
                    Name   = $optionalPkgName
                    # DependsOn = '[cChocoInstaller]InstallChoco' # Ajouter si InstallChoco est explicite
                }
            }
        }

        #------------------------------------------------------
        # Configuration du Local Configuration Manager (LCM)
        #------------------------------------------------------
        LocalConfigurationManager
        {
            RebootNodeIfNeeded = $RebootNodeIfNeeded
            ConfigurationMode = 'ApplyAndAutoCorrect'
            ActionAfterReboot = 'ContinueConfiguration'
            ConfigurationModeFrequencyMins = 15
            AllowModuleOverWrite = $true
        }
    } # Fin Node
} # Fin Configuration