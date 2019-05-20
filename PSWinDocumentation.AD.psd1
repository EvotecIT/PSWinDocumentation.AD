@{
    Copyright = 'Evotec (c) 2011-2019. All rights reserved.'
    PrivateData = @{
        PSData = @{
            Tags = 'Windows', 'ActiveDirectory', 'ad'
            ProjectUri = 'https://github.com/EvotecIT/PSWinDocumentation.AD'
            IconUri = 'https://evotec.xyz/wp-content/uploads/2018/10/PSWinDocumentation.png'
            Prerelease = 'Preview2'
        }
    }
    Description = 'Dataset covering Active Directory'
    PowerShellVersion = '5.1'
    FunctionsToExport = 'Get-WinADDomainInformation', 'Get-WinADForestInformation'
    Author = 'Przemyslaw Klys'
    RequiredModules = @{
        ModuleVersion = '0.0.77'
        ModuleName = 'PSSharedGoods'
        GUID = 'ee272aa8-baaa-4edf-9f45-b6d6f7d844fe'
    }, @{
        ModuleVersion = '3.4'
        ModuleName = 'DSInternals'
        GUID = '766b3ad8-eb78-48e6-84bd-61b31d96b53e'
    }
    GUID = 'a46f9775-04d2-4423-9631-01cfda42b95d'
    RootModule = 'PSWinDocumentation.AD.psm1'
    AliasesToExport = ''
    ModuleVersion = '0.0.8'
    ScriptsToProcess = 'Enums\ActiveDirectory.ps1'
    CompanyName = 'Evotec'
}