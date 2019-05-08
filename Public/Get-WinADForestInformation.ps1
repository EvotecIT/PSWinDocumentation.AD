function Get-WinADForestInformation {
    [CmdletBinding()]
    param (
        [PSWinDocumentation.ActiveDirectory[]] $TypesRequired,
        [switch] $RequireTypes,
        [string] $PathToPasswords,
        [string] $PathToPasswordsHashes,
        [switch] $PasswordQuality
    )

    Write-Verbose -Message "Getting all information - Start"
    Write-Verbose -Message "Getting forest information - Start"
    $TimeToGenerateForest = Start-TimeLog
    if ($null -eq $TypesRequired) {
        # Gets all types
        Write-Verbose 'Getting forest information - TypesRequired is null. Getting all.'
        $TypesRequired = Get-Types -Types ([PSWinDocumentation.ActiveDirectory])
    }

    # Forest is required to get all domains
    $Forest = Get-WinADForest
    if ($null -eq $Forest) {
        Write-Warning "Getting forest information - Failed to get information."
        return
    }


    # Start of building data
    $Data = [ordered] @{}

    $Data.ForestRootDSE = Get-DataInformation -Text 'Getting forest information - ForestRootDSE' {
        Get-WinADRootDSE
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::ForestRootDSE
        [PSWinDocumentation.ActiveDirectory]::ForestInformation
    )

    $Data.ForestInformation = Get-DataInformation -Text 'Getting forest information - Forest' {
        Get-WinADForestInfo -Forest $Forest -RootDSE $Data.ForestRootDSE
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::ForestInformation
    )

    # This is Forest Schema Properties for Users and Computers
    $Data.ForestSchemaPropertiesComputers = Get-DataInformation -Text "Getting forest information - ForestSchemaPropertiesComputers" {
        Get-WinADForestSchemaPropertiesComputers
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::ForestSchemaPropertiesComputers
        [PSWinDocumentation.ActiveDirectory]::DomainComputersFullList
        [PSWinDocumentation.ActiveDirectory]::DomainComputersAll
        [PSWinDocumentation.ActiveDirectory]::DomainComputersAllCount
        [PSWinDocumentation.ActiveDirectory]::DomainServers
        [PSWinDocumentation.ActiveDirectory]::DomainServersCount
        [PSWinDocumentation.ActiveDirectory]::DomainComputers
        [PSWinDocumentation.ActiveDirectory]::DomainComputersCount
        [PSWinDocumentation.ActiveDirectory]::DomainComputersUnknown
        [PSWinDocumentation.ActiveDirectory]::DomainComputersUnknownCount
        [PSWinDocumentation.ActiveDirectory]::DomainBitlocker
        [PSWinDocumentation.ActiveDirectory]::DomainLAPS
    )
    $Data.ForestSchemaPropertiesUsers = Get-DataInformation -Text "Getting forest information - ForestSchemaPropertiesUsers" {
        Get-WinADForestSchemaPropertiesUsers
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::ForestSchemaPropertiesUsers
        [PSWinDocumentation.ActiveDirectory]::DomainUsersFullList
    )
    ## Forest Information
    $Data.ForestUPNSuffixes = Get-DataInformation -Text 'Getting forest information - Forest UPNSuffixes' {
        Get-WinADForestUPNSuffixes -Forest $Data.Forest
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::ForestUPNSuffixes
    )

    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::ForestGlobalCatalogs)) {
        Write-Verbose 'Getting forest information - Forest GlobalCatalogs'
        $Data.ForestGlobalCatalogs = $Data.Forest.GlobalCatalogs
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::ForestSPNSuffixes)) {
        Write-Verbose 'Getting forest information - Forest SPNSuffixes'
        $Data.ForestSPNSuffixes = $Data.Forest.SPNSuffixes
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::ForestFSMO)) {
        Write-Verbose 'Getting forest information - Forest FSMO'
        $Data.ForestFSMO = [ordered] @{
            'Domain Naming Master' = $Data.Forest.DomainNamingMaster
            'Schema Master'        = $Data.Forest.SchemaMaster
        }
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::ForestDomainControllers)) {
        # External command from PSSharedGoods
        $Data.ForestDomainControllers = Get-WinADForestControllers
    }
    # Forest Sites
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::ForestSites, [PSWinDocumentation.ActiveDirectory]::ForestSites1, [PSWinDocumentation.ActiveDirectory]::ForestSites2)) {
        Write-Verbose 'Getting forest information - Forest Sites'
        $Data.ForestSites = Get-WinADForestSites
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::ForestSites1)) {
        Write-Verbose 'Getting forest information - Forest Sites1'
        $Data.ForestSites1 = Get-WinADForestSites1 -ForestSites $Data.ForestSites
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::ForestSites2)) {
        Write-Verbose 'Getting forest information - Forest Sites2'
        $Data.ForestSites2 = Get-WinADForestSites2 -ForestSites $Data.ForestSites
    }
    ## Forest Subnets
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::ForestSubnet , [PSWinDocumentation.ActiveDirectory]::ForestSubnets1, [PSWinDocumentation.ActiveDirectory]::ForestSubnets2)) {
        Write-Verbose 'Getting forest information - Forest Subnets'
        $Data.ForestSubnets = Get-WinADForestSubnets
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::ForestSubnets1)) {
        Write-Verbose 'Getting forest information - Forest Subnets1'
        $Data.ForestSubnets1 = Get-WinADForestSubnets1 -ForestSubnets $Data.ForestSubnets
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::ForestSubnets2)) {
        Write-Verbose 'Getting forest information - Forest Subnets2'
        $Data.ForestSubnets2 = Get-WinADForestSubnets2 -ForestSubnets $Data.ForestSubnets
    }
    ## Forest Site Links
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::ForestSiteLinks)) {
        Write-Verbose 'Getting forest information - Forest SiteLinks'
        $Data.ForestSiteLinks = Get-WinADForestSiteLinks
    }
    ## Forest Optional Features
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::ForestOptionalFeatures)) {
        Write-Verbose 'Getting forest information - Forest Optional Features'
        $Data.ForestOptionalFeatures = Get-WinADForestOptionalFeatures
    }
    $EndTimeForest = Stop-TimeLog -Time $TimeToGenerateForest -Continue


    ### Generate Data from Domains
    $Data.FoundDomains = [ordered]@{}
    foreach ($Domain in $Forest.Domains) {
        $Data.FoundDomains.$Domain = Get-WinADDomainInformation -Domain $Domain `
            -TypesRequired $TypesRequired `
            -PathToPasswords $PathToPasswords `
            -PathToPasswordsHashes $PathToPasswordsHashes `
            -ForestSchemaComputers $Data.ForestSchemaPropertiesComputers  `
            -ForestSchemaUsers $Data.ForestSchemaPropertiesUsers -PasswordQuality:$PasswordQuality
    }
    $EndTimeAll = Stop-TimeLog -Time $TimeToGenerateForest

    # cleans up empty fields created during gathering process
    Clear-DataInformation -Data $Data

    Write-Verbose "Getting forest information - Stop - Time to generate: $EndTimeForest"
    Write-Verbose "Getting all information - Stop - Time to generate: $EndTimeAll"

    return $Data
}
