function Get-WinADForestInformation {
    [CmdletBinding()]
    param (
        [PSWinDocumentation.ActiveDirectory[]] $TypesRequired,
        [switch] $RequireTypes,
        [string] $PathToPasswords,
        [string] $PathToPasswordsHashes,
        [switch] $PasswordQuality
    )


    Write-Verbose "Get-WinADForestInformation - Getting information"
    $TimeToGenerateForest = Start-TimeLog
    if ($null -eq $TypesRequired) {
        # Gets all types
        Write-Verbose 'Get-WinADForestInformation - TypesRequired is null. Getting all.'
        $TypesRequired = Get-Types -Types ([PSWinDocumentation.ActiveDirectory])
    }

    $Forest = Get-WinADForest
    if ($null -eq $Forest) {
        Write-Warning "Get-WinADForestInformation - Failed to get information."
        return
    }

    # Start of building data
    $Data = [ordered] @{}
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::ForestRootDSE, [PSWinDocumentation.ActiveDirectory]::ForestInformation)) {
        $Data.RootDSE = Get-WinADRootDSE
    }
    # This is tempporary data that should be removed at some point
    #if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::ForestName)) {
    #    Write-Verbose 'Getting forest information - ForestName'
    #    $Data.ForestName = $Data.Forest.Name
    #}
    #if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::ForestNameDN)) {
    #   Write-Verbose 'Getting forest information - ForestNameDN'
    #    $Data.ForestNameDN = $Data.RootDSE.defaultNamingContext
    #}
    # This is utilized for FoundDomains property
    # if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::ForestRootDSE)) {
    #     Write-Verbose 'Getting forest information - Domains list'
    #     $Data.Domains = $Data.Forest.Domains
    # }
    # This is Forest Schema Properties for Users and Computers
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::ForestSchemaPropertiesComputers)) {
        $Data.ForestSchemaPropertiesComputers = Get-WinADForestSchemaPropertiesComputers
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::ForestSchemaPropertiesUsers)) {
        $Data.ForestSchemaPropertiesUsers = Get-WinADForestSchemaPropertiesUsers
    }
    ## Forest Information
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::ForestInformation)) {
        $Data.ForestInformation = Get-WinADForestInfo -Forest $Forest -RootDSE $Data.RootDSE
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::ForestUPNSuffixes)) {
        Write-Verbose 'Getting forest information - Forest UPNSuffixes'
        $Data.ForestUPNSuffixes = Get-WinADForestUPNSuffixes -Forest $Data.Forest
    }
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
    Write-Verbose "Getting forest information - Time to generate: $EndTimeForest"
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
    Write-Verbose "Getting all information - Time to generate: $EndTimeAll"
    return $Data
}
