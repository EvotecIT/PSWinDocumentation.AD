function Get-WinADForestInformation {
    [CmdletBinding()]
    param (
        [PSWinDocumentation.ActiveDirectory[]] $TypesRequired,
        [switch] $RequireTypes,
        [string] $PathToPasswords,
        [string] $PathToPasswordsHashes,
        [switch] $PasswordQuality,
        [switch] $DontRemoveSupportData,
        [switch] $DontRemoveEmpty,
        [switch] $Formatted,
        [string] $Splitter,
        [switch] $Parallel,
        [switch] $Extended,
        [int] $ResultPageSize = 500000
    )
    $PSDefaultParameterValues["Get-DataInformation:Verbose"] = $PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent

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
        Write-Warning "Getting forest information - Failed to get information. This may mean that RSAT is not available or you can't connect to Active Directory."
        return
    }
    # Start of building data
    $Data = [ordered] @{ }

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
        Get-WinADForestSchemaProperties -Schema 'Computers'
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
        [PSWinDocumentation.ActiveDirectory]::ForestOptionalFeatures
    )
    $Data.ForestSchemaPropertiesUsers = Get-DataInformation -Text "Getting forest information - ForestSchemaPropertiesUsers" {
        Get-WinADForestSchemaProperties -Schema 'Users'
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::ForestSchemaPropertiesUsers
        [PSWinDocumentation.ActiveDirectory]::DomainUsersFullList
    )


    ## Forest Information
    $Data.ForestUPNSuffixes = Get-DataInformation -Text 'Getting forest information - ForestUPNSuffixes' {
        Get-WinADForestUPNSuffixes -Forest $Forest
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::ForestUPNSuffixes
    )

    $Data.ForestSPNSuffixes = Get-DataInformation -Text 'Getting forest information - ForestSPNSuffixes' {
        Get-WinADForestSPNSuffixes -Forest $Forest
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::ForestSPNSuffixes
    )

    # Forest DC GC - Review if required
    $Data.ForestGlobalCatalogs = Get-DataInformation -Text 'Getting forest information - ForestGlobalCatalogs' {
        $Forest.GlobalCatalogs
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::ForestGlobalCatalogs
    )

    $Data.ForestFSMO = Get-DataInformation -Text 'Getting forest information - ForestFSMO' {
        Get-WinADForestFSMO -Forest $Forest
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::ForestFSMO
    )

    $Data.ForestDomainControllers = Get-DataInformation -Text 'Getting forest information - ForestDomainControllers' {
        # External command from PSSharedGoods
        Get-WinADForestControllers
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::ForestDomainControllers
    )

    # Forest Sites
    $Data.ForestSites = Get-DataInformation -Text 'Getting forest information - ForestSites' {
        Get-WinADForestSites -Formatted:$Formatted -Splitter $Splitter
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::ForestSites
        [PSWinDocumentation.ActiveDirectory]::ForestSites1
        [PSWinDocumentation.ActiveDirectory]::ForestSites2
    )
    $Data.ForestSites1 = Get-DataInformation -Text 'Getting forest information - ForestSites1' {
        if ($Formatted) {
            $Data.ForestSites | Select-Object -Property Name, Description, Protected, 'Subnets Count', 'Domain Controllers Count', Modified
        } else {
            $Data.ForestSites | Select-Object -Property Name, Description, Protected, 'SubnetsCount', 'DomainControllersCount', Modified
        }
        #Get-WinADForestSites1 -ForestSites $Data.ForestSites
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::ForestSites1
    )
    $Data.ForestSites2 = Get-DataInformation -Text 'Getting forest information - ForestSites2' {
        if ($Formatted) {
            $Data.ForestSites | Select-Object -Property 'Topology Cleanup Enabled', 'Topology DetectStale Enabled', 'Topology MinimumHops Enabled', 'Universal Group Caching Enabled', 'Universal Group Caching Refresh Site'
        } else {
            $Data.ForestSites | Select-Object -Property TopologyCleanupEnabled, TopologyDetectStaleEnabled, TopologyMinimumHopsEnabled, UniversalGroupCachingEnabled, UniversalGroupCachingRefreshSite
        }
        #Get-WinADForestSites2 -ForestSites $Data.ForestSites
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::ForestSites2
    )

    ## Forest Subnets
    $Data.ForestSubnets = Get-DataInformation -Text 'Getting forest information - ForestSubnets' {
        Get-WinADForestSubnets
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::ForestSubnets
        [PSWinDocumentation.ActiveDirectory]::ForestSubnets1
        [PSWinDocumentation.ActiveDirectory]::ForestSubnets2
    )
    $Data.ForestSubnets1 = Get-DataInformation -Text 'Getting forest information - ForestSubnets1' {
        Get-WinADForestSubnets1 -ForestSubnets $Data.ForestSubnets
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::ForestSubnets1
    )
    $Data.ForestSubnets2 = Get-DataInformation -Text 'Getting forest information - ForestSubnets2' {
        Get-WinADForestSubnets2 -ForestSubnets $Data.ForestSubnets
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::ForestSubnets2
    )

    ## Forest Site Links
    $Data.ForestSiteLinks = Get-DataInformation -Text 'Getting forest information - ForestSiteLinks' {
        Get-WinADForestSiteLinks
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::ForestSiteLinks
    )

    ## Forest Optional Features
    $Data.ForestOptionalFeatures = Get-DataInformation -Text 'Getting forest information - ForestOptionalFeatures' {
        Get-WinADForestOptionalFeatures -ComputerProperties $ForestSchemaPropertiesComputers
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::ForestOptionalFeatures
    )

    $Data.ForestReplication = Get-DataInformation -Text 'Getting forest information - ForestReplication' {
        Get-WinADForestReplication -Extended:$Extended
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::ForestReplication
    )

    $EndTimeForest = Stop-TimeLog -Time $TimeToGenerateForest -Continue

    $Data.FoundDomains = Get-DataInformation -Text 'Getting forest information - Domains' {
        ### Generate Data from Domains
        $FoundDomains = @{ }
        foreach ($Domain in $Forest.Domains) {
            $FoundDomains.$Domain = Get-WinADDomainInformation -Domain $Domain `
                -TypesRequired $TypesRequired `
                -PathToPasswords $PathToPasswords `
                -PathToPasswordsHashes $PathToPasswordsHashes `
                -ForestSchemaComputers $Data.ForestSchemaPropertiesComputers  `
                -ForestSchemaUsers $Data.ForestSchemaPropertiesUsers -PasswordQuality:$PasswordQuality.IsPresent -Splitter $Splitter -Parallel:$Parallel.IsPresent -ResultPageSize $ResultPageSize -Formatted:$formatted.IsPresent
        }
        $FoundDomains
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory].GetEnumValues() | Where-Object { $_ -like 'Domain*' }
    )

    $EndTimeAll = Stop-TimeLog -Time $TimeToGenerateForest
    # cleans up empty fields created during gathering process
    Clear-DataInformation -Data $Data -TypesRequired $TypesRequired -DontRemoveSupportData:$DontRemoveSupportData -DontRemoveEmpty:$DontRemoveEmpty

    # final output
    Write-Verbose "Getting forest information - Stop - Time to generate: $EndTimeForest"
    Write-Verbose "Getting all information - Stop - Time to generate: $EndTimeAll"
    return $Data
}
