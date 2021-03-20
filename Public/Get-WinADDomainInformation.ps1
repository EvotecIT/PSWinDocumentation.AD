function Get-WinADDomainInformation {
    [CmdletBinding()]
    param (
        [string] $Domain,
        [PSWinDocumentation.ActiveDirectory[]] $TypesRequired,
        [string] $PathToPasswords,
        [string] $PathToPasswordsHashes,
        [switch] $Extended,
        [switch] $Formatted,
        [Array] $ForestSchemaComputers,
        [Array] $ForestSchemaUsers,
        [switch] $PasswordQuality,
        [alias('Joiner')][string] $Splitter,
        [switch] $Parallel,
        [int] $ResultPageSize = 500000
    )
    # temporary set here, will be moved to variables when all functions will support it
    $Formatted = $true
    $PSDefaultParameterValues["Get-DataInformation:Verbose"] = $PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent

    $Data = [ordered] @{ }

    if ($Domain -eq '') {
        Write-Warning 'Get-WinADDomainInformation - $Domain parameter is empty. Try your domain name like ad.evotec.xyz. Skipping for now...'
        return
    }
    if ($null -eq $TypesRequired) {
        Write-Verbose 'Get-WinADDomainInformation - TypesRequired is null. Getting all.'
        $TypesRequired = Get-Types -Types ([PSWinDocumentation.ActiveDirectory])
    } # Gets all types
    $TimeToGenerate = Start-TimeLog

    # this is required to make sure certain properties are used in domain, such as LAPS, EXCHANGE and so on.
    # this prevents errors of asking for wrong property - normally that would be provided by forest
    if ($null -eq $ForestSchemaComputers) {
        $ForestSchemaComputers = Get-DataInformation -Text "Getting domain information - ForestSchemaPropertiesComputers" {
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
        )
    }
    if ($null -eq $ForestSchemaUsers) {
        $ForestSchemaUsers = Get-DataInformation -Text "Getting domain information - ForestSchemaPropertiesUsers" {
            Get-WinADForestSchemaProperties -Schema 'Users'
        } -TypesRequired $TypesRequired -TypesNeeded @(
            [PSWinDocumentation.ActiveDirectory]::ForestSchemaPropertiesUsers
            [PSWinDocumentation.ActiveDirectory]::DomainUsersFullList
        )
    }

    # This is standard cache
    $Data.DomainObjects = @{ }
    # this is cache by netbios name such as EVOTEC\SamAccountName
    $Data.DomainObjectsNetBios = @{}

    # Domain Root DSE - Complete TypesNeeded
    $Data.DomainRootDSE = Get-DataInformation -Text "Getting domain information - $Domain DomainRootDSE" {
        Get-WinADRootDSE -Domain $Domain
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainRootDSE
        [PSWinDocumentation.ActiveDirectory]::DomainGUIDS
        [PSWinDocumentation.ActiveDirectory]::DomainOrganizationalUnitsBasicACL
        [PSWinDocumentation.ActiveDirectory]::DomainOrganizationalUnitsExtendedACL
    )

    $Data.DomainInformation = Get-DataInformation -Text "Getting domain information - $Domain DomainInformation" {
        Get-WinADDomain -Domain $Domain
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainInformation
        [PSWinDocumentation.ActiveDirectory]::DomainRIDs
        [PSWinDocumentation.ActiveDirectory]::DomainFSMO
        [PSWinDocumentation.ActiveDirectory]::DomainOrganizationalUnitsDN
        [PSWinDocumentation.ActiveDirectory]::DomainOrganizationalUnitsBasicACL
        [PSWinDocumentation.ActiveDirectory]::DomainOrganizationalUnitsExtendedACL
        [PSWinDocumentation.ActiveDirectory]::DomainAdministrators
        [PSWinDocumentation.ActiveDirectory]::DomainAdministratorsRecursive
        [PSWinDocumentation.ActiveDirectory]::DomainEnterpriseAdministrators
        [PSWinDocumentation.ActiveDirectory]::DomainEnterpriseAdministratorsRecursive
        [PSWinDocumentation.ActiveDirectory].GetEnumValues() | Where-Object { $_ -like 'DomainPassword*' }
        [PSWinDocumentation.ActiveDirectory]::DomainGroupsPriviliged
    )

    # Groups
    $Data.DomainGroupsFullList = Get-DataInformation -Text "Getting domain information - $Domain DomainGroupsFullList" {
        Get-WinADDomainGroupsFullList -Domain $Domain -DomainObjects $Data.DomainObjects -ResultPageSize $ResultPageSize
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainGroupsFullList
        [PSWinDocumentation.ActiveDirectory]::DomainUsers
        [PSWinDocumentation.ActiveDirectory]::DomainFineGrainedPoliciesUsers
        [PSWinDocumentation.ActiveDirectory]::DomainFineGrainedPoliciesUsersExtended
        [PSWinDocumentation.ActiveDirectory]::DomainGroups
        [PSWinDocumentation.ActiveDirectory]::DomainGroupsPriviliged
        [PSWinDocumentation.ActiveDirectory]::DomainGroupsMembers
        [PSWinDocumentation.ActiveDirectory]::DomainGroupsMembersRecursive
    )


    # Users
    $Data.DomainUsersFullList = Get-DataInformation -Text "Getting domain information - $Domain DomainUsersFullList" {
        Get-WinADDomainUsersFullList -Domain $Domain -Extended:$Extended -ForestSchemaUsers $ForestSchemaUsers -DomainObjects $Data.DomainObjects -ResultPageSize $ResultPageSize
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainUsersFullList
        [PSWinDocumentation.ActiveDirectory]::DomainUsers
        [PSWinDocumentation.ActiveDirectory]::DomainUsersAll
        [PSWinDocumentation.ActiveDirectory]::DomainUsersSystemAccounts
        [PSWinDocumentation.ActiveDirectory]::DomainUsersNeverExpiring
        [PSWinDocumentation.ActiveDirectory]::DomainUsersNeverExpiringInclDisabled
        [PSWinDocumentation.ActiveDirectory]::DomainUsersExpiredInclDisabled
        [PSWinDocumentation.ActiveDirectory]::DomainUsersExpiredExclDisabled
        [PSWinDocumentation.ActiveDirectory]::DomainUsersCount
        [PSWinDocumentation.ActiveDirectory]::DomainFineGrainedPoliciesUsers
        [PSWinDocumentation.ActiveDirectory]::DomainFineGrainedPoliciesUsersExtended
        [PSWinDocumentation.ActiveDirectory]::DomainGroups
        [PSWinDocumentation.ActiveDirectory]::DomainGroupsMembers
        [PSWinDocumentation.ActiveDirectory]::DomainGroupsMembersRecursive

        [PSWinDocumentation.ActiveDirectory].GetEnumValues() | Where-Object { $_ -like 'DomainPassword*' }
    )

    $Data.DomainComputersFullList = Get-DataInformation -Text "Getting domain information - $Domain DomainComputersFullList" {
        Get-WinADDomainComputersFullList -Domain $Domain -ForestSchemaComputers $ForestSchemaComputers -DomainObjects $Data.DomainObjects -ResultPageSize $ResultPageSize
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainComputersFullList
        [PSWinDocumentation.ActiveDirectory]::DomainComputersAll
        [PSWinDocumentation.ActiveDirectory]::DomainComputersAllCount
        [PSWinDocumentation.ActiveDirectory]::DomainComputersAllBuildCount
        [PSWinDocumentation.ActiveDirectory]::DomainServers
        [PSWinDocumentation.ActiveDirectory]::DomainServersCount
        [PSWinDocumentation.ActiveDirectory]::DomainComputers
        [PSWinDocumentation.ActiveDirectory]::DomainComputersCount
        [PSWinDocumentation.ActiveDirectory]::DomainComputersUnknown
        [PSWinDocumentation.ActiveDirectory]::DomainComputersUnknownCount
        [PSWinDocumentation.ActiveDirectory]::DomainBitlocker
        [PSWinDocumentation.ActiveDirectory]::DomainLAPS

        [PSWinDocumentation.ActiveDirectory]::DomainUsers
        [PSWinDocumentation.ActiveDirectory]::DomainGroupsMembers
        [PSWinDocumentation.ActiveDirectory]::DomainGroupsMembersRecursive

        [PSWinDocumentation.ActiveDirectory].GetEnumValues() | Where-Object { $_ -like 'DomainPassword*' }
    )

    $Data.DomainComputersAll = Get-DataInformation -Text "Getting domain information - $Domain DomainComputersAll" {
        Get-WinADDomainComputersAll -DomainComputersFullList $Data.DomainComputersFullList -Splitter $Splitter -DomainObjects $Data.DomainObjects -DomainObjectsNetbios $Data.DomainObjectsNetBios -Domaininformation $Data.DomainInformation
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainComputersAll
        [PSWinDocumentation.ActiveDirectory]::DomainComputersAllCount
        [PSWinDocumentation.ActiveDirectory]::DomainComputersAllBuildCount
        [PSWinDocumentation.ActiveDirectory]::DomainServers
        [PSWinDocumentation.ActiveDirectory]::DomainServersCount
        [PSWinDocumentation.ActiveDirectory]::DomainComputers
        [PSWinDocumentation.ActiveDirectory]::DomainComputersCount
        [PSWinDocumentation.ActiveDirectory]::DomainComputersUnknown
        [PSWinDocumentation.ActiveDirectory]::DomainComputersUnknownCount

        [PSWinDocumentation.ActiveDirectory].GetEnumValues() | Where-Object { $_ -like 'DomainPassword*' }
    )

    $Data.DomainComputersAllCount = Get-DataInformation -Text "Getting domain information - $Domain DomainComputersAllCount" {
        Get-WinADDomainComputersAllCount -DomainComputersAll $Data.DomainComputersAll
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainComputersAllCount
    )
    $Data.DomainComputersAllBuildCount = Get-DataInformation -Text "Getting domain information - $Domain DomainComputersAllBuildCount" {
        Get-WinADDomainComputersAllBuildSummary -DomainComputers $Data.DomainComputersAll -Formatted:$Formatted
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainComputersAllBuildCount
    )

    $Data.DomainServers = Get-DataInformation -Text "Getting domain information - $Domain DomainServers" {
        Get-WinADDomainServers -DomainComputersAll $Data.DomainComputersAll
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainServers
        [PSWinDocumentation.ActiveDirectory]::DomainComputersAll
    )

    $Data.DomainServersCount = Get-DataInformation -Text "Getting domain information - $Domain DomainServersCount" {
        Get-WinADDomainServersCount -DomainServers $Data.DomainServers
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainServersCount
        [PSWinDocumentation.ActiveDirectory]::DomainServers
    )

    $Data.DomainComputers = Get-DataInformation -Text "Getting domain information - $Domain DomainComputers" {
        Get-WinADDomainComputers -DomainComputersAll $Data.DomainComputersAll
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainComputers
        [PSWinDocumentation.ActiveDirectory]::DomainComputersAll
    )

    $Data.DomainComputersCount = Get-DataInformation -Text "Getting domain information - $Domain DomainComputersCount" {
        Get-WinADDomainComputersCount -DomainComputers $Data.DomainComputers
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainComputersCount
        [PSWinDocumentation.ActiveDirectory]::DomainComputers
    )

    $Data.DomainComputersUnknown = Get-DataInformation -Text "Getting domain information - $Domain DomainComputersUnknown" {
        Get-WinADDomainComputersUnknown -DomainComputersAll $Data.DomainComputersAll
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainComputersUnknown
        [PSWinDocumentation.ActiveDirectory]::DomainComputersAll
    )

    $Data.DomainComputersUnknownCount = Get-DataInformation -Text "Getting domain information - $Domain DomainComputersUnknownCount" {
        Get-WinADDomainComputersUnknownCount -DomainComputersUnknown $Data.DomainComputersUnknown
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainComputersUnknownCount
        [PSWinDocumentation.ActiveDirectory]::DomainComputersUnknown
    )

    $Data.DomainRIDs = Get-DataInformation -Text "Getting domain information - $Domain DomainRIDs" {
        Get-WinADDomainRIDs -DomainInformation $Data.DomainInformation -Domain $Domain
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainRIDs
    )

    $Data.DomainGUIDS = Get-DataInformation -Text "Getting domain information - $Domain DomainGUIDS" {
        Get-WinADDomainGUIDs -RootDSE $Data.DomainRootDSE -Domain $Domain
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainGUIDS
        [PSWinDocumentation.ActiveDirectory]::DomainOrganizationalUnitsExtendedACL
    )

    $Data.DomainAuthenticationPolicies = Get-DataInformation -Text "Getting domain information - $Domain DomainAuthenticationPolicies" {
        Get-ADAuthenticationPolicy -Server $Domain -LDAPFilter '(name=AuthenticationPolicy*)'
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainAuthenticationPolicies
    )

    $Data.DomainAuthenticationPolicySilos = Get-DataInformation -Text "Getting domain information - $Domain DomainAuthenticationPolicySilos" {
        Get-ADAuthenticationPolicySilo -Server $Domain -Filter 'Name -like "*AuthenticationPolicySilo*"'
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainAuthenticationPolicySilos
    )

    $Data.DomainCentralAccessPolicies = Get-DataInformation -Text "Getting domain information - $Domain DomainCentralAccessPolicies" {
        Get-ADCentralAccessPolicy -Server $Domain -Filter *
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainCentralAccessPolicies
    )

    $Data.DomainCentralAccessRules = Get-DataInformation -Text "Getting domain information - $Domain DomainCentralAccessRules" {
        Get-ADCentralAccessRule -Server $Domain -Filter *
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainCentralAccessRules
    )

    $Data.DomainClaimTransformPolicies = Get-DataInformation -Text "Getting domain information - $Domain DomainClaimTransformPolicies" {
        Get-ADClaimTransformPolicy -Server $Domain -Filter *
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainClaimTransformPolicies
    )

    $Data.DomainClaimTypes = Get-DataInformation -Text "Getting domain information - $Domain DomainClaimTypes" {
        Get-ADClaimType -Server $Domain -Filter *
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainClaimTypes
    )

    # This won't be in main Data, needed for DomainDNSSrv/DomainDNSA
    $DomainDNSData = Get-DataInformation -Text "Getting domain information - $Domain DomainDNSData" {
        Get-WinADDomainDNSData -Domain $Domain
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainDNSSRV
        [PSWinDocumentation.ActiveDirectory]::DomainDNSA
    )

    $Data.DomainDNSSrv = Get-DataInformation -Text "Getting domain information - $Domain DomainDNSSrv" {
        $DomainDNSData.SRV
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainDNSSrv
    )

    $Data.DomainDNSA = Get-DataInformation -Text "Getting domain information - $Domain DomainDNSA" {
        $DomainDNSData.A
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainDNSA
    )

    $Data.DomainFSMO = Get-DataInformation -Text "Getting domain information - $Domain DomainFSMO" {
        Get-WinADDomainFSMO -Domain $Domain -DomainInformation $Data.DomainInformation
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainFSMO
        [PSWinDocumentation.ActiveDirectory]::DomainTrusts
    )

    $Data.DomainTrustsClean = Get-DataInformation -Text "Getting domain information - $Domain DomainTrustsClean" {
        Get-WinADDomainTrustsClean -Domain $Domain
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainTrustsClean
        [PSWinDocumentation.ActiveDirectory]::DomainTrusts
    )

    $Data.DomainTrusts = Get-DataInformation -Text "Getting domain information - $Domain DomainTrusts" {
        Get-WinADDomainTrusts -DomainPDC $Data.DomainFSMO.'PDC Emulator' -Trusts $Data.DomainTrustsClean -Domain $Domain
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainTrusts
    )

    $Data.DomainGroupPoliciesClean = Get-DataInformation -Text "Getting domain information - $Domain DomainGroupPoliciesClean" {
        Get-GPO -Domain $Domain -All
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainGroupPoliciesClean
        [PSWinDocumentation.ActiveDirectory]::DomainGroupPolicies
        [PSWinDocumentation.ActiveDirectory]::DomainGroupPoliciesDetails
        [PSWinDocumentation.ActiveDirectory]::DomainGroupPoliciesACL
    )

    $Data.DomainGroupPolicies = Get-DataInformation -Text "Getting domain information - $Domain DomainGroupPolicies" {
        Get-WinADDomainGroupPolicies -GroupPolicies $Data.DomainGroupPoliciesClean -Domain $Domain
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainGroupPolicies
    )

    $Data.DomainGroupPoliciesDetails = Get-DataInformation -Text "Getting domain information - $Domain DomainGroupPoliciesDetails" {
        Get-WinADDomainGroupPoliciesDetails -GroupPolicies $Data.DomainGroupPoliciesClean -Domain $Domain -Splitter $Splitter
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainGroupPoliciesDetails
    )

    $Data.DomainGroupPoliciesACL = Get-DataInformation -Text "Getting domain information - $Domain DomainGroupPoliciesACL" {
        Get-GPOZaurrPermission -Forest $Forest -IncludeDomains $Domain
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainGroupPoliciesACL
    )

    $Data.DomainGroupPoliciesACLConsistency = Get-DataInformation -Text "Getting domain information - $Domain DomainGroupPoliciesACLConsistency" {
        Get-GPOZaurrPermissionConsistency -Forest $Forest -IncludeDomains $Domain -VerifyInheritance
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainGroupPoliciesACLConsistency
    )

    $Data.DomainGroupPoliciesSysVol = Get-DataInformation -Text "Getting domain information - $Domain DomainGroupPoliciesSysVol" {
        Get-GPOZaurrBroken -Forest $Forest -IncludeDomains $Domain
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainGroupPoliciesSysVol
    )

    $Data.DomainGroupPoliciesOwners = Get-DataInformation -Text "Gettting domain information - $Domain DomainGroupPoliciesOwners" {
        Get-GPOZaurrOwner -Forest $Forest -IncludeDomains $Domain -IncludeSysvol
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainGroupPoliciesOwners
    )

    $Data.DomainGroupPoliciesWMI = Get-DataInformation -Text "Gettting domain information - $Domain DomainGroupPoliciesWMI" {
        Get-GPOZaurrWMI -Forest $Forest -IncludeDomains $Domain
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainGroupPoliciesWMI
    )

    $Data.DomainGroupPoliciesLinksSummary = Get-DataInformation -Text "Gettting domain information - $Domain DomainGroupPoliciesLinksSummary" {
        Get-GPOZaurrLinkSummary -Report LinksSummary -Forest $Forest -IncludeDomains $Domain
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainGroupPoliciesLinksSummary
    )

    $Data.DomainBitlocker = Get-DataInformation -Text "Getting domain information - $Domain DomainBitlocker" {
        Get-WinADDomainBitlocker -Domain $Domain -Computers $Data.DomainComputersFullList
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainBitlocker
    )

    $Data.DomainLAPS = Get-DataInformation -Text "Getting domain information - $Domain DomainLAPS" {
        Get-WinADDomainLAPS -Domain $Domain -Computers $Data.DomainComputersFullList -Splitter $Splitter
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainLAPS
    )

    $Data.DomainDefaultPasswordPolicy = Get-DataInformation -Text "Getting domain information - $Domain DomainDefaultPasswordPolicy" {
        Get-WinADDomainDefaultPasswordPolicy -Domain $Domain
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainDefaultPasswordPolicy
    )

    $Data.DomainOrganizationalUnitsClean = Get-DataInformation -Text "Getting domain information - $Domain DomainOrganizationalUnitsClean" {
        Get-ADOrganizationalUnit -Server $Domain -Properties * -Filter *
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainOrganizationalUnitsClean
        [PSWinDocumentation.ActiveDirectory]::DomainOrganizationalUnits
        [PSWinDocumentation.ActiveDirectory]::DomainOrganizationalUnitsDN
        [PSWinDocumentation.ActiveDirectory]::DomainOrganizationalUnitsBasicACL
        [PSWinDocumentation.ActiveDirectory]::DomainOrganizationalUnitsExtendedACL
    )

    $Data.DomainOrganizationalUnits = Get-DataInformation -Text "Getting domain information - $Domain DomainOrganizationalUnits" {
        Get-WinADDomainOrganizationalUnits -Domain $Domain -OrgnaizationalUnits $Data.DomainOrganizationalUnitsClean -DomainObjects $Data.DomainObjects
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainOrganizationalUnits
    )

    $Data.DomainOrganizationalUnitsDN = Get-DataInformation -Text "Getting domain information - $Domain DomainOrganizationalUnitsDN" {
        @(
            $Data.DomainInformation.DistinguishedName
            $Data.DomainOrganizationalUnitsClean.DistinguishedName
            # TODO:
            # Wth needs to fix
            $Data.DomainContainers.DistinguishedName
        )
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainOrganizationalUnitsDN
    )

    $Data.DomainOrganizationalUnitsBasicACL = Get-DataInformation -Text "Getting domain information - $Domain DomainOrganizationalUnitsBasicACL" {
        Get-WinADDomainOrganizationalUnitsACL  `
            -DomainOrganizationalUnitsClean $Data.DomainOrganizationalUnitsClean `
            -Domain $Domain `
            -NetBiosName $Data.DomainInformation.NetBIOSName `
            -RootDomainNamingContext $Data.DomainRootDSE.rootDomainNamingContext
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainOrganizationalUnitsBasicACL
    )

    $Data.DomainOrganizationalUnitsExtendedACL = Get-DataInformation -Text "Getting domain information - $Domain DomainOrganizationalUnitsExtendedACL" {
        Get-WinADDomainOrganizationalUnitsACLExtended  `
            -DomainOrganizationalUnitsClean $Data.DomainOrganizationalUnitsClean `
            -Domain $Domain `
            -NetBiosName $Data.DomainInformation.NetBIOSName `
            -RootDomainNamingContext $Data.DomainRootDSE.rootDomainNamingContext `
            -GUID $Data.DomainGUIDS
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainOrganizationalUnitsExtendedACL
    )

    <#
    $Data.DomainUsers = Get-DataInformation -Text "Getting domain information - $Domain DomainUsers" {
        Get-WinUsers `
            -Users $Data.DomainUsersFullList `
            -Domain $Domain `
            -ADCatalog $Data.DomainUsersFullList, $Data.DomainComputersFullList, $Data.DomainGroupsFullList `
            -ADCatalogUsers $Data.DomainUsersFullList
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainUsers

        [PSWinDocumentation.ActiveDirectory]::DomainUsersAll
        [PSWinDocumentation.ActiveDirectory]::DomainUsersSystemAccounts
        [PSWinDocumentation.ActiveDirectory]::DomainUsersNeverExpiring
        [PSWinDocumentation.ActiveDirectory]::DomainUsersNeverExpiringInclDisabled
        [PSWinDocumentation.ActiveDirectory]::DomainUsersExpiredInclDisabled
        [PSWinDocumentation.ActiveDirectory]::DomainUsersExpiredExclDisabled
        [PSWinDocumentation.ActiveDirectory]::DomainUsersCount
    )
#>

    $Data.DomainUsers = Get-DataInformation -Text "Getting domain information - $Domain DomainUsers" {
        Get-WinADDomainUsersAll -Users $Data.DomainUsersFullList -Domain $Domain -DomainObjects $Data.DomainObjects -Splitter $Splitter -DomainObjectsNetbios $Data.DomainObjectsNetBios -Domaininformation $Data.DomainInformation
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainUsers

        [PSWinDocumentation.ActiveDirectory]::DomainUsersAll
        [PSWinDocumentation.ActiveDirectory]::DomainUsersSystemAccounts
        [PSWinDocumentation.ActiveDirectory]::DomainUsersNeverExpiring
        [PSWinDocumentation.ActiveDirectory]::DomainUsersNeverExpiringInclDisabled
        [PSWinDocumentation.ActiveDirectory]::DomainUsersExpiredInclDisabled
        [PSWinDocumentation.ActiveDirectory]::DomainUsersExpiredExclDisabled
        [PSWinDocumentation.ActiveDirectory]::DomainUsersCount

        [PSWinDocumentation.ActiveDirectory].GetEnumValues() | Where-Object { $_ -like 'DomainPassword*' }
    )

    $Data.DomainUsersAll = Get-DataInformation -Text "Getting domain information - $Domain DomainUsersAll" {
        Get-WinADDomainUsersAllFiltered -DomainUsers $Data.DomainUsers
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainUsersAll

        [PSWinDocumentation.ActiveDirectory].GetEnumValues() | Where-Object { $_ -like 'DomainPassword*' }
    )

    $Data.DomainUsersSystemAccounts = Get-DataInformation -Text "Getting domain information - $Domain DomainUsersSystemAccounts" {
        Get-WinADDomainUsersSystemAccounts -DomainUsers $Data.DomainUsers
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainUsersSystemAccounts
    )

    $Data.DomainUsersNeverExpiring = Get-DataInformation -Text "Getting domain information - $Domain DomainUsersNeverExpiring" {
        Get-WinADDomainUsersNeverExpiring -DomainUsers $Data.DomainUsers
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainUsersNeverExpiring
    )

    $Data.DomainUsersNeverExpiringInclDisabled = Get-DataInformation -Text "Getting domain information - $Domain DomainUsersNeverExpiringInclDisabled" {
        Get-WinADDomainUsersNeverExpiringInclDisabled -DomainUsers $Data.DomainUsers
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainUsersNeverExpiringInclDisabled
    )

    $Data.DomainUsersExpiredInclDisabled = Get-DataInformation -Text "Getting domain information - $Domain DomainUsersExpiredInclDisabled" {
        Get-WinADDomainUsersExpiredInclDisabled -DomainUsers $Data.DomainUsers
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainUsersExpiredInclDisabled
    )

    $Data.DomainUsersExpiredExclDisabled = Get-DataInformation -Text "Getting domain information - $Domain DomainUsersExpiredExclDisabled" {
        Get-WinADDomainUsersExpiredExclDisabled -DomainUsers $Data.DomainUsers
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainUsersExpiredExclDisabled
    )

    $Data.DomainUsersCount = Get-DataInformation -Text "Getting domain information - $Domain DomainUsersCount" {
        Get-WinADDomainAllUsersCount `
            -DomainUsers $Data.DomainUsers `
            -DomainUsersAll $Data.DomainUsersAll `
            -DomainUsersExpiredExclDisabled $Data.DomainUsersExpiredExclDisabled `
            -DomainUsersExpiredInclDisabled $Data.DomainUsersExpiredInclDisabled `
            -DomainUsersNeverExpiring $Data.DomainUsersNeverExpiring `
            -DomainUsersNeverExpiringInclDisabled $Data.DomainUsersNeverExpiringInclDisabled `
            -DomainUsersSystemAccounts $Data.DomainUsersSystemAccounts


    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainUsersCount

        <#
        [PSWinDocumentation.ActiveDirectory]::DomainUsers
        [PSWinDocumentation.ActiveDirectory]::DomainUsersAll
        [PSWinDocumentation.ActiveDirectory]::DomainUsersSystemAccounts
        [PSWinDocumentation.ActiveDirectory]::DomainUsersNeverExpiring
        [PSWinDocumentation.ActiveDirectory]::DomainUsersNeverExpiringInclDisabled
        [PSWinDocumentation.ActiveDirectory]::DomainUsersExpiredInclDisabled
        [PSWinDocumentation.ActiveDirectory]::DomainUsersExpiredExclDisabled
        #>
    )

    $Data.DomainControllers = Get-DataInformation -Text "Getting domain information - $Domain DomainControllers" {
        Get-WinADDomainControllersInternal -Domain $Domain
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainControllers
    )

    $Data.DomainFineGrainedPolicies = Get-DataInformation -Text "Getting domain information - $Domain DomainFineGrainedPolicies" {
        Get-WinADDomainFineGrainedPolicies -Domain $Domain
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainFineGrainedPolicies
        [PSWinDocumentation.ActiveDirectory]::DomainFineGrainedPoliciesUsers
        [PSWinDocumentation.ActiveDirectory]::DomainFineGrainedPoliciesUsersExtended
    )

    $Data.DomainFineGrainedPoliciesUsers = Get-DataInformation -Text "Getting domain information - $Domain DomainFineGrainedPoliciesUsers" {
        Get-WinADDomainFineGrainedPoliciesUsers -DomainFineGrainedPolicies $Data.DomainFineGrainedPolicies -DomainObjects $Data.DomainObjects
        #-DomainUsersFullList $Data.DomainUsersFullList `
        # -DomainGroupsFullList $Data.DomainGroupsFullList `

    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainFineGrainedPoliciesUsers
    )


    $Data.DomainFineGrainedPoliciesUsersExtended = Get-DataInformation -Text "Getting domain information - $Domain DomainFineGrainedPoliciesUsersExtended" {
        Get-WinADDomainFineGrainedPoliciesUsersExtended -DomainFineGrainedPolicies $Data.DomainFineGrainedPolicies -Domain $Domain -DomainObjects $Data.DomainObjects
        #    -DomainUsersFullList $Data.DomainUsersFullList `
        #    -DomainGroupsFullList $Data.DomainGroupsFullList `

    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainFineGrainedPoliciesUsersExtended
    )




    $Data.DomainGroups = Get-DataInformation -Text "Getting domain information - $Domain DomainGroups" {
        Get-WinGroups -Groups $Data.DomainGroupsFullList -Domain $Domain -Splitter $Splitter -DomainObjects $Data.DomainObjects
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainGroups
        [PSWinDocumentation.ActiveDirectory]::DomainGroupsPriviliged
        [PSWinDocumentation.ActiveDirectory]::DomainGroupsSpecial
    )

    $Data.DomainGroupsMembers = Get-DataInformation -Text "Getting domain information - $Domain DomainGroupsMembers" {
        Get-WinGroupMembers -Groups $Data.DomainGroups `
            -Domain $Domain `
            -Option Standard `
            -DomainObjects $Data.DomainObjects
        #-ADCatalog $Data.DomainUsersFullList, $Data.DomainComputersFullList, $Data.DomainGroupsFullList `
        # -ADCatalogUsers $Data.DomainUsersFullList `

    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainGroupsMembers
        [PSWinDocumentation.ActiveDirectory]::DomainGroupsSpecialMembers
        [PSWinDocumentation.ActiveDirectory]::DomainGroupsPriviligedMembers
        [PSWinDocumentation.ActiveDirectory]::DomainAdministrators
        [PSWinDocumentation.ActiveDirectory]::DomainEnterpriseAdministrators
    )

    $Data.DomainGroupsMembersRecursive = Get-DataInformation -Text "Getting domain information - $Domain DomainGroupsMembersRecursive" {
        Get-WinGroupMembers -Groups $Data.DomainGroups `
            -Domain $Domain `
            -Option Recursive `
            -DomainObjects $Data.DomainObjects
        # -ADCatalog $Data.DomainUsersFullList, $Data.DomainComputersFullList, $Data.DomainGroupsFullList `
        # -ADCatalogUsers $Data.DomainUsersFullList `

    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainGroupsMembersRecursive
        [PSWinDocumentation.ActiveDirectory]::DomainGroupsSpecialMembersRecursive
        [PSWinDocumentation.ActiveDirectory]::DomainGroupsPriviligedMembersRecursive
        [PSWinDocumentation.ActiveDirectory]::DomainAdministratorsRecursive
        [PSWinDocumentation.ActiveDirectory]::DomainEnterpriseAdministratorsRecursive
    )

    $Data.DomainGroupsPriviliged = Get-DataInformation -Text "Getting domain information - $Domain DomainGroupsPriviliged" {
        Get-DomainGroupsPriviliged -DomainGroups $Data.DomainGroups -DomainInformation $Data.DomainInformation
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainGroupsPriviliged
        [PSWinDocumentation.ActiveDirectory]::DomainGroupsPriviligedMembers
        [PSWinDocumentation.ActiveDirectory]::DomainGroupsPriviligedMembersRecursive
    )

    $Data.DomainGroupsSpecial = Get-DataInformation -Text "Getting domain information - $Domain DomainGroupsSpecial" {
        Get-WinADDomainGroupsSpecial -DomainGroups $Data.DomainGroups
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainGroupsSpecial
        [PSWinDocumentation.ActiveDirectory]::DomainGroupMembersRecursiveSpecial
    )

    $Data.DomainGroupsSpecialMembers = Get-DataInformation -Text "Getting domain information - $Domain DomainGroupsSpecialMembers" {
        Get-WinADDomainGroupsSpecialMembers -DomainGroupsMembers $Data.DomainGroupsMembers
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainGroupsSpecialMembers
    )

    $Data.DomainGroupsSpecialMembersRecursive = Get-DataInformation -Text "Getting domain information - $Domain DomainGroupsSpecialMembersRecursive" {
        Get-WinADDomainGroupsSpecialMembersRecursive -DomainGroupsMembersRecursive $Data.DomainGroupsMembersRecursive
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainGroupsSpecialMembersRecursive
    )

    $Data.DomainGroupsPriviligedMembers = Get-DataInformation -Text "Getting domain information - $Domain DomainGroupsPriviligedMembers" {
        ### NEEDS REVIEW, something looks wrong
        Get-WinADDomainGroupsPriviligedMembers -DomainGroupsMembers $Data.DomainGroupsMembers -DomainGroupsPriviliged $Data.DomainGroupsPriviliged
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainGroupsPriviligedMembers
    )
    $Data.DomainGroupsPriviligedMembersRecursive = Get-DataInformation -Text "Getting domain information - $Domain DomainGroupsPriviligedMembersRecursive" {
        ### NEEDS REVIEW, something looks wrong
        Get-WinADDomainGroupsPriviligedMembersRecursive -DomainGroupsMembersRecursive $Data.DomainGroupsMembersRecursive -DomainGroupsPriviliged $Data.DomainGroupsPriviliged
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainGroupsPriviligedMembersRecursive
    )

    $Data.DomainAdministrators = Get-DataInformation -Text "Getting domain information - $Domain DomainAdministrators" {
        Get-WinADDomainAdministrators -DomainGroupsMembers $Data.DomainGroupsMembers -DomainInformation $Data.DomainInformation
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainAdministrators
    )
    $Data.DomainAdministratorsRecursive = Get-DataInformation -Text "Getting domain information - $Domain DomainAdministratorsRecursive" {
        Get-WinADDomainAdministratorsRecursive -DomainGroupsMembersRecursive $Data.DomainGroupsMembersRecursive -DomainInformation $Data.DomainInformation
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainAdministratorsRecursive
    )


    $Data.DomainEnterpriseAdministrators = Get-DataInformation -Text "Getting domain information - $Domain DomainEnterpriseAdministrators" {
        Get-WinADDomainEnterpriseAdministrators -DomainGroupsMembers $Data.DomainGroupsMembers -DomainInformation $Data.DomainInformation
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainEnterpriseAdministrators
    )
    $Data.DomainEnterpriseAdministratorsRecursive = Get-DataInformation -Text "Getting domain information - $Domain DomainEnterpriseAdministratorsRecursive" {
        Get-WinADDomainEnterpriseAdministratorsRecursive -DomainGroupsMembersRecursive $Data.DomainGroupsMembersRecursive -DomainInformation $Data.DomainInformation
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainEnterpriseAdministratorsRecursive
    )

    $Data.DomainWellKnownFolders = Get-DataInformation -Text "Gettting domain information - $Domain DomainWellKnownFolders" {
        Get-WinADWellKnownFolders -IncludeDomains $Domain
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainWellKnownFolders
    )
    # PASSWORD QUALITY SECTION

    $Data.DomainPasswordDataUsers = Get-DataInformation -Text "Getting domain information - $Domain DomainPasswordDataUsers" {
        Get-WinADDomainPassword -DnsRoot $Data.DomainInformation.DNSRoot -DistinguishedName $Data.DomainInformation.DistinguishedName
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory].GetEnumValues() | Where-Object { $_ -like 'DomainPassword*' }
    )

    $Data.DomainPasswordDataPasswords = Get-DataInformation -Text "Getting domain information - $Domain DomainPasswordDataPasswords" {
        Get-WinADDomainPasswordQuality `
            -FilePath $PathToPasswords `
            -DomainDistinguishedName $Data.DomainInformation.DistinguishedName `
            -DnsRoot $Data.DomainInformation.DnsRoot `
            -Verbose:$false `
            -PasswordQualityUsers $Data.DomainPasswordDataUsers `
            -PasswordQuality:$PasswordQuality.IsPresent `
            -DomainObjectsNetbios $Data.DomainObjectsNetBios
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory].GetEnumValues() | Where-Object { $_ -like 'DomainPassword*' }
    )

    $Data.DomainPasswordDataPasswordsHashes = Get-DataInformation -Text "Getting domain information - $Domain DomainPasswordDataPasswordsHashes" {
        Get-WinADDomainPasswordQuality `
            -FilePath $PathToPasswordsHashes `
            -DomainDistinguishedName $Data.DomainInformation.DistinguishedName `
            -DnsRoot $DomainInformation.DnsRoot `
            -UseHashes `
            -Verbose:$false `
            -PasswordQualityUsers $Data.DomainPasswordDataUsers `
            -PasswordQuality:$PasswordQuality.IsPresent `
            -DomainObjectsNetbios $Data.DomainObjectsNetBios
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainPasswordHashesWeakPassword,
        [PSWinDocumentation.ActiveDirectory]::DomainPasswordHashesWeakPasswordEnabled,
        [PSWinDocumentation.ActiveDirectory]::DomainPasswordHashesWeakPasswordDisabled
    )

    if ($Data.DomainPasswordDataPasswords) {
        $PasswordsQuality = $Data.DomainPasswordDataPasswords
    } elseif ($Data.DomainPasswordDataPasswordsHashes) {
        $PasswordsQuality = $Data.DomainPasswordDataPasswordsHashes
    } else {
        $PasswordsQuality = $null
    }


    $Data.DomainPasswordClearTextPassword = Get-DataInformation -Text "Getting domain information - $Domain DomainPasswordClearTextPassword" {
        $PasswordsQuality.DomainPasswordClearTextPassword
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainPasswordClearTextPassword
    )
    $Data.DomainPasswordLMHash = Get-DataInformation -Text "Getting domain information - $Domain DomainPasswordLMHash" {
        $PasswordsQuality.DomainPasswordLMHash
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainPasswordLMHash
    )
    $Data.DomainPasswordEmptyPassword = Get-DataInformation -Text "Getting domain information - $Domain DomainPasswordEmptyPassword" {
        $PasswordsQuality.DomainPasswordEmptyPassword
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainPasswordEmptyPassword
    )
    $Data.DomainPasswordEmptyPassword = Get-DataInformation -Text "Getting domain information - $Domain DomainPasswordEmptyPassword" {
        $PasswordsQuality.DomainPasswordEmptyPassword
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainPasswordEmptyPassword
    )

    $Data.DomainPasswordWeakPassword = Get-DataInformation -Text "Getting domain information - $Domain DomainPasswordWeakPassword" {
        $PasswordsQuality.DomainPasswordWeakPassword
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainPasswordWeakPassword
    )

    $Data.DomainPasswordWeakPasswordEnabled = Get-DataInformation -Text "Getting domain information - $Domain DomainPasswordWeakPasswordEnabled" {
        $PasswordsQuality.DomainPasswordWeakPasswordEnabled
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainPasswordWeakPasswordEnabled
    )

    $Data.DomainPasswordWeakPasswordDisabled = Get-DataInformation -Text "Getting domain information - $Domain DomainPasswordWeakPasswordDisabled" {
        $PasswordsQuality.DomainPasswordWeakPasswordDisabled
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainPasswordWeakPasswordDisabled
    )

    $Data.DomainPasswordWeakPasswordList = Get-DataInformation -Text "Getting domain information - $Domain DomainPasswordWeakPasswordList" {
        $PasswordsQuality.DomainPasswordWeakPasswordList
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainPasswordWeakPasswordList
    )

    $Data.DomainPasswordDefaultComputerPassword = Get-DataInformation -Text "Getting domain information - $Domain DomainPasswordDefaultComputerPassword" {
        $PasswordsQuality.DomainPasswordDefaultComputerPassword
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainPasswordDefaultComputerPassword
    )

    $Data.DomainPasswordPasswordNotRequired = Get-DataInformation -Text "Getting domain information - $Domain DomainPasswordPasswordNotRequired" {
        $PasswordsQuality.DomainPasswordPasswordNotRequired
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainPasswordPasswordNotRequired
    )

    $Data.DomainPasswordPasswordNeverExpires = Get-DataInformation -Text "Getting domain information - $Domain DomainPasswordPasswordNeverExpires" {
        $PasswordsQuality.DomainPasswordPasswordNeverExpires
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainPasswordPasswordNeverExpires
    )

    $Data.DomainPasswordAESKeysMissing = Get-DataInformation -Text "Getting domain information - $Domain DomainPasswordAESKeysMissing" {
        $PasswordsQuality.DomainPasswordAESKeysMissing
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainPasswordAESKeysMissing
    )

    $Data.DomainPasswordPreAuthNotRequired = Get-DataInformation -Text "Getting domain information - $Domain DomainPasswordPreAuthNotRequired" {
        $PasswordsQuality.DomainPasswordPreAuthNotRequired
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainPasswordPreAuthNotRequired
    )

    $Data.DomainPasswordDESEncryptionOnly = Get-DataInformation -Text "Getting domain information - $Domain DomainPasswordDESEncryptionOnly" {
        $PasswordsQuality.DomainPasswordDESEncryptionOnly
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainPasswordDESEncryptionOnly
    )

    $Data.DomainPasswordDelegatableAdmins = Get-DataInformation -Text "Getting domain information - $Domain DomainPasswordDelegatableAdmins" {
        $PasswordsQuality.DomainPasswordDelegatableAdmins
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainPasswordDelegatableAdmins
    )

    $Data.DomainPasswordDuplicatePasswordGroups = Get-DataInformation -Text "Getting domain information - $Domain DomainPasswordDuplicatePasswordGroups" {
        $PasswordsQuality.DomainPasswordDuplicatePasswordGroups
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainPasswordDuplicatePasswordGroups
    )

    $Data.DomainPasswordHashesWeakPassword = Get-DataInformation -Text "Getting domain information - $Domain DomainPasswordHashesWeakPassword" {
        $PasswordsQuality.DomainPasswordHashesWeakPassword
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainPasswordHashesWeakPassword
    )

    $Data.DomainPasswordHashesWeakPasswordEnabled = Get-DataInformation -Text "Getting domain information - $Domain DomainPasswordHashesWeakPasswordEnabled" {
        $PasswordsQuality.DomainPasswordHashesWeakPasswordEnabled
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainPasswordHashesWeakPasswordEnabled
    )

    $Data.DomainPasswordHashesWeakPasswordDisabled = Get-DataInformation -Text "Getting domain information - $Domain DomainPasswordHashesWeakPasswordDisabled" {
        $Data.DomainPasswordDataPasswordsHashes.DomainPasswordWeakPasswordDisabled
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainPasswordHashesWeakPasswordDisabled
    )
    $Data.DomainPasswordSmartCardUsersWithPassword = Get-DataInformation -Text "Getting domain information - $Domain DomainPasswordSmartCardUsersWithPassword" {
        $Data.DomainPasswordDataPasswordsHashes.DomainPasswordSmartCardUsersWithPassword
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainPasswordSmartCardUsersWithPassword
    )
    $Data.DomainPasswordStats = Get-DataInformation -Text "Getting domain information - $Domain DomainPasswordStats" {
        Get-WinADDomainPasswordStats -PasswordsQuality $PasswordsQuality -TypesRequired $TypesRequired `
            -DomainPasswordHashesWeakPassword $Data.DomainPasswordHashesWeakPassword `
            -DomainPasswordHashesWeakPasswordEnabled $Data.DomainPasswordHashesWeakPasswordEnabled `
            -DomainPasswordHashesWeakPasswordDisabled $Data.DomainPasswordHashesWeakPasswordDisabled

    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainPasswordStats
    )


    $EndTime = Stop-TimeLog -Time $TimeToGenerate
    Write-Verbose "Getting domain information - $Domain - Time to generate: $EndTime"
    return $Data
}
