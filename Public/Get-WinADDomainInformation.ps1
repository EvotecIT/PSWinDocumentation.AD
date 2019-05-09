function Get-WinADDomainInformation {
    [CmdletBinding()]
    param (
        [string] $Domain,
        [PSWinDocumentation.ActiveDirectory[]] $TypesRequired,
        [string] $PathToPasswords,
        [string] $PathToPasswordsHashes,
        [switch] $Extended,
        [Array] $ForestSchemaComputers,
        [Array] $ForestSchemaUsers,
        [switch] $PasswordQuality
    )
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
    }
    if ($null -eq $ForestSchemaUsers) {
        $ForestSchemaUsers = Get-DataInformation -Text "Getting domain information - ForestSchemaPropertiesUsers" {
            Get-WinADForestSchemaPropertiesUsers
        } -TypesRequired $TypesRequired -TypesNeeded @(
            [PSWinDocumentation.ActiveDirectory]::ForestSchemaPropertiesUsers
            [PSWinDocumentation.ActiveDirectory]::DomainUsersFullList
        )
    }

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
    )

    # Groups
    $Data.DomainGroupsFullList = Get-DataInformation -Text "Getting domain information - $Domain DomainGroupsFullList" {
        Get-WinADDomainGroupsFullList -Domain $Domain
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainGroupsFullList
    )


    # Users
    $Data.DomainUsersFullList = Get-DataInformation -Text "Getting domain information - $Domain DomainUsersFullList" {
        Get-WinADDomainUsersFullList -Domain $Domain -Extended:$Extended -ForestSchemaUsers $ForestSchemaUsers
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
    )

    $Data.DomainComputersFullList = Get-DataInformation -Text "Getting domain information - $Domain DomainComputersFullList" {
        Get-WinADDomainComputersFullList -Domain $Domain -ForestSchemaComputers $ForestSchemaComputers
    } -TypesRequired $TypesRequired -TypesNeeded @(
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

    $Data.DomainComputersAll = Get-DataInformation -Text "Getting domain information - $Domain DomainComputersAll" {
        Get-WinADDomainComputersAll -DomainComputersFullList $Data.DomainComputersFullList
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainComputersAll
        [PSWinDocumentation.ActiveDirectory]::DomainComputersAllCount
        [PSWinDocumentation.ActiveDirectory]::DomainServers
        [PSWinDocumentation.ActiveDirectory]::DomainServersCount
        [PSWinDocumentation.ActiveDirectory]::DomainComputers
        [PSWinDocumentation.ActiveDirectory]::DomainComputersCount
        [PSWinDocumentation.ActiveDirectory]::DomainComputersUnknown
        [PSWinDocumentation.ActiveDirectory]::DomainComputersUnknownCount
    )

    $Data.DomainComputersAllCount = Get-DataInformation -Text "Getting domain information - $Domain DomainComputersAllCount" {
        Get-WinADDomainComputersAllCount -DomainComputersAll $Data.DomainComputersAll
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainComputersAllCount
        [PSWinDocumentation.ActiveDirectory]::DomainComputersAll
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
        Get-WinADDomainGroupPoliciesDetails -GroupPolicies $Data.DomainGroupPoliciesClean -Domain $Domain
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainGroupPoliciesDetails
    )

    $Data.DomainGroupPoliciesACL = Get-DataInformation -Text "Getting domain information - $Domain DomainGroupPoliciesACL" {
        Get-WinADDomainGroupPoliciesACL -GroupPolicies $Data.DomainGroupPoliciesClean -Domain $Domain
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainGroupPoliciesACL
    )

    $Data.DomainBitlocker = Get-DataInformation -Text "Getting domain information - $Domain DomainBitlocker" {
        Get-WinADDomainBitlocker -Domain $Domain -Computers $Data.DomainComputersFullList
    } -TypesRequired $TypesRequired -TypesNeeded @(
        [PSWinDocumentation.ActiveDirectory]::DomainBitlocker
    )

    $Data.DomainLAPS = Get-DataInformation -Text "Getting domain information - $Domain DomainLAPS" {
        Get-WinADDomainLAPS -Domain $Domain -Computers $Data.DomainComputersFullList
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
        Get-WinADDomainOrganizationalUnits -Domain $Domain -OrgnaizationalUnits $Data.DomainOrganizationalUnitsClean
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


    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @(
            [PSWinDocumentation.ActiveDirectory]::DomainUsers,
            [PSWinDocumentation.ActiveDirectory]::DomainUsersAll,
            [PSWinDocumentation.ActiveDirectory]::DomainUsersSystemAccounts,
            [PSWinDocumentation.ActiveDirectory]::DomainUsersNeverExpiring,
            [PSWinDocumentation.ActiveDirectory]::DomainUsersNeverExpiringInclDisabled,
            [PSWinDocumentation.ActiveDirectory]::DomainUsersExpiredInclDisabled,
            [PSWinDocumentation.ActiveDirectory]::DomainUsersExpiredExclDisabled,
            [PSWinDocumentation.ActiveDirectory]::DomainUsersCount
        )) {

        $Data.DomainUsers = Invoke-Command -ScriptBlock {
            Write-Verbose "Getting domain information - $Domain DomainUsers"
            return Get-WinUsers -Users $Data.DomainUsersFullList -Domain $Domain -ADCatalog $Data.DomainUsersFullList, $Data.DomainComputersFullList, $Data.DomainGroupsFullList -ADCatalogUsers $Data.DomainUsersFullList
        }
        Write-Verbose "Getting domain information - $Domain DomainUsersAll"
        $Data.DomainUsersAll = $Data.DomainUsers | Where-Object { $_.PasswordNotRequired -eq $False } #| Select-Object * #Name, SamAccountName, UserPrincipalName, Enabled
        Write-Verbose "Getting domain information - $Domain DomainUsersSystemAccounts"
        $Data.DomainUsersSystemAccounts = $Data.DomainUsers | Where-Object { $_.PasswordNotRequired -eq $true } #| Select-Object * #Name, SamAccountName, UserPrincipalName, Enabled
        Write-Verbose "Getting domain information - $Domain DomainUsersNeverExpiring"
        $Data.DomainUsersNeverExpiring = $Data.DomainUsers | Where-Object { $_.PasswordNeverExpires -eq $true -and $_.Enabled -eq $true -and $_.PasswordNotRequired -eq $false } #| Select-Object * #Name, SamAccountName, UserPrincipalName, Enabled
        Write-Verbose "Getting domain information - $Domain DomainUsersNeverExpiringInclDisabled"
        $Data.DomainUsersNeverExpiringInclDisabled = $Data.DomainUsers | Where-Object { $_.PasswordNeverExpires -eq $true -and $_.PasswordNotRequired -eq $false } #| Select-Object * #Name, SamAccountName, UserPrincipalName, Enabled
        Write-Verbose "Getting domain information - $Domain DomainUsersExpiredInclDisabled"
        $Data.DomainUsersExpiredInclDisabled = $Data.DomainUsers | Where-Object { $_.PasswordNeverExpires -eq $false -and $_.DaysToExpire -le 0 -and $_.PasswordNotRequired -eq $false } #| Select-Object * #Name, SamAccountName, UserPrincipalName, Enabled
        Write-Verbose "Getting domain information - $Domain DomainUsersExpiredExclDisabled"
        $Data.DomainUsersExpiredExclDisabled = $Data.DomainUsers | Where-Object { $_.PasswordNeverExpires -eq $false -and $_.DaysToExpire -le 0 -and $_.Enabled -eq $true -and $_.PasswordNotRequired -eq $false } #| Select-Object * # Name, SamAccountName, UserPrincipalName, Enabled
        Write-Verbose "Getting domain information - $Domain All Users Count"
        $Data.DomainUsersCount = [ordered] @{
            'Users Count Incl. System'            = Get-ObjectCount -Object $Data.DomainUsers
            'Users Count'                         = Get-ObjectCount -Object $Data.DomainUsersAll
            'Users Expired'                       = Get-ObjectCount -Object $Data.DomainUsersExpiredExclDisabled
            'Users Expired Incl. Disabled'        = Get-ObjectCount -Object $Data.DomainUsersExpiredInclDisabled
            'Users Never Expiring'                = Get-ObjectCount -Object $Data.DomainUsersNeverExpiring
            'Users Never Expiring Incl. Disabled' = Get-ObjectCount -Object $Data.DomainUsersNeverExpiringInclDisabled
            'Users System Accounts'               = Get-ObjectCount -Object $Data.DomainUsersSystemAccounts
        }
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::DomainControllers )) {
        Write-Verbose "Getting domain information - $Domain DomainControllers"
        $Data.DomainControllersClean = $(Get-ADDomainController -Server $Domain -Filter * )
        $Data.DomainControllers = Invoke-Command -ScriptBlock {
            foreach ($Policy in $Data.DomainControllersClean) {
                [PSCustomObject][ordered] @{
                    'Name'             = $Policy.Name
                    'Host Name'        = $Policy.HostName
                    'Operating System' = $Policy.OperatingSystem
                    'Site'             = $Policy.Site
                    'Ipv4'             = $Policy.Ipv4Address
                    'Ipv6'             = $Policy.Ipv6Address
                    'Global Catalog?'  = $Policy.IsGlobalCatalog
                    'Read Only?'       = $Policy.IsReadOnly
                    'Ldap Port'        = $Policy.LdapPort
                    'SSL Port'         = $Policy.SSLPort
                }
            }
        }
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::DomainFineGrainedPolicies)) {
        Write-Verbose "Getting domain information - $Domain DomainFineGrainedPolicies"
        $Data.DomainFineGrainedPolicies = Get-WinADDomainFineGrainedPolicies -Domain $Domain
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::DomainFineGrainedPoliciesUsers)) {
        Write-Verbose "Getting domain information - $Domain DomainFineGrainedPoliciesUsers"
        $Data.DomainFineGrainedPoliciesUsers = Get-WinADDomainFineGrainedPoliciesUsers `
            -DomainFineGrainedPolicies $Data.DomainFineGrainedPolicies `
            -DomainUsersFullList $Data.DomainUsersFullList `
            -DomainGroupsFullList $Data.DomainGroupsFullList
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::DomainFineGrainedPoliciesUsersExtended)) {
        $Data.DomainFineGrainedPoliciesUsersExtended = Get-WinADDomainFineGrainedPoliciesUsersExtended `
            -DomainFineGrainedPolicies $Data.DomainFineGrainedPoliciesUsers `
            -DomainUsersFullList $Data.DomainUsersFullList `
            -DomainGroupsFullList $Data.DomainGroupsFullList `
            -Domain $Domain
    }

    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::DomainGroups, [PSWinDocumentation.ActiveDirectory]::DomainGroupsSpecial)) {
        Write-Verbose "Getting domain information - $Domain DomainGroups"
        $Data.DomainGroups = Get-WinGroups -Groups $Data.DomainGroupsFullList -Users $Data.DomainUsersFullList -Domain $Domain
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::DomainGroups, [PSWinDocumentation.ActiveDirectory]::DomainGroupsMembers)) {
        Write-Verbose "Getting domain information - $Domain DomainGroupsMembers"
        $Data.DomainGroupsMembers = Get-WinGroupMembers -Groups $Data.DomainGroups -Domain $Domain -ADCatalog $Data.DomainUsersFullList, $Data.DomainComputersFullList, $Data.DomainGroupsFullList -ADCatalogUsers $Data.DomainUsersFullList -Option Standard
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::DomainGroups, [PSWinDocumentation.ActiveDirectory]::DomainGroupsMembersRecursive)) {
        Write-Verbose "Getting domain information - $Domain DomainGroupsMembersRecursive"
        $Data.DomainGroupsMembersRecursive = Get-WinGroupMembers -Groups $Data.DomainGroups -Domain $Domain -ADCatalog $Data.DomainUsersFullList, $Data.DomainComputersFullList, $Data.DomainGroupsFullList -ADCatalogUsers $Data.DomainUsersFullList -Option Recursive
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::DomainGroupsPriviliged)) {
        $Data.DomainGroupsPriviliged = Get-DomainGroupsPriviliged -DomainGroups $Data.DomainGroups -DomainInformation $Data.DomainInformation
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::DomainGroupsSpecial, [PSWinDocumentation.ActiveDirectory]::DomainGroupMembersRecursiveSpecial)) {
        Write-Verbose "Getting domain information - $Domain DomainGroupsSpecial"
        $Data.DomainGroupsSpecial = $Data.DomainGroups | Where-Object { ($_.'Group SID').Length -eq 12 }
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::DomainGroupsSpecialMembers, [PSWinDocumentation.ActiveDirectory]::DomainGroupsSpecialMembersRecursive)) {
        Write-Verbose "Getting domain information - $Domain DomainGroupMembersSpecialRecursive"
        $Data.DomainGroupsSpecialMembers = $Data.DomainGroupsMembers | Where-Object { ($_.'Group SID').Length -eq 12 } | Select-Object * #-Exclude Group*, 'High Privileged Group'
        Write-Verbose "Getting domain information - $Domain DomainGroupsSpecialMembersRecursive"
        $Data.DomainGroupsSpecialMembersRecursive = $Data.DomainGroupsMembersRecursive | Where-Object { ($_.'Group SID').Length -eq 12 } | Select-Object * #-Exclude Group*, 'High Privileged Group'
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::DomainGroupsPriviligedMembers, [PSWinDocumentation.ActiveDirectory]::DomainGroupsPriviligedMembersRecursive)) {
        Write-Verbose "Getting domain information - $Domain DomainGroupsPriviligedMembers"
        $Data.DomainGroupsPriviligedMembers = $Data.DomainGroupsMembers | Where-Object { $Data.DomainGroupsPriviliged.'Group SID' -contains ($_.'Group SID') } | Select-Object * #-Exclude Group*, 'High Privileged Group'
        Write-Verbose "Getting domain information - $Domain DomainGroupsPriviligedMembersRecursive"
        $Data.DomainGroupsPriviligedMembersRecursive = $Data.DomainGroupsMembersRecursive | Where-Object { $Data.DomainGroupsPriviliged.'Group SID' -contains ($_.'Group SID') } | Select-Object * #-Exclude Group*, 'High Privileged Group'
    }
    ## Users per one group only.
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::DomainAdministrators, [PSWinDocumentation.ActiveDirectory]::DomainGroupsMembers)) {
        Write-Verbose "Getting domain information - $Domain DomainAdministrators"
        $Data.DomainAdministrators = $Data.DomainGroupsMembers | Where-Object { $_.'Group SID' -eq $('{0}-512' -f $Data.DomainInformation.DomainSID.Value) } | Select-Object * -Exclude Group*, 'High Privileged Group'
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::DomainAdministratorsRecursive, [PSWinDocumentation.ActiveDirectory]::DomainGroupsMembersRecursive)) {
        Write-Verbose "Getting domain information - $Domain DomainAdministratorsRecursive"
        $Data.DomainAdministratorsRecursive = $Data.DomainGroupsMembersRecursive | Where-Object { $_.'Group SID' -eq $('{0}-512' -f $Data.DomainInformation.DomainSID.Value) } | Select-Object * -Exclude Group*, 'High Privileged Group'
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::DomainEnterpriseAdministrators, [PSWinDocumentation.ActiveDirectory]::DomainGroupsMembers)) {
        Write-Verbose "Getting domain information - $Domain DomainEnterpriseAdministrators"
        $Data.DomainEnterpriseAdministrators = $Data.DomainGroupsMembers | Where-Object { $_.'Group SID' -eq $('{0}-519' -f $Data.DomainInformation.DomainSID.Value) } | Select-Object * -Exclude Group*, 'High Privileged Group'
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::DomainEnterpriseAdministratorsRecursive, [PSWinDocumentation.ActiveDirectory]::DomainGroupsMembersRecursive)) {
        Write-Verbose "Getting domain information - $Domain DomainEnterpriseAdministratorsRecursive"
        $Data.DomainEnterpriseAdministratorsRecursive = $Data.DomainGroupsMembersRecursive | Where-Object { $_.'Group SID' -eq $('{0}-519' -f $Data.DomainInformation.DomainSID.Value) } | Select-Object * -Exclude Group*, 'High Privileged Group'
    }

    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @(
            [PSWinDocumentation.ActiveDirectory]::DomainPasswordDataUsers,
            [PSWinDocumentation.ActiveDirectory]::DomainPasswordDataPasswords,
            [PSWinDocumentation.ActiveDirectory]::DomainPasswordClearTextPassword,
            [PSWinDocumentation.ActiveDirectory]::DomainPasswordLMHash,
            [PSWinDocumentation.ActiveDirectory]::DomainPasswordEmptyPassword,
            [PSWinDocumentation.ActiveDirectory]::DomainPasswordWeakPassword,
            [PSWinDocumentation.ActiveDirectory]::DomainPasswordWeakPasswordEnabled,
            [PSWinDocumentation.ActiveDirectory]::DomainPasswordWeakPasswordDisabled,
            [PSWinDocumentation.ActiveDirectory]::DomainPasswordWeakPasswordList,
            [PSWinDocumentation.ActiveDirectory]::DomainPasswordDefaultComputerPassword,
            [PSWinDocumentation.ActiveDirectory]::DomainPasswordPasswordNotRequired,
            [PSWinDocumentation.ActiveDirectory]::DomainPasswordPasswordNeverExpires,
            [PSWinDocumentation.ActiveDirectory]::DomainPasswordAESKeysMissing,
            [PSWinDocumentation.ActiveDirectory]::DomainPasswordPreAuthNotRequired,
            [PSWinDocumentation.ActiveDirectory]::DomainPasswordDESEncryptionOnly,
            [PSWinDocumentation.ActiveDirectory]::DomainPasswordDelegatableAdmins,
            [PSWinDocumentation.ActiveDirectory]::DomainPasswordDuplicatePasswordGroups,
            [PSWinDocumentation.ActiveDirectory]::DomainPasswordStats,
            [PSWinDocumentation.ActiveDirectory]::DomainPasswordHashesWeakPassword,
            [PSWinDocumentation.ActiveDirectory]::DomainPasswordHashesWeakPasswordEnabled,
            [PSWinDocumentation.ActiveDirectory]::DomainPasswordHashesWeakPasswordDisabled
        )) {
        Write-Verbose "Getting domain password information - $Domain DomainPasswordDataUsers - This will take a while if set!"
        $TimeToProcess = Start-TimeLog
        try {
            $Data.DomainPasswordDataUsers = Get-ADReplAccount -All -Server $Data.DomainInformation.DnsRoot -NamingContext $Data.DomainInformation.DistinguishedName
        } catch {
            $ErrorMessage = $_.Exception.Message -replace "`n", " " -replace "`r", " "
            if ($ErrorMessage -like '*is not recognized as the name of a cmdlet*') {
                Write-Warning "Get-ADReplAccount - Please install module DSInternals (Install-Module DSInternals) - Error: $ErrorMessage"
            } else {
                Write-Warning "Get-ADReplAccount - Error occured: $ErrorMessage"
            }
        }
        Write-Verbose "Getting domain password information - $Domain DomainPasswordDataUsers - Time: $($TimeToProcess | Stop-TimeLog)"
    }

    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @(
            [PSWinDocumentation.ActiveDirectory]::DomainPasswordDataPasswords,
            [PSWinDocumentation.ActiveDirectory]::DomainPasswordClearTextPassword,
            [PSWinDocumentation.ActiveDirectory]::DomainPasswordLMHash,
            [PSWinDocumentation.ActiveDirectory]::DomainPasswordEmptyPassword,
            [PSWinDocumentation.ActiveDirectory]::DomainPasswordWeakPassword,
            [PSWinDocumentation.ActiveDirectory]::DomainPasswordWeakPasswordEnabled,
            [PSWinDocumentation.ActiveDirectory]::DomainPasswordWeakPasswordDisabled,
            [PSWinDocumentation.ActiveDirectory]::DomainPasswordWeakPasswordList,
            [PSWinDocumentation.ActiveDirectory]::DomainPasswordDefaultComputerPassword,
            [PSWinDocumentation.ActiveDirectory]::DomainPasswordPasswordNotRequired,
            [PSWinDocumentation.ActiveDirectory]::DomainPasswordPasswordNeverExpires,
            [PSWinDocumentation.ActiveDirectory]::DomainPasswordAESKeysMissing,
            [PSWinDocumentation.ActiveDirectory]::DomainPasswordPreAuthNotRequired,
            [PSWinDocumentation.ActiveDirectory]::DomainPasswordDESEncryptionOnly,
            [PSWinDocumentation.ActiveDirectory]::DomainPasswordDelegatableAdmins,
            [PSWinDocumentation.ActiveDirectory]::DomainPasswordDuplicatePasswordGroups,
            [PSWinDocumentation.ActiveDirectory]::DomainPasswordStats,
            [PSWinDocumentation.ActiveDirectory]::DomainPasswordHashesWeakPassword,
            [PSWinDocumentation.ActiveDirectory]::DomainPasswordHashesWeakPasswordEnabled,
            [PSWinDocumentation.ActiveDirectory]::DomainPasswordHashesWeakPasswordDisabled
        )) {
        Write-Verbose "Getting domain password information - $Domain DomainPasswordDataPasswords - This will take a while if set!"
        Write-Verbose "Getting domain password information - $Domain Passwords Path: $PathToPasswords"
        $TimeToProcess = Start-TimeLog
        $Data.DomainPasswordDataPasswords = Get-WinADDomainPasswordQuality `
            -FilePath $PathToPasswords `
            -DomainComputersAll $Data.DomainComputersAll `
            -DomainUsersAll $Data.DomainUsersAll `
            -DomainDistinguishedName $Data.DomainInformation.DistinguishedName `
            -DnsRoot $DomainInformation.DnsRoot `
            -Verbose:$false `
            -PasswordQualityUsers $Data.DomainPasswordDataUsers `
            -PasswordQuality:$PasswordQuality
        Write-Verbose "Getting domain password information - $Domain DomainPasswordDataPasswords - Time: $($TimeToProcess | Stop-TimeLog)"
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @(
            [PSWinDocumentation.ActiveDirectory]::DomainPasswordHashesWeakPassword,
            [PSWinDocumentation.ActiveDirectory]::DomainPasswordHashesWeakPasswordEnabled,
            [PSWinDocumentation.ActiveDirectory]::DomainPasswordHashesWeakPasswordDisabled
        )) {
        Write-Verbose "Getting domain password information - $Domain DomainPasswordDataPasswordsHashes - This will take a while if set!"
        Write-Verbose "Getting domain password information - $Domain Passwords Hashes Path: $PathToPasswordsHashes"
        $TimeToProcess = Start-TimeLog
        $Data.DomainPasswordDataPasswordsHashes = Get-WinADDomainPasswordQuality `
            -FilePath $PathToPasswordsHashes `
            -DomainComputersAll $Data.DomainComputersAll `
            -DomainUsersAll $Data.DomainUsersAll `
            -DomainDistinguishedName $Data.DomainInformation.DistinguishedName `
            -DnsRoot $DomainInformation.DnsRoot `
            -UseHashes `
            -Verbose:$false `
            -PasswordQualityUsers $Data.DomainPasswordDataUsers
        Write-Verbose "Getting domain password information - $Domain DomainPasswordDataPasswordsHashes - Time: $($TimeToProcess | Stop-TimeLog)"
    }
    if ($Data.DomainPasswordDataPasswords) {
        $PasswordsQuality = $Data.DomainPasswordDataPasswords
    } elseif ($Data.DomainPasswordDataPasswordsHashes) {
        $PasswordsQuality = $Data.DomainPasswordDataPasswordsHashes
    } else {
        $PasswordsQuality = $null
    }

    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @( [PSWinDocumentation.ActiveDirectory]::DomainPasswordClearTextPassword)) {
        Write-Verbose "Getting domain password information - $Domain DomainPasswordClearTextPassword"
        $Data.DomainPasswordClearTextPassword = $PasswordsQuality.DomainPasswordClearTextPassword
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @( [PSWinDocumentation.ActiveDirectory]::DomainPasswordLMHash)) {
        Write-Verbose "Getting domain password information - $Domain DomainPasswordLMHash"
        $Data.DomainPasswordLMHash = $PasswordsQuality.DomainPasswordLMHash
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @( [PSWinDocumentation.ActiveDirectory]::DomainPasswordEmptyPassword)) {
        Write-Verbose "Getting domain password information - $Domain DomainPasswordEmptyPassword"
        $Data.DomainPasswordEmptyPassword = $PasswordsQuality.DomainPasswordEmptyPassword
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @( [PSWinDocumentation.ActiveDirectory]::DomainPasswordWeakPassword)) {
        Write-Verbose "Getting domain password information - $Domain DomainPasswordWeakPassword"
        $Data.DomainPasswordWeakPassword = $Data.DomainPasswordDataPasswords.DomainPasswordWeakPassword
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @( [PSWinDocumentation.ActiveDirectory]::DomainPasswordWeakPasswordEnabled)) {
        Write-Verbose "Getting domain password information - $Domain DomainPasswordWeakPasswordEnabled"
        $Data.DomainPasswordWeakPasswordEnabled = $Data.DomainPasswordDataPasswords.DomainPasswordWeakPasswordEnabled
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @( [PSWinDocumentation.ActiveDirectory]::DomainPasswordWeakPasswordDisabled)) {
        Write-Verbose "Getting domain password information - $Domain DomainPasswordWeakPasswordDisabled"
        $Data.DomainPasswordWeakPasswordDisabled = $Data.DomainPasswordDataPasswords.DomainPasswordWeakPasswordDisabled
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @( [PSWinDocumentation.ActiveDirectory]::DomainPasswordWeakPasswordList)) {
        Write-Verbose "Getting domain password information - $Domain DomainPasswordWeakPasswordList"
        $Data.DomainPasswordWeakPasswordList = $Data.DomainPasswordDataPasswords.DomainPasswordWeakPasswordList
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @( [PSWinDocumentation.ActiveDirectory]::DomainPasswordDefaultComputerPassword)) {
        Write-Verbose "Getting domain password information - $Domain DomainPasswordDefaultComputerPassword"
        $Data.DomainPasswordDefaultComputerPassword = $PasswordsQuality.DomainPasswordDefaultComputerPassword
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @( [PSWinDocumentation.ActiveDirectory]::DomainPasswordPasswordNotRequired)) {
        Write-Verbose "Getting domain password information - $Domain DomainPasswordPasswordNotRequired"
        $Data.DomainPasswordPasswordNotRequired = $PasswordsQuality.DomainPasswordPasswordNotRequired
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @( [PSWinDocumentation.ActiveDirectory]::DomainPasswordPasswordNeverExpires)) {
        Write-Verbose "Getting domain password information - $Domain DomainPasswordPasswordNeverExpires"
        $Data.DomainPasswordPasswordNeverExpires = $PasswordsQuality.DomainPasswordPasswordNeverExpires
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @( [PSWinDocumentation.ActiveDirectory]::DomainPasswordAESKeysMissing)) {
        Write-Verbose "Getting domain password information - $Domain DomainPasswordAESKeysMissing"
        $Data.DomainPasswordAESKeysMissing = $PasswordsQuality.DomainPasswordAESKeysMissing
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @( [PSWinDocumentation.ActiveDirectory]::DomainPasswordPreAuthNotRequired)) {
        Write-Verbose "Getting domain password information - $Domain DomainPasswordPreAuthNotRequired"
        $Data.DomainPasswordPreAuthNotRequired = $PasswordsQuality.DomainPasswordPreAuthNotRequired
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @( [PSWinDocumentation.ActiveDirectory]::DomainPasswordDESEncryptionOnly)) {
        Write-Verbose "Getting domain password information - $Domain DomainPasswordDESEncryptionOnly"
        $Data.DomainPasswordDESEncryptionOnly = $PasswordsQuality.DomainPasswordDESEncryptionOnly
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @( [PSWinDocumentation.ActiveDirectory]::DomainPasswordDelegatableAdmins)) {
        Write-Verbose "Getting domain password information - $Domain DomainPasswordDelegatableAdmins"
        $Data.DomainPasswordDelegatableAdmins = $PasswordsQuality.DomainPasswordDelegatableAdmins
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @( [PSWinDocumentation.ActiveDirectory]::DomainPasswordDuplicatePasswordGroups)) {
        Write-Verbose "Getting domain password information - $Domain DomainPasswordDuplicatePasswordGroups"
        $Data.DomainPasswordDuplicatePasswordGroups = $PasswordsQuality.DomainPasswordDuplicatePasswordGroups
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @( [PSWinDocumentation.ActiveDirectory]::DomainPasswordHashesWeakPassword)) {
        Write-Verbose "Getting domain password information - $Domain DomainPasswordHashesWeakPassword"
        $Data.DomainPasswordHashesWeakPassword = $Data.DomainPasswordDataPasswordsHashes.DomainPasswordWeakPassword
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @( [PSWinDocumentation.ActiveDirectory]::DomainPasswordHashesWeakPasswordEnabled)) {
        Write-Verbose "Getting domain password information - $Domain DomainPasswordHashesWeakPasswordEnabled"
        $Data.DomainPasswordHashesWeakPasswordEnabled = $Data.DomainPasswordDataPasswordsHashes.DomainPasswordWeakPasswordEnabled
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @( [PSWinDocumentation.ActiveDirectory]::DomainPasswordHashesWeakPasswordDisabled)) {
        Write-Verbose "Getting domain password information - $Domain DomainPasswordHashesWeakPasswordDisabled"
        $Data.DomainPasswordHashesWeakPasswordDisabled = $Data.DomainPasswordDataPasswordsHashes.DomainPasswordWeakPasswordDisabled
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @( [PSWinDocumentation.ActiveDirectory]::DomainPasswordStats)) {
        Write-Verbose "Getting domain password information - $Domain DomainPasswordStats"
        $Data.DomainPasswordStats = Invoke-Command -ScriptBlock {
            $Stats = [ordered] @{ }
            $Stats.'Clear Text Passwords' = Get-ObjectCount -Object $PasswordsQuality.DomainPasswordClearTextPassword
            $Stats.'LM Hashes' = Get-ObjectCount -Object $PasswordsQuality.DomainPasswordLMHash
            $Stats.'Empty Passwords' = Get-ObjectCount -Object $PasswordsQuality.DomainPasswordEmptyPassword
            $Stats.'Weak Passwords' = Get-ObjectCount -Object $PasswordsQuality.DomainPasswordWeakPassword
            $Stats.'Weak Passwords Enabled' = Get-ObjectCount -Object $PasswordsQuality.DomainPasswordWeakPasswordEnabled
            $Stats.'Weak Passwords Disabled' = Get-ObjectCount -Object $PasswordsQuality.DomainPasswordWeakPasswordDisabled
            if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::DomainPasswordHashesWeakPassword)) {
                $Stats.'Weak Passwords (HASH)' = Get-ObjectCount -Object $Data.DomainPasswordDataPasswordsHashes.DomainPasswordHashesWeakPassword
            }
            if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::DomainPasswordHashesWeakPasswordEnabled)) {
                $Stats.'Weak Passwords (HASH) Enabled' = Get-ObjectCount -Object $Data.DomainPasswordDataPasswordsHashes.DomainPasswordHashesWeakPasswordEnabled
            }
            if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::DomainPasswordHashesWeakPasswordDisabled)) {
                $Stats.'Weak Passwords (HASH) Disabled' = Get-ObjectCount -Object $Data.DomainPasswordDataPasswordsHashes.DomainPasswordHashesWeakPasswordDisabled
            }
            $Stats.'Default Computer Passwords' = Get-ObjectCount -Object $PasswordsQuality.DomainPasswordDefaultComputerPassword
            $Stats.'Password Not Required' = Get-ObjectCount -Object $PasswordsQuality.DomainPasswordPasswordNotRequired
            $Stats.'Password Never Expires' = Get-ObjectCount -Object $PasswordsQuality.DomainPasswordPasswordNeverExpires
            $Stats.'AES Keys Missing' = Get-ObjectCount -Object $PasswordsQuality.DomainPasswordAESKeysMissing
            $Stats.'PreAuth Not Required' = Get-ObjectCount -Object $PasswordsQuality.DomainPasswordPreAuthNotRequired
            $Stats.'DES Encryption Only' = Get-ObjectCount -Object $PasswordsQuality.DomainPasswordDESEncryptionOnly
            $Stats.'Delegatable Admins' = Get-ObjectCount -Object $PasswordsQuality.DomainPasswordDelegatableAdmins
            $Stats.'Duplicate Password Users' = Get-ObjectCount -Object $PasswordsQuality.DomainPasswordDuplicatePasswordGroups
            $Stats.'Duplicate Password Grouped' = Get-ObjectCount ($PasswordsQuality.DomainPasswordDuplicatePasswordGroups.'Duplicate Group' | Sort-Object -Unique)
            return $Stats
        }
    }
    $EndTime = Stop-TimeLog -Time $TimeToGenerate
    Write-Verbose "Getting domain information - $Domain - Time to generate: $EndTime"
    return $Data
}
