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
    if ([string]::IsNullOrEmpty($Domain)) {
        Write-Warning 'Get-WinADDomainInformation - $Domain parameter is empty. Try your domain name like ad.evotec.xyz. Skipping for now...'
        return
    }
    if ($null -eq $TypesRequired) {
        Write-Verbose 'Get-WinADDomainInformation - TypesRequired is null. Getting all.'
        $TypesRequired = Get-Types -Types ([PSWinDocumentation.ActiveDirectory])
    } # Gets all types
    $TimeToGenerate = Start-TimeLog

    # this is required to make sure certain properties are used in domain, such as LAPS, EXCHANGE and so on.
    # this prevents errors of asking for wrong property
    if ($null -eq $ForestSchemaComputers) {
        $ForestSchemaComputers = Get-WinADForestSchemaPropertiesComputers
    }
    if ($null -eq $ForestSchemaUsers) {
        $ForestSchemaUsers = Get-WinADForestSchemaPropertiesUsers
    }

    #$CurrentDate = Get-Date

    $Data = [ordered] @{ }
    $Data.DomainRootDSE = Get-WinADRootDSE -Domain $Domain
    Write-Verbose "Getting domain information - $Domain DomainInformation"
    $Data.DomainInformation = Get-WinADDomain -Domain $Domain
    if ($null -eq $Data.DomainInformation -or $null -eq $Data.DomainRootDSE) {
        return
    }

    $Data.DomainGroupsFullList = Get-WinADDomainGroupsFullList -Domain $Domain
    $Data.DomainUsersFullList = Get-WinADDomainUsersFullList -Domain $Domain -Extended:$Extended -ForestSchemaUsers $ForestSchemaUsers
    $Data.DomainComputersFullList = Get-WinADDomainComputersFullList -Domain $Domain -ForestSchemaComputers $ForestSchemaComputers

    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @(
            [PSWinDocumentation.ActiveDirectory]::DomainComputersAll,
            [PSWinDocumentation.ActiveDirectory]::DomainComputersAllCount,
            [PSWinDocumentation.ActiveDirectory]::DomainServers,
            [PSWinDocumentation.ActiveDirectory]::DomainServersCount,
            [PSWinDocumentation.ActiveDirectory]::DomainComputers,
            [PSWinDocumentation.ActiveDirectory]::DomainComputersCount,
            [PSWinDocumentation.ActiveDirectory]::DomainComputersUnknown,
            [PSWinDocumentation.ActiveDirectory]::DomainComputersUnknownCount
        )) {
        Write-Verbose "Getting domain information - $Domain DomainComputersAll"
        $Data.DomainComputersAll = $Data.DomainComputersFullList | Select-Object SamAccountName, Enabled, OperatingSystem, PasswordLastSet, IPv4Address, IPv6Address, Name, DNSHostName, ManagedBy, OperatingSystemVersion, OperatingSystemHotfix, OperatingSystemServicePack , PasswordNeverExpires, PasswordNotRequired, UserPrincipalName, LastLogonDate, LockedOut, LogonCount, CanonicalName, SID, Created, Modified, Deleted, MemberOf
    }
    if ($TypesRequired -contains [PSWinDocumentation.ActiveDirectory]::DomainComputersAllCount) {
        Write-Verbose "Getting domain information - $Domain DomainComputersAllCount"
        $Data.DomainComputersAllCount = $Data.DomainComputersAll | Group-Object -Property OperatingSystem | Select-Object @{ L = 'System Name'; Expression = { if ($_.Name -ne '') { $_.Name } else { 'Unknown' } } } , @{ L = 'System Count'; Expression = { $_.Count } }
    }
    if ($TypesRequired -contains [PSWinDocumentation.ActiveDirectory]::DomainServers) {
        Write-Verbose "Getting domain information - $Domain DomainServers"
        $Data.DomainServers = $Data.DomainComputersAll  | & { process { if ($_.OperatingSystem -like 'Windows Server*') { $_ } } } #| Where-Object { $_.OperatingSystem -like 'Windows Server*' }
    }
    if ($TypesRequired -contains [PSWinDocumentation.ActiveDirectory]::DomainServersCount) {
        Write-Verbose "Getting domain information - $Domain DomainServersCount"
        $Data.DomainServersCount = $Data.DomainServers | Group-Object -Property OperatingSystem | Select-Object @{ L = 'System Name'; Expression = { if ($_.Name -ne '') { $_.Name } else { 'N/A' } } } , @{ L = 'System Count'; Expression = { $_.Count } }
    }
    if ($TypesRequired -contains [PSWinDocumentation.ActiveDirectory]::DomainComputers) {
        Write-Verbose "Getting domain information - $Domain DomainComputers"
        $Data.DomainComputers = $Data.DomainComputersAll | & { process { if ($_.OperatingSystem -notlike 'Windows Server*' -and $null -ne $_.OperatingSystem) { $_ } } }   #    | Where-Object { $_.OperatingSystem -notlike 'Windows Server*' -and $_.OperatingSystem -ne $null }
    }
    if ($TypesRequired -contains [PSWinDocumentation.ActiveDirectory]::DomainComputersCount) {
        Write-Verbose "Getting domain information - $Domain DomainComputersCount"
        $Data.DomainComputersCount = $Data.DomainComputers | Group-Object -Property OperatingSystem | Select-Object @{ L = 'System Name'; Expression = { if ($_.Name -ne '') { $_.Name } else { 'N/A' } } } , @{ L = 'System Count'; Expression = { $_.Count } }
    }

    if ($TypesRequired -contains [PSWinDocumentation.ActiveDirectory]::DomainComputersUnknown) {
        Write-Verbose "Getting domain information - $Domain DomainComputersUnknown"
        $Data.DomainComputersUnknown = $Data.DomainComputersAll | & { process { if ( $null -eq $_.OperatingSystem ) { $_ } } } # | Where-Object { $_.OperatingSystem -eq $null }
    }
    if ($TypesRequired -contains [PSWinDocumentation.ActiveDirectory]::DomainComputersUnknownCount) {
        Write-Verbose "Getting domain information - $Domain DomainComputersUnknownCount"
        $Data.DomainComputersUnknownCount = $Data.DomainComputersUnknown | Group-Object -Property OperatingSystem | Select-Object @{ L = 'System Name'; Expression = { if ($_.Name -ne '') { $_.Name } else { 'Unknown' } } } , @{ L = 'System Count'; Expression = { $_.Count } }
    }

    if ($TypesRequired -contains [PSWinDocumentation.ActiveDirectory]::DomainRIDs) {
        $Data.DomainRIDs = Get-WinADDomainRIDs -DomainInformation $Data.DomainInformation -Domain $Domain
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired @([PSWinDocumentation.ActiveDirectory]::DomainGUIDS, [PSWinDocumentation.ActiveDirectory]::DomainOrganizationalUnitsBasicACL, [PSWinDocumentation.ActiveDirectory]::DomainOrganizationalUnitsExtended)) {
        $Data.DomainGUIDS = Get-WinADDomainGUIDs -RootDSE $Data.DomainRootDSE -Domain $Domain
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::DomainAuthenticationPolicies)) {
        Write-Verbose "Getting domain information - $Domain DomainAuthenticationPolicies"
        $Data.DomainAuthenticationPolicies = $(Get-ADAuthenticationPolicy -Server $Domain -LDAPFilter '(name=AuthenticationPolicy*)')
    }

    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::DomainAuthenticationPolicySilos)) {
        Write-Verbose "Getting domain information - $Domain DomainAuthenticationPolicySilos"
        $Data.DomainAuthenticationPolicySilos = $(Get-ADAuthenticationPolicySilo -Server $Domain -Filter 'Name -like "*AuthenticationPolicySilo*"')
    }

    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::DomainCentralAccessPolicies)) {
        Write-Verbose "Getting domain information - $Domain DomainCentralAccessPolicies"
        $Data.DomainCentralAccessPolicies = $(Get-ADCentralAccessPolicy -Server $Domain -Filter * )
    }

    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::DomainCentralAccessRules)) {
        Write-Verbose "Getting domain information - $Domain DomainCentralAccessRules"
        $Data.DomainCentralAccessRules = $(Get-ADCentralAccessRule -Server $Domain -Filter * )
    }

    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::DomainClaimTransformPolicies)) {
        Write-Verbose "Getting domain information - $Domain DomainClaimTransformPolicies"
        $Data.DomainClaimTransformPolicies = $(Get-ADClaimTransformPolicy -Server $Domain -Filter * )
    }

    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::DomainClaimTypes)) {
        Write-Verbose "Getting domain information - $Domain DomainClaimTypes"
        $Data.DomainClaimTypes = $(Get-ADClaimType -Server $Domain -Filter * )
    }

    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::DomainDNSSRV, [PSWinDocumentation.ActiveDirectory]::DomainDNSA )) {
        Write-Verbose "Getting domain information - $Domain DomainDNSSRV / DomainDNSA"
        $Data.DomainDNSData = Get-WinADDomainDNSData -Domain $Domain
        $Data.DomainDNSSrv = $Data.DomainDNSData.SRV
        $Data.DomainDNSA = $Data.DomainDNSData.A
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::DomainFSMO, [PSWinDocumentation.ActiveDirectory]::DomainTrusts, [PSWinDocumentation.ActiveDirectory]::DomainTrustsClean )) {
        $Data.DomainFSMO = Get-WinADDomainFSMO -Domain $Domain -DomainInformation $Data.DomainInformation
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::DomainTrustsClean, [PSWinDocumentation.ActiveDirectory]::DomainTrusts)) {
        $Data.DomainTrustsClean = Get-WinADDomainTrustsClean -Domain $Domain
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::DomainTrusts)) {
        $Data.DomainTrusts = Get-WinADDomainTrusts -DomainPDC $Data.DomainFSMO.'PDC Emulator' -Trusts $Data.DomainTrustsClean -Domain $Domain
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @(
            [PSWinDocumentation.ActiveDirectory]::DomainGroupPolicies,
            [PSWinDocumentation.ActiveDirectory]::DomainGroupPoliciesDetails,
            [PSWinDocumentation.ActiveDirectory]::DomainGroupPoliciesACL
        )) {
        Write-Verbose "Getting domain information - $Domain DomainGroupPolicies"
        $Data.DomainGroupPoliciesClean = $(Get-GPO -Domain $Domain -All)
        $Data.DomainGroupPolicies = foreach ($gpo in $Data.DomainGroupPoliciesClean) {
            [PSCustomObject][ordered] @{
                'Display Name'      = $gpo.DisplayName
                'Gpo Status'        = $gpo.GPOStatus
                'Creation Time'     = $gpo.CreationTime
                'Modification Time' = $gpo.ModificationTime
                'Description'       = $gpo.Description
                'Wmi Filter'        = $gpo.WmiFilter
            }
        }
        $Data.DomainGroupPoliciesDetails = Invoke-Command -ScriptBlock {
            Write-Verbose -Message "Getting domain information - $Domain Group Policies Details"
            $Output = ForEach ($GPO in $Data.DomainGroupPoliciesClean) {
                [xml]$XmlGPReport = $GPO.generatereport('xml')
                #GPO version
                if ($XmlGPReport.GPO.Computer.VersionDirectory -eq 0 -and $XmlGPReport.GPO.Computer.VersionSysvol -eq 0) { $ComputerSettings = "NeverModified" }else { $ComputerSettings = "Modified" }
                if ($XmlGPReport.GPO.User.VersionDirectory -eq 0 -and $XmlGPReport.GPO.User.VersionSysvol -eq 0) { $UserSettings = "NeverModified" }else { $UserSettings = "Modified" }
                #GPO content
                if ($null -eq $XmlGPReport.GPO.User.ExtensionData) { $UserSettingsConfigured = $false } else { $UserSettingsConfigured = $true }
                if ($null -eq $XmlGPReport.GPO.Computer.ExtensionData) { $ComputerSettingsConfigured = $false } else { $ComputerSettingsConfigured = $true }
                #Output
                [PSCustomObject][ordered] @{
                    'Name'                   = $XmlGPReport.GPO.Name
                    'Links'                  = $XmlGPReport.GPO.LinksTo | Select-Object -ExpandProperty SOMPath
                    'Has Computer Settings'  = $ComputerSettingsConfigured
                    'Has User Settings'      = $UserSettingsConfigured
                    'User Enabled'           = $XmlGPReport.GPO.User.Enabled
                    'Computer Enabled'       = $XmlGPReport.GPO.Computer.Enabled
                    'Computer Settings'      = $ComputerSettings
                    'User Settings'          = $UserSettings
                    'Gpo Status'             = $GPO.GpoStatus
                    'Creation Time'          = $GPO.CreationTime
                    'Modification Time'      = $GPO.ModificationTime
                    'WMI Filter'             = $GPO.WmiFilter.name
                    'WMI Filter Description' = $GPO.WmiFilter.Description
                    'Path'                   = $GPO.Path
                    'GUID'                   = $GPO.Id
                    'SDDL'                   = $XmlGPReport.GPO.SecurityDescriptor.SDDL.'#text'
                    #'ACLs'                   = $XmlGPReport.GPO.SecurityDescriptor.Permissions.TrusteePermissions | ForEach-Object -Process {
                    #    New-Object -TypeName PSObject -Property @{
                    #        'User'            = $_.trustee.name.'#Text'
                    #        'Permission Type' = $_.type.PermissionType
                    #        'Inherited'       = $_.Inherited
                    #        'Permissions'     = $_.Standard.GPOGroupedAccessEnum
                    #    }
                    #}
                }
            }
            return $Output
        }
        $Data.DomainGroupPoliciesACL = Invoke-Command -ScriptBlock {
            Write-Verbose -Message "Getting domain information - $Domain Group Policies ACLs"
            $Output = ForEach ($GPO in $Data.DomainGroupPoliciesClean) {
                [xml]$XmlGPReport = $GPO.generatereport('xml')
                $ACLs = $XmlGPReport.GPO.SecurityDescriptor.Permissions.TrusteePermissions
                foreach ($ACL in $ACLS) {
                    [PSCustomObject][ordered] @{
                        'GPO Name'        = $GPO.DisplayName
                        'User'            = $ACL.trustee.name.'#Text'
                        'Permission Type' = $ACL.type.PermissionType
                        'Inherited'       = $ACL.Inherited
                        'Permissions'     = $ACL.Standard.GPOGroupedAccessEnum
                    }
                }
            }
            return $Output
        }
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::DomainBitlocker)) {
        #$Data.DomainBitlocker = Get-WinADDomainBitlocker -Domain $Domain -Computers $Data.DomainComputersFullList
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::DomainLAPS)) {
        $Data.DomainLAPS = Get-WinADDomainLAPS -Domain $Domain -Computers $Data.DomainComputersFullList
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::DomainDefaultPasswordPolicy)) {
        Write-Verbose -Message "Getting domain information - $Domain DomainDefaultPasswordPolicy"
        $Data.DomainDefaultPasswordPolicy = Invoke-Command -ScriptBlock {
            $Policy = $(Get-ADDefaultDomainPasswordPolicy -Server $Domain)
            [ordered] @{
                'Complexity Enabled'            = $Policy.ComplexityEnabled
                'Lockout Duration'              = $Policy.LockoutDuration
                'Lockout Observation Window'    = $Policy.LockoutObservationWindow
                'Lockout Threshold'             = $Policy.LockoutThreshold
                'Max Password Age'              = $Policy.MaxPasswordAge
                'Min Password Length'           = $Policy.MinPasswordLength
                'Min Password Age'              = $Policy.MinPasswordAge
                'Password History Count'        = $Policy.PasswordHistoryCount
                'Reversible Encryption Enabled' = $Policy.ReversibleEncryptionEnabled
                'Distinguished Name'            = $Policy.DistinguishedName
            }
        }
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @(
            [PSWinDocumentation.ActiveDirectory]::DomainOrganizationalUnits,
            [PSWinDocumentation.ActiveDirectory]::DomainContainers,
            [PSWinDocumentation.ActiveDirectory]::DomainOrganizationalUnitsDN,
            [PSWinDocumentation.ActiveDirectory]::DomainOrganizationalUnitsACL,
            [PSWinDocumentation.ActiveDirectory]::DomainOrganizationalUnitsBasicACL,
            [PSWinDocumentation.ActiveDirectory]::DomainOrganizationalUnitsExtended
        )) {
        Write-Verbose -Message "Getting domain information - $Domain DomainOrganizationalUnits Clean"
        $Data.DomainOrganizationalUnitsClean = $(Get-ADOrganizationalUnit -Server $Domain -Properties * -Filter * )
        $Data.DomainOrganizationalUnits = Get-WinADDomainOrganizationalUnits -Domain $Domain -OrgnaizationalUnits $Data.DomainOrganizationalUnitsClean
        Write-Verbose -Message "Getting domain information - $Domain DomainOrganizationalUnitsDN"
        $Data.DomainOrganizationalUnitsDN = @(
            $Data.DomainInformation.DistinguishedName
            $Data.DomainOrganizationalUnitsClean.DistinguishedName
            $Data.DomainContainers.DistinguishedName
        )


        <#
        $OrganizationalUnitACL = Get-WinADDomainOrganizationalUnitsACL `
            -DomainOrganizationalUnitsClean $Data.DomainOrganizationalUnitsClean `
            -Domain $Domain `
            -NetBiosName $Data.DomainInformation.NetBIOSName
        #>

        $Data.DomainOrganizationalUnitsBasicACL = Get-WinADDomainOrganizationalUnitsACL  `
            -DomainOrganizationalUnitsClean $Data.DomainOrganizationalUnitsClean `
            -Domain $Domain `
            -NetBiosName $Data.DomainInformation.NetBIOSName `
            -RootDomainNamingContext $Data.DomainRootDSE.rootDomainNamingContext

        $Data.DomainOrganizationalUnitsExtended = Get-WinADDomainOrganizationalUnitsACLExtended  `
            -DomainOrganizationalUnitsClean $Data.DomainOrganizationalUnitsClean `
            -Domain $Domain `
            -NetBiosName $Data.DomainInformation.NetBIOSName `
            -RootDomainNamingContext $Data.DomainRootDSE.rootDomainNamingContext `
            -GUID $Data.DomainGUIDS
        #$null = $OrganizationalUnitACL # remove unneeded stuff

        #-DomainOrganizationalUnitsBasicACL $Data.DomainOrganizationalUnitsBasicACL `
        #-DomainOrganizationalUnitsExtended $Data.DomainOrganizationalUnitsExtended

        <#
        Write-Verbose -Message "Getting domain information - $Domain DomainOrganizationalUnitsACL"
        $Data.DomainOrganizationalUnitsACL = Invoke-Command -ScriptBlock {
            $ReportBasic = @()
            $ReportExtented = @()
            $OUs = @()
            #$OUs += @{ Name = 'Root'; Value = $Data.DomainRootDSE.rootDomainNamingContext }
            foreach ($OU in $Data.DomainOrganizationalUnitsClean) {
                $OUs += @{ Name = 'Organizational Unit'; Value = $OU.DistinguishedName }
                #Write-Verbose "1. $($Ou.DistinguishedName)"
            }
            #foreach ($OU in $Data.DomainContainers) {
            #    $OUs += @{ Name = 'Container'; Value = $OU.DistinguishedName }
            #    Write-Verbose "2. $($Ou.DistinguishedName)"
            #}
            $PSDriveName = $Data.DomainInformation.NetBIOSName
            New-PSDrive -Name $PSDriveName -Root "" -PsProvider ActiveDirectory -Server $Domain

            ForEach ($OU in $OUs) {
                #Write-Verbose "3. $($Ou.Value)"
                $ReportBasic += Get-Acl -Path "$PSDriveName`:\$($OU.Value)" | Select-Object `
                @{name = 'Distinguished Name'; expression = { $OU.Value } },
                @{name = 'Type'; expression = { $OU.Name } },
                @{name = 'Owner'; expression = { $_.Owner } },
                @{name = 'Group'; expression = { $_.Group } },
                @{name = 'Are AccessRules Protected'; expression = { $_.AreAccessRulesProtected } },
                @{name = 'Are AuditRules Protected'; expression = { $_.AreAuditRulesProtected } },
                @{name = 'Are AccessRules Canonical'; expression = { $_.AreAccessRulesCanonical } },
                @{name = 'Are AuditRules Canonical'; expression = { $_.AreAuditRulesCanonical } },
                @{name = 'Sddl'; expression = { $_.Sddl } }

                $ReportExtented += Get-Acl -Path "$PSDriveName`:\$($OU.Value)" | `
                    Select-Object -ExpandProperty Access | `
                    Select-Object `
                @{name = 'Distinguished Name'; expression = { $OU.Value } },
                @{name = 'Type'; expression = { $OU.Name } },
                @{name = 'AccessControlType'; expression = { $_.AccessControlType } },
                @{name = 'ObjectType Name'; expression = { if ($_.objectType.ToString() -eq '00000000-0000-0000-0000-000000000000') { 'All' } Else { $GUID.Item($_.objectType) } } },
                @{name = 'Inherited ObjectType Name'; expression = { $GUID.Item($_.inheritedObjectType) } },
                @{name = 'ActiveDirectoryRights'; expression = { $_.ActiveDirectoryRights } },
                @{name = 'InheritanceType'; expression = { $_.InheritanceType } },
                @{name = 'ObjectType'; expression = { $_.ObjectType } },
                @{name = 'InheritedObjectType'; expression = { $_.InheritedObjectType } },
                @{name = 'ObjectFlags'; expression = { $_.ObjectFlags } },
                @{name = 'IdentityReference'; expression = { $_.IdentityReference } },
                @{name = 'IsInherited'; expression = { $_.IsInherited } },
                @{name = 'InheritanceFlags'; expression = { $_.InheritanceFlags } },
                @{name = 'PropagationFlags'; expression = { $_.PropagationFlags } }


            }
            return @{ Basic = $ReportBasic; Extended = $ReportExtented }
        }
        Write-Verbose -Message "Getting domain information - $Domain DomainOrganizationalUnitsBasicACL"
        $Data.DomainOrganizationalUnitsBasicACL = $Data.DomainOrganizationalUnitsACL.Basic
        Write-Verbose -Message "Getting domain information - $Domain DomainOrganizationalUnitsExtended"
        $Data.DomainOrganizationalUnitsExtended = $Data.DomainOrganizationalUnitsACL.Extended
        #>
    }
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

        <#
        Write-Verbose "Getting domain information - $Domain DomainFineGrainedPoliciesUsersExtended"
        $Data.DomainFineGrainedPoliciesUsersExtended = Invoke-Command -ScriptBlock {
            $PolicyUsers = @()
            foreach ($Policy in $Data.DomainFineGrainedPolicies) {
                $Users = @()
                $Groups = @()
                foreach ($U in $Policy.'Applies To') {
                    $Users += Get-ADObjectFromDistingusishedName -ADCatalog $Data.DomainUsersFullList -DistinguishedName $U
                    $Groups += Get-ADObjectFromDistingusishedName -ADCatalog $Data.DomainGroupsFullList -DistinguishedName $U
                }
                foreach ($User in $Users) {
                    $PolicyUsers += [pscustomobject][ordered] @{
                        'Policy Name'                       = $Policy.Name
                        Name                                = $User.Name
                        SamAccountName                      = $User.SamAccountName
                        Type                                = $User.ObjectClass
                        SID                                 = $User.SID
                        'High Privileged Group'             = 'N/A'
                        'Display Name'                      = $User.DisplayName
                        'Member Name'                       = $Member.Name
                        'User Principal Name'               = $User.UserPrincipalName
                        'Sam Account Name'                  = $User.SamAccountName
                        'Email Address'                     = $User.EmailAddress
                        'PasswordExpired'                   = $User.PasswordExpired
                        'PasswordLastSet'                   = $User.PasswordLastSet
                        'PasswordNotRequired'               = $User.PasswordNotRequired
                        'PasswordNeverExpires'              = $User.PasswordNeverExpires
                        'Enabled'                           = $User.Enabled
                        'MemberSID'                         = $Member.SID.Value
                        'Manager'                           = (Get-ADObjectFromDistingusishedName -ADCatalog $Data.DomainUsersFullList -DistinguishedName $User.Manager).Name
                        'ManagerEmail'                      = (Get-ADObjectFromDistingusishedName -ADCatalog $Data.DomainUsersFullList -DistinguishedName $User.Manager).EmailAddress
                        'DateExpiry'                        = Convert-ToDateTime -Timestring $($Object."msDS-UserPasswordExpiryTimeComputed") # -Verbose
                        "DaysToExpire"                      = (Convert-TimeToDays -StartTime ($CurrentDate) -EndTime (Convert-ToDateTime -Timestring $($User."msDS-UserPasswordExpiryTimeComputed")))
                        "AccountExpirationDate"             = $User.AccountExpirationDate
                        "AccountLockoutTime"                = $User.AccountLockoutTime
                        "AllowReversiblePasswordEncryption" = $User.AllowReversiblePasswordEncryption
                        "BadLogonCount"                     = $User.BadLogonCount
                        "CannotChangePassword"              = $User.CannotChangePassword
                        "CanonicalName"                     = $User.CanonicalName
                        'Given Name'                        = $User.GivenName
                        'Surname'                           = $User.Surname
                        "Description"                       = $User.Description
                        "DistinguishedName"                 = $User.DistinguishedName
                        "EmployeeID"                        = $User.EmployeeID
                        "EmployeeNumber"                    = $User.EmployeeNumber
                        "LastBadPasswordAttempt"            = $User.LastBadPasswordAttempt
                        "LastLogonDate"                     = $User.LastLogonDate
                        "Created"                           = $User.Created
                        "Modified"                          = $User.Modified
                        "Protected"                         = $User.ProtectedFromAccidentalDeletion
                        "Domain"                            = $Domain
                    }
                }

                foreach ($Group in $Groups) {
                    $GroupMembership = Get-ADGroupMember -Server $Domain -Identity $Group.SID -Recursive
                    foreach ($Member in $GroupMembership) {
                        $Object = (Get-ADObjectFromDistingusishedName -ADCatalog $Data.DomainUsersFullList -DistinguishedName $Member.DistinguishedName)
                        $PolicyUsers += [pscustomobject][ordered] @{
                            'Policy Name'                       = $Policy.Name
                            Name                                = $Group.Name
                            SamAccountName                      = $Group.SamAccountName
                            Type                                = $Group.ObjectClass
                            SID                                 = $Group.SID
                            'High Privileged Group'             = if ($Group.adminCount -eq 1) { $True } else { $False }
                            'Display Name'                      = $Object.DisplayName
                            'Member Name'                       = $Member.Name
                            'User Principal Name'               = $Object.UserPrincipalName
                            'Sam Account Name'                  = $Object.SamAccountName
                            'Email Address'                     = $Object.EmailAddress
                            'PasswordExpired'                   = $Object.PasswordExpired
                            'PasswordLastSet'                   = $Object.PasswordLastSet
                            'PasswordNotRequired'               = $Object.PasswordNotRequired
                            'PasswordNeverExpires'              = $Object.PasswordNeverExpires
                            'Enabled'                           = $Object.Enabled
                            'MemberSID'                         = $Member.SID.Value
                            'Manager'                           = (Get-ADObjectFromDistingusishedName -ADCatalog $Data.DomainUsersFullList -DistinguishedName $Object.Manager).Name
                            'ManagerEmail'                      = (Get-ADObjectFromDistingusishedName -ADCatalog $Data.DomainUsersFullList -DistinguishedName $Object.Manager).EmailAddress
                            'DateExpiry'                        = Convert-ToDateTime -Timestring $($Object."msDS-UserPasswordExpiryTimeComputed") # -Verbose
                            "DaysToExpire"                      = (Convert-TimeToDays -StartTime ($CurrentDate) -EndTime (Convert-ToDateTime -Timestring $($Object."msDS-UserPasswordExpiryTimeComputed")))
                            "AccountExpirationDate"             = $Object.AccountExpirationDate
                            "AccountLockoutTime"                = $Object.AccountLockoutTime
                            "AllowReversiblePasswordEncryption" = $Object.AllowReversiblePasswordEncryption
                            "BadLogonCount"                     = $Object.BadLogonCount
                            "CannotChangePassword"              = $Object.CannotChangePassword
                            "CanonicalName"                     = $Object.CanonicalName
                            'Given Name'                        = $Object.GivenName
                            'Surname'                           = $Object.Surname
                            "Description"                       = $Object.Description
                            "DistinguishedName"                 = $Object.DistinguishedName
                            "EmployeeID"                        = $Object.EmployeeID
                            "EmployeeNumber"                    = $Object.EmployeeNumber
                            "LastBadPasswordAttempt"            = $Object.LastBadPasswordAttempt
                            "LastLogonDate"                     = $Object.LastLogonDate
                            "Created"                           = $Object.Created
                            "Modified"                          = $Object.Modified
                            "Protected"                         = $Object.ProtectedFromAccidentalDeletion
                            "Domain"                            = $Domain
                        }
                    }
                }


            }
            return $PolicyUsers
        }
         #>
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
