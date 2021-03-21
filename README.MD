
<p align="center">
<a href="https://www.powershellgallery.com/packages/PSWinDocumentation.AD"><img src="https://img.shields.io/powershellgallery/v/PSWinDocumentation.AD.svg"></a>
<a href="https://www.powershellgallery.com/packages/PSWinDocumentation.AD"><img src="https://img.shields.io/powershellgallery/vpre/PSWinDocumentation.AD.svg?label=powershell%20gallery%20preview&colorB=yellow"></a>
</p>

<p align="center">
<a href="https://www.powershellgallery.com/packages/PSWinDocumentation.AD"><img src="https://img.shields.io/powershellgallery/p/PSWinDocumentation.AD.svg"></a>
<a href="https://github.com/EvotecIT/PSWinDocumentation.AD"><img src="https://img.shields.io/github/languages/top/evotecit/PSWinDocumentation.AD.svg"></a>
<a href="https://github.com/EvotecIT/PSWinDocumentation.AD"><img src="https://img.shields.io/github/languages/code-size/evotecit/PSWinDocumentation.AD.svg"></a>
<a href="https://github.com/EvotecIT/PSWinDocumentation.AD"><img src="https://img.shields.io/powershellgallery/dt/PSWinDocumentation.AD.svg"></a>
</p>

# PSWinDocumentation.AD - PowerShell Module

`PSWinDocumentation.AD` is a Powershell module that has a single goal of getting Active Directory data

### Use cases described

- [x] [What do we say to writing Active Directory documentation?](https://evotec.xyz/what-do-we-say-to-writing-active-directory-documentation/)

### ChangeLog

- 0.1.20 - 2021.03.21
  - [x] Few fixes to get it up and running

- 0.1.19 - 31.08.2020
  - Types
    - [x] Added `DomainWellKnownFolders`
    - [x] Added `DomainGroupPoliciesACLConsistency`
    - [x] Added `DomainGroupPoliciesSysVol`
    - [x] Added `DomainGroupPoliciesOwners`
    - [x] Added `DomainGroupPoliciesWMI`
    - [x] Added `DomainGroupPoliciesLinksSummary`
- 0.1.8 - 22.06.2020
  - [x] Fix for PasswordQuality and support for DSInternals 4.3
    - [ ] At some point DSInternals was updated with different output and I didn't notice.
  - [x] Improved PasswordQuality speed (conversion to hashtables)
  - [x] Removed some dead code
  - [x] Added `Invoke-ADPasswordAnalysis` to simplify PasswordQuality

- 0.1.7 - 20.08.2019
  - [x] Added ForestRoles (FSMO different)
  - [x] Modified ForestSites, ForestSites1, ForestSites2
- 0.1.6 - 8.07.2019
  - [x] Get-WinADForestReplicationPartnerMetaData - error optimizations
  - [x] Updated DSInternals to 3.6

- 0.1.5 - 23.06.2019
  - [x] ForestOptionalFeatures
    - Added LAPS detection in Optional Features
  - [x] DomainGroupsPriviliged
    - Wouldn't work when asked just for this value
  - Removed [ordered] from [PSCustomObject] - not needed
  - Started fixing Enum values so that they are immune to Import-CliXML issues
  - Updated support for DSInternals 3.5
  - Updated support for PSSharedGoods 0.0.79

- 0.1.4 - 1.06.2019
  - Added ForestReplication data set (thanx Ronnie Smith)

- 0.1.3 - 31.05.2019
  - Small changes to Default Password Policy Output (converted TimeSpan into Days/Minutes)

- 0.1.1 - 28.05.2019
  - Peformance update (up to 10x faster in larger domains)
  - Small tweaks

- 0.0.7 - 12.05.2019
  - First public release

### Install

```
Install-Module PSWinDocumentation.AD -Force
```

### Datasets covered by PSWinDocumentation.AD

- [x] ForestInformation
- [x] ForestFSMO
- [ ] ForestRoles
- [x] ForestGlobalCatalogs
- [x] ForestOptionalFeatures
- [x] ForestUPNSuffixes
- [x] ForestSPNSuffixes
- [x] ForestSites
- [x] ForestSites1
- [x] ForestSites2
- [x] ForestSubnets
- [x] ForestSubnets1
- [x] ForestSubnets2
- [x] ForestSiteLinks
- [x] ForestDomainControllers
- [x] ForestRootDSE
- [x] ForestSchemaPropertiesUsers
- [x] ForestSchemaPropertiesComputers
- [x] DomainRootDSE
- [x] DomainRIDs
- [x] DomainAuthenticationPolicies
- [x] DomainAuthenticationPolicySilos
- [x] DomainCentralAccessPolicies
- [x] DomainCentralAccessRules
- [x] DomainClaimTransformPolicies
- [x] DomainClaimTypes
- [x] DomainFineGrainedPolicies
- [x] DomainFineGrainedPoliciesUsers
- [x] DomainFineGrainedPoliciesUsersExtended
- [x] DomainGUIDS
- [x] DomainDNSSRV
- [x] DomainDNSA
- [x] DomainInformation
- [x] DomainControllers
- [x] DomainFSMO
- [x] DomainDefaultPasswordPolicy
- [x] DomainGroupPolicies
- [x] DomainGroupPoliciesDetails
- [x] DomainGroupPoliciesACL
- [x] DomainOrganizationalUnits
- [x] DomainOrganizationalUnitsBasicACL
- [x] DomainOrganizationalUnitsExtendedACL
- [x] DomainContainers
- [x] DomainTrustsClean
- [x] DomainTrusts
- [x] DomainBitlocker
- [x] DomainLAPS
- [x] DomainGroupsFullList
- [x] DomainGroups
- [x] DomainGroupsMembers
- [x] DomainGroupsMembersRecursive
- [x] DomainGroupsSpecial
- [x] DomainGroupsSpecialMembers
- [x] DomainGroupsSpecialMembersRecursive
- [x] DomainGroupsPriviliged
- [x] DomainGroupsPriviligedMembers
- [x] DomainGroupsPriviligedMembersRecursive
- [x] DomainUsersFullList
- [x] DomainUsers
- [x] DomainUsersCount
- [x] DomainUsersAll
- [x] DomainUsersSystemAccounts
- [x] DomainUsersNeverExpiring
- [x] DomainUsersNeverExpiringInclDisabled
- [x] DomainUsersExpiredInclDisabled
- [x] DomainUsersExpiredExclDisabled
- [x] DomainAdministrators
- [x] DomainAdministratorsRecursive
- [x] DomainEnterpriseAdministrators
- [x] DomainEnterpriseAdministratorsRecursive
- [x] DomainComputersFullList
- [x] DomainComputersAll
- [x] DomainComputersAllCount
- [x] DomainComputers
- [x] DomainComputersCount
- [x] DomainServers
- [x] DomainServersCount
- [x] DomainComputersUnknown
- [x] DomainComputersUnknownCount
- [x] DomainPasswordDataUsers
- [x] DomainPasswordDataPasswords
- [x] DomainPasswordDataPasswordsHashes
- [x] DomainPasswordClearTextPassword
- [x] DomainPasswordClearTextPasswordEnabled
- [x] DomainPasswordClearTextPasswordDisabled
- [x] DomainPasswordLMHash
- [x] DomainPasswordEmptyPassword
- [x] DomainPasswordWeakPassword
- [x] DomainPasswordWeakPasswordEnabled
- [x] DomainPasswordWeakPasswordDisabled
- [x] DomainPasswordWeakPasswordList
- [x] DomainPasswordDefaultComputerPassword
- [x] DomainPasswordPasswordNotRequired
- [x] DomainPasswordPasswordNeverExpires
- [x] DomainPasswordAESKeysMissing
- [x] DomainPasswordPreAuthNotRequired
- [x] DomainPasswordDESEncryptionOnly
- [x] DomainPasswordDelegatableAdmins
- [x] DomainPasswordDuplicatePasswordGroups
- [x] DomainPasswordHashesWeakPassword
- [x] DomainPasswordHashesWeakPasswordEnabled
- [x] DomainPasswordHashesWeakPasswordDisabled
- [x] DomainPasswordStats

Example outputs:

- [x] HTML Version: <https://evotec.xyz/wp-content/uploads/2019/05/DashboardActiveDirectory.html>
- [x] DocX Version: <https://evotec.xyz/wp-content/uploads/2019/05/Starter-AD.docx>
- [x] Xlsx Version: <https://evotec.xyz/wp-content/uploads/2019/05/Run-Demo02-1.xlsx>

### Small code sample 1

```powershell
$Forest = Get-WinADForestInformation -Verbose -PasswordQuality
$Forest
```

### Small code sample 2

```powershell
$Forest = Get-WinADForestInformation -Verbose -PasswordQuality
$Forest.FoundDomains
$Forest.FoundDomains.'ad.evotec.xyz'
```

### Small code sample 3

```powershell
$Forest = Get-WinADForestInformation -Verbose -PasswordQuality -DontRemoveSupportData -TypesRequired DomainGroups -Splitter "`r`n"
$Forest
```

### Example output while running

```powershell
VERBOSE: Loading module from path 'C:\Program Files\WindowsPowerShell\Modules\PSWinDocumentation.AD\0.0.8\PSWinDocumentation.AD.psd1'.
VERBOSE: Populating RepositorySourceLocation property for module PSWinDocumentation.AD.
VERBOSE: Loading module from path 'C:\Program Files\WindowsPowerShell\Modules\PSWinDocumentation.AD\0.0.8\PSWinDocumentation.AD.psm1'.
VERBOSE: Importing function 'Get-WinADDomainInformation'.
VERBOSE: Importing function 'Get-WinADForestInformation'.
VERBOSE: Getting all information - Start
VERBOSE: Getting forest information - Start
VERBOSE: Getting forest information - TypesRequired is null. Getting all.
VERBOSE: Getting forest information - ForestRootDSE
VERBOSE: Getting forest information - ForestRootDSE - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 21 milliseconds
VERBOSE: Getting forest information - Forest
VERBOSE: Getting forest information - Forest - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 13 milliseconds
VERBOSE: Getting forest information - ForestSchemaPropertiesComputers
VERBOSE: Getting forest information - ForestSchemaPropertiesComputers - Time: 0 days, 0 hours, 0 minutes, 1 seconds, 369 milliseconds
VERBOSE: Getting forest information - ForestSchemaPropertiesUsers
VERBOSE: Getting forest information - ForestSchemaPropertiesUsers - Time: 0 days, 0 hours, 0 minutes, 1 seconds, 242 milliseconds
VERBOSE: Getting forest information - ForestUPNSuffixes
VERBOSE: Getting forest information - ForestUPNSuffixes - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 8 milliseconds
VERBOSE: Getting forest information - ForestSPNSuffixes
VERBOSE: Getting forest information - ForestSPNSuffixes - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 6 milliseconds
VERBOSE: Getting forest information - ForestGlobalCatalogs
VERBOSE: Getting forest information - ForestGlobalCatalogs - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 5 milliseconds
VERBOSE: Getting forest information - ForestFSMO
VERBOSE: Getting forest information - ForestFSMO - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 7 milliseconds
VERBOSE: Getting forest information - ForestDomainControllers
VERBOSE: Getting forest information - ForestDomainControllers - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 106 milliseconds
VERBOSE: Getting forest information - ForestSites
VERBOSE: Getting forest information - ForestSites - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 49 milliseconds
VERBOSE: Getting forest information - ForestSites1
VERBOSE: Getting forest information - ForestSites1 - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 11 milliseconds
VERBOSE: Getting forest information - ForestSites2
VERBOSE: Getting forest information - ForestSites2 - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 7 milliseconds
VERBOSE: Getting forest information - ForestSubnets
VERBOSE: Getting forest information - ForestSubnets - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 12 milliseconds
VERBOSE: Getting forest information - ForestSubnets1
VERBOSE: Getting forest information - ForestSubnets1 - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 6 milliseconds
VERBOSE: Getting forest information - ForestSubnets2
VERBOSE: Getting forest information - ForestSubnets2 - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 11 milliseconds
VERBOSE: Getting forest information - ForestSiteLinks
VERBOSE: Getting forest information - ForestSiteLinks - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 14 milliseconds
VERBOSE: Getting forest information - ForestOptionalFeatures
VERBOSE: Getting forest information - ForestOptionalFeatures - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 14 milliseconds
VERBOSE: Getting forest information - Domains
VERBOSE: Getting domain information - TestDomain.pl DomainRootDSE
VERBOSE: Getting domain information - TestDomain.pl DomainRootDSE - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 17 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainInformation
VERBOSE: Getting domain information - TestDomain.pl DomainInformation - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 63 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainGroupsFullList
VERBOSE: Getting domain information - TestDomain.pl DomainGroupsFullList - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 964 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainUsersFullList
VERBOSE: Getting domain information - TestDomain.pl DomainUsersFullList - Time: 0 days, 0 hours, 0 minutes, 20 seconds, 622 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainComputersFullList
VERBOSE: Getting domain information - TestDomain.pl DomainComputersFullList - Time: 0 days, 0 hours, 0 minutes, 21 seconds, 758 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainComputersAll
VERBOSE: Getting domain information - TestDomain.pl DomainComputersAll - Time: 0 days, 0 hours, 0 minutes, 39 seconds, 450 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainComputersAllCount
VERBOSE: Getting domain information - TestDomain.pl DomainComputersAllCount - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 73 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainServers
VERBOSE: Getting domain information - TestDomain.pl DomainServers - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 21 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainServersCount
VERBOSE: Getting domain information - TestDomain.pl DomainServersCount - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 68 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainComputers
VERBOSE: Getting domain information - TestDomain.pl DomainComputers - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 44 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainComputersCount
VERBOSE: Getting domain information - TestDomain.pl DomainComputersCount - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 39 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainComputersUnknown
VERBOSE: Getting domain information - TestDomain.pl DomainComputersUnknown - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 20 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainComputersUnknownCount
VERBOSE: Getting domain information - TestDomain.pl DomainComputersUnknownCount - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 11 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainRIDs
VERBOSE: Getting domain information - TestDomain.pl DomainRIDs - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 38 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainGUIDS
VERBOSE: Getting domain information - TestDomain.pl DomainGUIDS - Time: 0 days, 0 hours, 0 minutes, 3 seconds, 579 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainAuthenticationPolicies
VERBOSE: Getting domain information - TestDomain.pl DomainAuthenticationPolicies - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 27 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainAuthenticationPolicySilos
VERBOSE: Getting domain information - TestDomain.pl DomainAuthenticationPolicySilos - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 29 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainCentralAccessPolicies
VERBOSE: Getting domain information - TestDomain.pl DomainCentralAccessPolicies - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 22 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainCentralAccessRules
VERBOSE: Getting domain information - TestDomain.pl DomainCentralAccessRules - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 34 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainClaimTransformPolicies
VERBOSE: Getting domain information - TestDomain.pl DomainClaimTransformPolicies - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 25 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainClaimTypes
VERBOSE: Getting domain information - TestDomain.pl DomainClaimTypes - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 43 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainDNSData
VERBOSE: Getting domain information - TestDomain.pl DomainDNSData - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 15 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainDNSSrv
VERBOSE: Getting domain information - TestDomain.pl DomainDNSSrv - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 6 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainDNSA
VERBOSE: Getting domain information - TestDomain.pl DomainDNSA - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 5 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainFSMO
VERBOSE: Getting domain information - TestDomain.pl DomainFSMO - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 6 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainTrustsClean
VERBOSE: Getting domain information - TestDomain.pl DomainTrustsClean - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 36 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainTrusts
VERBOSE: Getting domain information - TestDomain.pl DomainTrusts - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 46 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainGroupPoliciesClean
VERBOSE: Getting domain information - TestDomain.pl DomainGroupPoliciesClean - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 48 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainGroupPolicies
VERBOSE: Getting domain information - TestDomain.pl DomainGroupPolicies - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 479 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainGroupPoliciesDetails
VERBOSE: Getting domain information - TestDomain.pl DomainGroupPoliciesDetails - Time: 0 days, 0 hours, 0 minutes, 16 seconds, 881 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainGroupPoliciesACL
VERBOSE: Getting domain information - TestDomain.pl DomainGroupPoliciesACL - Time: 0 days, 0 hours, 0 minutes, 11 seconds, 496 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainBitlocker
VERBOSE: Getting domain information - TestDomain.pl DomainBitlocker - Time: 0 days, 0 hours, 0 minutes, 7 seconds, 889 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainLAPS
VERBOSE: Getting domain information - TestDomain.pl DomainLAPS - Time: 0 days, 0 hours, 0 minutes, 2 seconds, 434 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainDefaultPasswordPolicy
VERBOSE: Getting domain information - TestDomain.pl DomainDefaultPasswordPolicy - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 35 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainOrganizationalUnitsClean
VERBOSE: Getting domain information - TestDomain.pl DomainOrganizationalUnitsClean - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 126 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainOrganizationalUnits
VERBOSE: Getting domain information - TestDomain.pl DomainOrganizationalUnits - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 59 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainOrganizationalUnitsBasicACL
VERBOSE: Getting domain information - TestDomain.pl DomainOrganizationalUnitsBasicACL - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 950 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainOrganizationalUnitsExtendedACL
VERBOSE: Getting domain information - TestDomain.pl DomainOrganizationalUnitsExtendedACL - Time: 0 days, 0 hours, 0 minutes, 1 seconds, 290 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainUsers
VERBOSE: Getting domain information - TestDomain.pl DomainUsers - Time: 0 days, 0 hours, 0 minutes, 44 seconds, 843 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainUsersAll
VERBOSE: Getting domain information - TestDomain.pl DomainUsersAll - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 25 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainUsersSystemAccounts
VERBOSE: Getting domain information - TestDomain.pl DomainUsersSystemAccounts - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 13 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainUsersNeverExpiring
VERBOSE: Getting domain information - TestDomain.pl DomainUsersNeverExpiring - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 25 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainUsersNeverExpiringInclDisabled
VERBOSE: Getting domain information - TestDomain.pl DomainUsersNeverExpiringInclDisabled - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 21 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainUsersExpiredInclDisabled
VERBOSE: Getting domain information - TestDomain.pl DomainUsersExpiredInclDisabled - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 22 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainUsersExpiredExclDisabled
VERBOSE: Getting domain information - TestDomain.pl DomainUsersExpiredExclDisabled - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 41 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainUsersCount
VERBOSE: Getting domain information - TestDomain.pl DomainUsersCount - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 12 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainControllers
VERBOSE: Getting domain information - TestDomain.pl DomainControllers - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 54 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainFineGrainedPolicies
VERBOSE: Getting domain information - TestDomain.pl DomainFineGrainedPolicies - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 29 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainFineGrainedPoliciesUsers
VERBOSE: Getting domain information - TestDomain.pl DomainFineGrainedPoliciesUsers - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 12 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainFineGrainedPoliciesUsersExtended
VERBOSE: Getting domain information - TestDomain.pl DomainFineGrainedPoliciesUsersExtended - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 10 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainGroups
VERBOSE: Getting domain information - TestDomain.pl DomainGroups - Time: 0 days, 0 hours, 0 minutes, 23 seconds, 920 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainGroupsMembers
VERBOSE: Getting domain information - TestDomain.pl DomainGroupsMembers - Time: 0 days, 0 hours, 0 minutes, 39 seconds, 399 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainGroupsMembersRecursive
VERBOSE: Getting domain information - TestDomain.pl DomainGroupsMembersRecursive - Time: 0 days, 0 hours, 1 minutes, 54 seconds, 350 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainGroupsPriviliged
VERBOSE: Getting domain information - TestDomain.pl DomainGroupsPriviliged - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 12 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainGroupsSpecial
VERBOSE: Getting domain information - TestDomain.pl DomainGroupsSpecial - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 16 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainGroupsSpecialMembers
VERBOSE: Getting domain information - TestDomain.pl DomainGroupsSpecialMembers - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 298 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainGroupsSpecialMembersRecursive
VERBOSE: Getting domain information - TestDomain.pl DomainGroupsSpecialMembersRecursive - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 417 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainGroupsPriviligedMembers
VERBOSE: Getting domain information - TestDomain.pl DomainGroupsPriviligedMembers - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 493 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainGroupsPriviligedMembersRecursive
VERBOSE: Getting domain information - TestDomain.pl DomainGroupsPriviligedMembersRecursive - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 751 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainAdministrators
VERBOSE: Getting domain information - TestDomain.pl DomainAdministrators - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 482 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainAdministratorsRecursive
VERBOSE: Getting domain information - TestDomain.pl DomainAdministratorsRecursive - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 743 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainEnterpriseAdministrators
VERBOSE: Getting domain information - TestDomain.pl DomainEnterpriseAdministrators - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 471 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainEnterpriseAdministratorsRecursive
VERBOSE: Getting domain information - TestDomain.pl DomainEnterpriseAdministratorsRecursive - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 753 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainPasswordDataUsers
VERBOSE: Getting domain information - TestDomain.pl DomainPasswordDataUsers - Time: 0 days, 0 hours, 0 minutes, 8 seconds, 110 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainPasswordDataPasswords
VERBOSE: Getting domain information - TestDomain.pl DomainPasswordDataPasswords - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 9 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainPasswordDataPasswordsHashes
VERBOSE: Getting domain information - TestDomain.pl DomainPasswordDataPasswordsHashes - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 6 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainPasswordClearTextPassword
VERBOSE: Getting domain information - TestDomain.pl DomainPasswordClearTextPassword - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 6 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainPasswordLMHash
VERBOSE: Getting domain information - TestDomain.pl DomainPasswordLMHash - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 5 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainPasswordEmptyPassword
VERBOSE: Getting domain information - TestDomain.pl DomainPasswordEmptyPassword - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 5 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainPasswordEmptyPassword
VERBOSE: Getting domain information - TestDomain.pl DomainPasswordEmptyPassword - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 1 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainPasswordWeakPassword
VERBOSE: Getting domain information - TestDomain.pl DomainPasswordWeakPassword - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 5 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainPasswordWeakPasswordEnabled
VERBOSE: Getting domain information - TestDomain.pl DomainPasswordWeakPasswordEnabled - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 6 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainPasswordWeakPasswordDisabled
VERBOSE: Getting domain information - TestDomain.pl DomainPasswordWeakPasswordDisabled - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 6 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainPasswordWeakPasswordList
VERBOSE: Getting domain information - TestDomain.pl DomainPasswordWeakPasswordList - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 5 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainPasswordDefaultComputerPassword
VERBOSE: Getting domain information - TestDomain.pl DomainPasswordDefaultComputerPassword - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 5 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainPasswordPasswordNotRequired
VERBOSE: Getting domain information - TestDomain.pl DomainPasswordPasswordNotRequired - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 9 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainPasswordPasswordNeverExpires
VERBOSE: Getting domain information - TestDomain.pl DomainPasswordPasswordNeverExpires - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 6 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainPasswordAESKeysMissing
VERBOSE: Getting domain information - TestDomain.pl DomainPasswordAESKeysMissing - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 6 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainPasswordPreAuthNotRequired
VERBOSE: Getting domain information - TestDomain.pl DomainPasswordPreAuthNotRequired - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 5 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainPasswordDESEncryptionOnly
VERBOSE: Getting domain information - TestDomain.pl DomainPasswordDESEncryptionOnly - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 6 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainPasswordDelegatableAdmins
VERBOSE: Getting domain information - TestDomain.pl DomainPasswordDelegatableAdmins - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 8 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainPasswordDuplicatePasswordGroups
VERBOSE: Getting domain information - TestDomain.pl DomainPasswordDuplicatePasswordGroups - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 7 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainPasswordHashesWeakPassword
VERBOSE: Getting domain information - TestDomain.pl DomainPasswordHashesWeakPassword - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 6 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainPasswordHashesWeakPasswordEnabled
VERBOSE: Getting domain information - TestDomain.pl DomainPasswordHashesWeakPasswordEnabled - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 5 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainPasswordHashesWeakPasswordDisabled
VERBOSE: Getting domain information - TestDomain.pl DomainPasswordHashesWeakPasswordDisabled - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 5 milliseconds
VERBOSE: Getting domain information - TestDomain.pl DomainPasswordStats
VERBOSE: Getting domain information - TestDomain.pl DomainPasswordStats - Time: 0 days, 0 hours, 0 minutes, 0 seconds, 23 milliseconds
VERBOSE: Getting domain information - TestDomain.pl - Time to generate: 0 days, 0 hours, 6 minutes, 4 seconds, 935 milliseconds
VERBOSE: Getting forest information - Domains - Time: 0 days, 0 hours, 6 minutes, 4 seconds, 973 milliseconds
VERBOSE: Getting forest information - Stop - Time to generate: 0 days, 0 hours, 0 minutes, 3 seconds, 43 milliseconds
VERBOSE: Getting all information - Stop - Time to generate: 0 days, 0 hours, 6 minutes, 8 seconds, 62 milliseconds
```
