<center>

[![PowerShellGallery Version](https://img.shields.io/powershellgallery/v/PSWinDocumentation.AD.svg)](https://www.powershellgallery.com/packages/PSWinDocumentation.AD)

[![PowerShellGallery Platform](https://img.shields.io/powershellgallery/p/PSWinDocumentation.AD.svg)](https://www.powershellgallery.com/packages/PSWinDocumentation.AD)
[![PowerShellGallery Preview Version](https://img.shields.io/powershellgallery/vpre/PSWinDocumentation.AD.svg?label=powershell%20gallery%20preview&colorB=yellow)](https://www.powershellgallery.com/packages/PSWinDocumentation.AD)

![Top Language](https://img.shields.io/github/languages/top/evotecit/PSWinDocumentation.AD.svg)
![Code](https://img.shields.io/github/languages/code-size/evotecit/PSWinDocumentation.AD.svg)
[![PowerShellGallery Downloads](https://img.shields.io/powershellgallery/dt/PSWinDocumentation.AD.svg)](https://www.powershellgallery.com/packages/PSWinDocumentation.AD)

</center>

# PSWinDocumentation.AD - PowerShell Module

`PSWinDocumentation.AD` is a Powershell module that has a single goal of getting Active Directory data

### Use cases described

- [x] [What do we say to writing Active Directory documentation?](https://evotec.xyz/what-do-we-say-to-writing-active-directory-documentation/)

### Install

```
Install-Module PSWinDocumentation.AD -Force
```

### Small code sample 1:

```powershell
$Forest = Get-WinADForestInformation -Verbose -PasswordQuality
$Forest
```

### Small code sample 2:

```powershell
$Forest = Get-WinADForestInformation -Verbose -PasswordQuality
$Forest.FoundDomains
$Forest.FoundDomains.'ad.evotec.xyz'
```

### Small code sample 3:

```powershell
$Forest = Get-WinADForestInformation -Verbose -PasswordQuality -DontRemoveSupportData -TypesRequired DomainGroups -Splitter "`r`n"
$Forest
```

### Datasets covered by PSWinDocumentation.AD

- [x] ForestInformation
- [x] ForestFSMO
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

- [x] HTML Version: https://evotec.xyz/wp-content/uploads/2019/05/DashboardActiveDirectory.html
- [x] DocX Version: https://evotec.xyz/wp-content/uploads/2019/05/Starter-AD.docx
- [x] Xlsx Version: https://evotec.xyz/wp-content/uploads/2019/05/Run-Demo02-1.xlsx