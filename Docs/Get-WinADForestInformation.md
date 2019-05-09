---
external help file: PSWinDocumentation.AD-help.xml
Module Name: PSWinDocumentation.AD
online version:
schema: 2.0.0
---

# Get-WinADForestInformation

## SYNOPSIS
{{ Fill in the Synopsis }}

## SYNTAX

```
Get-WinADForestInformation [[-TypesRequired] <ActiveDirectory[]>] [-RequireTypes] [[-PathToPasswords] <String>]
 [[-PathToPasswordsHashes] <String>] [-PasswordQuality] [-DontRemoveSupportData] [<CommonParameters>]
```

## DESCRIPTION
{{ Fill in the Description }}

## EXAMPLES

### Example 1
```powershell
PS C:\> {{ Add example code here }}
```

{{ Add example description here }}

## PARAMETERS

### -DontRemoveSupportData
{{ Fill DontRemoveSupportData Description }}

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -PasswordQuality
{{ Fill PasswordQuality Description }}

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -PathToPasswords
{{ Fill PathToPasswords Description }}

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -PathToPasswordsHashes
{{ Fill PathToPasswordsHashes Description }}

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -RequireTypes
{{ Fill RequireTypes Description }}

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -TypesRequired
{{ Fill TypesRequired Description }}

```yaml
Type: ActiveDirectory[]
Parameter Sets: (All)
Aliases:
Accepted values: ForestInformation, ForestFSMO, ForestGlobalCatalogs, ForestOptionalFeatures, ForestUPNSuffixes, ForestSPNSuffixes, ForestSites, ForestSites1, ForestSites2, ForestSubnets, ForestSubnets1, ForestSubnets2, ForestSiteLinks, ForestDomainControllers, ForestRootDSE, ForestSchemaPropertiesUsers, ForestSchemaPropertiesComputers, DomainRootDSE, DomainRIDs, DomainAuthenticationPolicies, DomainAuthenticationPolicySilos, DomainCentralAccessPolicies, DomainCentralAccessRules, DomainClaimTransformPolicies, DomainClaimTypes, DomainFineGrainedPolicies, DomainFineGrainedPoliciesUsers, DomainFineGrainedPoliciesUsersExtended, DomainGUIDS, DomainDNSSRV, DomainDNSA, DomainInformation, DomainControllers, DomainFSMO, DomainDefaultPasswordPolicy, DomainGroupPolicies, DomainGroupPoliciesDetails, DomainGroupPoliciesACL, DomainOrganizationalUnits, DomainOrganizationalUnitsBasicACL, DomainOrganizationalUnitsExtendedACL, DomainContainers, DomainTrustsClean, DomainTrusts, DomainBitlocker, DomainLAPS, DomainGroupsFullList, DomainGroups, DomainGroupsMembers, DomainGroupsMembersRecursive, DomainGroupsSpecial, DomainGroupsSpecialMembers, DomainGroupsSpecialMembersRecursive, DomainGroupsPriviliged, DomainGroupsPriviligedMembers, DomainGroupsPriviligedMembersRecursive, DomainUsersFullList, DomainUsers, DomainUsersCount, DomainUsersAll, DomainUsersSystemAccounts, DomainUsersNeverExpiring, DomainUsersNeverExpiringInclDisabled, DomainUsersExpiredInclDisabled, DomainUsersExpiredExclDisabled, DomainAdministrators, DomainAdministratorsRecursive, DomainEnterpriseAdministrators, DomainEnterpriseAdministratorsRecursive, DomainComputersFullList, DomainComputersAll, DomainComputersAllCount, DomainComputers, DomainComputersCount, DomainServers, DomainServersCount, DomainComputersUnknown, DomainComputersUnknownCount, DomainPasswordDataUsers, DomainPasswordDataPasswords, DomainPasswordDataPasswordsHashes, DomainPasswordClearTextPassword, DomainPasswordClearTextPasswordEnabled, DomainPasswordClearTextPasswordDisabled, DomainPasswordLMHash, DomainPasswordEmptyPassword, DomainPasswordWeakPassword, DomainPasswordWeakPasswordEnabled, DomainPasswordWeakPasswordDisabled, DomainPasswordWeakPasswordList, DomainPasswordDefaultComputerPassword, DomainPasswordPasswordNotRequired, DomainPasswordPasswordNeverExpires, DomainPasswordAESKeysMissing, DomainPasswordPreAuthNotRequired, DomainPasswordDESEncryptionOnly, DomainPasswordDelegatableAdmins, DomainPasswordDuplicatePasswordGroups, DomainPasswordHashesWeakPassword, DomainPasswordHashesWeakPasswordEnabled, DomainPasswordHashesWeakPasswordDisabled, DomainPasswordStats

Required: False
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None

## OUTPUTS

### System.Object
## NOTES

## RELATED LINKS
