Add-Type -TypeDefinition @"
    using System;

    namespace PSWinDocumentation
    {
        [Flags]
        public enum ActiveDirectory {
            // Forest Information - Section Main
            ForestInformation,
            ForestFSMO,
            ForestRoles,
            ForestGlobalCatalogs,
            ForestOptionalFeatures,
            ForestUPNSuffixes,
            ForestSPNSuffixes,
            ForestSites,
            ForestSites1,
            ForestSites2,
            ForestSubnets,
            ForestSubnets1,
            ForestSubnets2,
            ForestSiteLinks,
            ForestDomainControllers,
            ForestRootDSE,
            ForestSchemaPropertiesUsers,
            ForestSchemaPropertiesComputers,
            ForestReplication,

            // Domain Information - Section Main
            DomainRootDSE,
            DomainRIDs,
            DomainAuthenticationPolicies, // Not yet tested
            DomainAuthenticationPolicySilos, // Not yet tested
            DomainCentralAccessPolicies, // Not yet tested
            DomainCentralAccessRules, // Not yet tested
            DomainClaimTransformPolicies, // Not yet tested
            DomainClaimTypes, // Not yet tested
            DomainFineGrainedPolicies,
            DomainFineGrainedPoliciesUsers,
            DomainFineGrainedPoliciesUsersExtended,
            DomainGUIDS,
            DomainDNSSRV,
            DomainDNSA,
            DomainInformation,
            DomainControllers,
            DomainFSMO,
            DomainDefaultPasswordPolicy,
            DomainGroupPolicies,
            DomainGroupPoliciesDetails,
            DomainGroupPoliciesACL,
            DomainGroupPoliciesACLConsistency,
            DomainGroupPoliciesSysVol,
            DomainGroupPoliciesOwners,
            DomainGroupPoliciesWMI,
            DomainGroupPoliciesLinksSummary,
            DomainOrganizationalUnits,
            DomainOrganizationalUnitsBasicACL,
            DomainOrganizationalUnitsExtendedACL,
            DomainContainers,
            DomainTrustsClean,
            DomainTrusts,

            DomainWellKnownFolders,

            DomainBitlocker,
            DomainLAPS,

            // Domain Information - Group Data
            DomainGroupsFullList, // Contains all data

            DomainGroups,
            DomainGroupsMembers,
            DomainGroupsMembersRecursive,

            DomainGroupsSpecial,
            DomainGroupsSpecialMembers,
            DomainGroupsSpecialMembersRecursive,

            DomainGroupsPriviliged,
            DomainGroupsPriviligedMembers,
            DomainGroupsPriviligedMembersRecursive,

            // Domain Information - User Data
            DomainUsersFullList, // Contains all data
            DomainUsers,
            DomainUsersCount,
            DomainUsersAll,
            DomainUsersSystemAccounts,
            DomainUsersNeverExpiring,
            DomainUsersNeverExpiringInclDisabled,
            DomainUsersExpiredInclDisabled,
            DomainUsersExpiredExclDisabled,
            DomainAdministrators,
            DomainAdministratorsRecursive,
            DomainEnterpriseAdministrators,
            DomainEnterpriseAdministratorsRecursive,

            // Domain Information - Computer Data
            DomainComputersFullList, // Contains all data
            DomainComputersAll,
            DomainComputersAllBuildCount,
            DomainComputersAllCount,
            DomainComputers,
            DomainComputersCount,
            DomainServers,
            DomainServersCount,
            DomainComputersUnknown,
            DomainComputersUnknownCount,

            // This requires DSInstall PowerShell Module
            DomainPasswordDataUsers, // Gathers users data and their passwords
            DomainPasswordDataPasswords, // Compares Users Password with File
            DomainPasswordDataPasswordsHashes, // Compares Users Password with File HASH
            DomainPasswordClearTextPassword, // include both enabled / disabled accounts
            DomainPasswordClearTextPasswordEnabled,  // include only enabled
            DomainPasswordClearTextPasswordDisabled, // include only disabled
            DomainPasswordLMHash,
            DomainPasswordEmptyPassword,
            DomainPasswordWeakPassword,
            DomainPasswordWeakPasswordEnabled,
            DomainPasswordWeakPasswordDisabled,
            DomainPasswordWeakPasswordList, // Password List from file..
            DomainPasswordDefaultComputerPassword,
            DomainPasswordPasswordNotRequired,
            DomainPasswordPasswordNeverExpires,
            DomainPasswordSmartCardUsersWithPassword,
            DomainPasswordAESKeysMissing,
            DomainPasswordPreAuthNotRequired,
            DomainPasswordDESEncryptionOnly,
            DomainPasswordDelegatableAdmins,
            DomainPasswordDuplicatePasswordGroups,
            DomainPasswordHashesWeakPassword,
            DomainPasswordHashesWeakPasswordEnabled,
            DomainPasswordHashesWeakPasswordDisabled,
            DomainPasswordStats
        }
    }
"@