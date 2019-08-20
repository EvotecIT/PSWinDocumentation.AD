function Get-WinADDomainFineGrainedPoliciesUsersExtended {
    [CmdletBinding()]
    param(
        [Array] $DomainFineGrainedPolicies,
        # [Array] $DomainUsersFullList,
        # [Array] $DomainGroupsFullList,
        [string] $Domain = ($Env:USERDNSDOMAIN).ToLower(),
        [hashtable] $DomainObjects
    )
    $CurrentDate = Get-Date
    $PolicyUsers = @(
        foreach ($Policy in $DomainFineGrainedPolicies) {
            $Objects = foreach ($U in $Policy.'Applies To') {
                #Get-ADObjectFromDistingusishedName -ADCatalog $DomainUsersFullList -DistinguishedName $U
                Get-ADObjectFromDNHash -ADCatalog $DomainObjects -DistinguishedName $U
            }
            $Users = foreach ($_ in $Objects) {
                if ($_.ObjectClass -eq 'user') {
                    $_
                }
            }
            $Groups = foreach ($_ in $Objects) {
                if ($_.ObjectClass -eq 'group') {
                    $_
                }
            }
            foreach ($User in $Users) {
                $Manager = Get-ADObjectFromDNHash -ADCatalog $DomainObjects -DistinguishedName $User.Manager

                [PsCustomObject] @{
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
                    #'Manager'                           = (Get-ADObjectFromDistingusishedName -ADCatalog $DomainUsersFullList -DistinguishedName $User.Manager).Name
                    #'ManagerEmail'                      = (Get-ADObjectFromDistingusishedName -ADCatalog $DomainUsersFullList -DistinguishedName $User.Manager).EmailAddress
                    'Manager'                           = $Manager.Name
                    'ManagerEmail'                      = if ($Splitter -ne '') { $Manager.EmailAddress -join $Splitter } else { $Manager.EmailAddress }
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
            #$Groups = foreach ($U in $Policy.'Applies To') {
            # Get-ADObjectFromDistingusishedName -ADCatalog $DomainGroupsFullList -DistinguishedName $U
            #   Get-ADObjectFromDNHash -ADCatalog $DomainObjects -DistinguishedName $U
            #}
            foreach ($Group in $Groups) {
                $GroupMembership = Get-ADGroupMember -Server $Domain -Identity $Group.SID -Recursive
                foreach ($Member in $GroupMembership) {
                    # $Object = (Get-ADObjectFromDistingusishedName -ADCatalog $DomainUsersFullList -DistinguishedName $Member.DistinguishedName)
                    $Object = Get-ADObjectFromDNHash -ADCatalog $DomainObjects -DistinguishedName $Member.DistinguishedName
                    $Manager = Get-ADObjectFromDNHash -ADCatalog $DomainObjects -DistinguishedName $Object.Manager
                    [PsCustomObject] @{
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
                        # 'Manager'                           = (Get-ADObjectFromDistingusishedName -ADCatalog $DomainUsersFullList -DistinguishedName $Object.Manager).Name
                        # 'ManagerEmail'                      = (Get-ADObjectFromDistingusishedName -ADCatalog $DomainUsersFullList -DistinguishedName $Object.Manager).EmailAddress
                        'Manager'                           = $Manager.Name
                        'ManagerEmail'                      = if ($Splitter -ne '') { $Manager.EmailAddress -join $Splitter } else { $Manager.EmailAddress }
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
    )
    return $PolicyUsers
}