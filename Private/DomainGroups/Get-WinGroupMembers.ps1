function Get-WinGroupMembers {
    [CmdletBinding()]
    param(
        [Array] $Groups,
        [string] $Domain = $Env:USERDNSDOMAIN,
        #[System.Object[]] $ADCatalog,
        #[System.Object[]] $ADCatalogUsers,
        [ValidateSet("Recursive", "Standard")][String] $Option,
        [hashtable] $DomainObjects,
        [string] $Splitter
    )
    [DateTime] $CurrentDate = Get-Date
    if ($Option -eq 'Recursive') {
        [Array] $GroupMembersRecursive = foreach ($Group in $Groups) {
            try {
                $GroupMembership = Get-ADGroupMember -Server $Domain -Identity $Group.'Group SID' -Recursive -ErrorAction Stop
            } catch {
                $ErrorMessage = $_.Exception.Message -replace "`n", " " -replace "`r", " "
                Write-Warning "Couldn't get information about group $($Group.Name) with SID $($Group.'Group SID') error: $ErrorMessage"
                continue
            }
            foreach ($Member in $GroupMembership) {
                # $Object = (Get-ADObjectFromDistingusishedName -ADCatalog $ADCatalog -DistinguishedName $Member.DistinguishedName)
                $Object = Get-ADObjectFromDNHash -ADCatalog $DomainObjects -DistinguishedName  $Member.DistinguishedName
                $Manager = Get-ADObjectFromDNHash -ADCatalog $DomainObjects -DistinguishedName $Object.Manager

                [PsCustomObject] @{
                    'Group Name'                        = $Group.'Group Name'
                    'Group SID'                         = $Group.'Group SID'
                    'Group Category'                    = $Group.'Group Category'
                    'Group Scope'                       = $Group.'Group Scope'
                    'High Privileged Group'             = if ($Group.adminCount -eq 1) { $True } else { $False }
                    'Display Name'                      = $Object.DisplayName
                    'Name'                              = $Member.Name
                    'User Principal Name'               = $Object.UserPrincipalName
                    'Sam Account Name'                  = $Object.SamAccountName
                    'Email Address'                     = $Object.EmailAddress
                    'PasswordExpired'                   = $Object.PasswordExpired
                    'PasswordLastSet'                   = $Object.PasswordLastSet
                    'PasswordNotRequired'               = $Object.PasswordNotRequired
                    'PasswordNeverExpires'              = $Object.PasswordNeverExpires
                    'Enabled'                           = $Object.Enabled
                    'SID'                               = $Member.SID.Value
                    #'Manager'                           = (Get-ADObjectFromDistingusishedName -ADCatalog $ADCatalogUsers -DistinguishedName $Object.Manager).Name
                    #'ManagerEmail'                      = (Get-ADObjectFromDistingusishedName -ADCatalog $ADCatalogUsers -DistinguishedName $Object.Manager).EmailAddress
                    'Manager'                           = $Manager.Name
                    'ManagerEmail'                      = if ($Splitter -ne '') { $Manager.EmailAddress -join $Splitter } else { $Manager.EmailAddress }

                    'DateExpiry'                        = Convert-ToDateTime -Timestring $($Object."msDS-UserPasswordExpiryTimeComputed") # -Verbose
                    "DaysToExpire"                      = (Convert-TimeToDays -StartTime $CurrentDate -EndTime (Convert-ToDateTime -Timestring $($Object."msDS-UserPasswordExpiryTimeComputed")))
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
                # $Member
            }
        }
        if ($GroupMembersRecursive.Count -eq 1) {
            return , $GroupMembersRecursive
        }
        return $GroupMembersRecursive
    }
    if ($Option -eq 'Standard') {
        [Array] $GroupMembersDirect = foreach ($Group in $Groups) {
            foreach ($Member in $Group.'Group Members DN') {
                $Object = Get-ADObjectFromDNHash -ADCatalog $DomainObjects -DistinguishedName  $Member
                $Manager = Get-ADObjectFromDNHash -ADCatalog $DomainObjects -DistinguishedName $Object.Manager

                [PsCustomObject] @{
                    'Group Name'                        = $Group.'Group Name'
                    'Group SID'                         = $Group.'Group SID'
                    'Group Category'                    = $Group.'Group Category'
                    'Group Scope'                       = $Group.'Group Scope'
                    'DisplayName'                       = $Object.DisplayName
                    'High Privileged Group'             = if ($Group.adminCount -eq 1) { $True } else { $False }
                    'UserPrincipalName'                 = $Object.UserPrincipalName
                    'SamAccountName'                    = $Object.SamAccountName
                    'EmailAddress'                      = $Object.EmailAddress
                    'PasswordExpired'                   = $Object.PasswordExpired
                    'PasswordLastSet'                   = $Object.PasswordLastSet
                    'PasswordNotRequired'               = $Object.PasswordNotRequired
                    'PasswordNeverExpires'              = $Object.PasswordNeverExpires
                    'Enabled'                           = $Object.Enabled
                    # 'Manager'                           = (Get-ADObjectFromDistingusishedName -ADCatalog $ADCatalogUsers -DistinguishedName $Object.Manager).Name
                    # 'ManagerEmail'                      = (Get-ADObjectFromDistingusishedName -ADCatalog $ADCatalogUsers -DistinguishedName $Object.Manager).EmailAddress

                    'Manager'                           = $Manager.Name
                    'ManagerEmail'                      = if ($Splitter -ne '') { $Manager.EmailAddress -join $Splitter } else { $Manager.EmailAddress }
                    'DateExpiry'                        = Convert-ToDateTime -Timestring $($Object."msDS-UserPasswordExpiryTimeComputed") #-Verbose
                    "DaysToExpire"                      = (Convert-TimeToDays -StartTime $CurrentDate -EndTime (Convert-ToDateTime -Timestring $($Object."msDS-UserPasswordExpiryTimeComputed")))
                    "AccountExpirationDate"             = $Object.AccountExpirationDate
                    "AccountLockoutTime"                = $Object.AccountLockoutTime
                    "AllowReversiblePasswordEncryption" = $Object.AllowReversiblePasswordEncryption
                    "BadLogonCount"                     = $Object.BadLogonCount
                    "CannotChangePassword"              = $Object.CannotChangePassword
                    "CanonicalName"                     = $Object.CanonicalName

                    "Description"                       = $Object.Description
                    "DistinguishedName"                 = $Object.DistinguishedName
                    "EmployeeID"                        = $Object.EmployeeID
                    "EmployeeNumber"                    = $Object.EmployeeNumber
                    "LastBadPasswordAttempt"            = $Object.LastBadPasswordAttempt
                    "LastLogonDate"                     = $Object.LastLogonDate

                    'Name'                              = $Object.Name
                    'SID'                               = $Object.SID.Value
                    'GivenName'                         = $Object.GivenName
                    'Surname'                           = $Object.Surname

                    "Created"                           = $Object.Created
                    "Modified"                          = $Object.Modified
                    "Protected"                         = $Object.ProtectedFromAccidentalDeletion
                    "Domain"                            = $Domain
                }
            }
        }
        if ($GroupMembersDirect.Count -eq 1) {
            return , $GroupMembersDirect
        }
        return $GroupMembersDirect
    }
}