function Get-WinADDomainUsersAll {
    [CmdletBinding()]
    param(
        [Array] $Users,
        [string] $Domain = $Env:USERDNSDOMAIN,
        [System.Collections.IDictionary] $DomainObjects,
        [System.Collections.IDictionary] $DomainObjectsNetbios,
        [Object] $Domaininformation,
        [string] $Splitter
    )
    [DateTime] $CurrentDate = Get-Date
    foreach ($U in $Users) {
        $Manager = Get-ADObjectFromDNHash -ADCatalog $DomainObjects -DistinguishedName $U.Manager
        $User = [PsCustomObject] @{
            'Name'                              = $U.Name
            'UserPrincipalName'                 = $U.UserPrincipalName
            'SamAccountName'                    = $U.SamAccountName
            'DisplayName'                       = $U.DisplayName
            'GivenName'                         = $U.GivenName
            'Surname'                           = $U.Surname
            'EmailAddress'                      = $U.EmailAddress
            'PasswordExpired'                   = $U.PasswordExpired
            'PasswordLastSet'                   = $U.PasswordLastSet
            'PasswordLastChanged(Days)'         = if ($null -ne $U.PasswordLastSet) { "$(-$($U.PasswordLastSet - $CurrentDate).Days)" } else { }
            'PasswordNotRequired'               = $U.PasswordNotRequired
            'PasswordNeverExpires'              = $U.PasswordNeverExpires
            'Enabled'                           = $U.Enabled
            'Manager'                           = $Manager.Name
            'ManagerEmail'                      = if ($Splitter -ne '') { $Manager.EmailAddress -join $Splitter } else { $Manager.EmailAddress }
            'DateExpiry'                        = Convert-ToDateTime -Timestring $($U."msDS-UserPasswordExpiryTimeComputed")
            "DaysToExpire"                      = (Convert-TimeToDays -StartTime $CurrentDate -EndTime (Convert-ToDateTime -Timestring $($U."msDS-UserPasswordExpiryTimeComputed")))
            "AccountExpirationDate"             = $U.AccountExpirationDate
            "AccountLockoutTime"                = $U.AccountLockoutTime
            "AllowReversiblePasswordEncryption" = $U.AllowReversiblePasswordEncryption
            "BadLogonCount"                     = $U.BadLogonCount
            "CannotChangePassword"              = $U.CannotChangePassword
            "CanonicalName"                     = $U.CanonicalName

            "Description"                       = $U.Description
            "DistinguishedName"                 = $U.DistinguishedName
            "EmployeeID"                        = $U.EmployeeID
            "EmployeeNumber"                    = $U.EmployeeNumber
            "LastBadPasswordAttempt"            = $U.LastBadPasswordAttempt
            "LastLogonDate"                     = $U.LastLogonDate

            "Created"                           = $U.Created
            "Modified"                          = $U.Modified
            "Protected"                         = $U.ProtectedFromAccidentalDeletion

            "Primary Group"                     = (Get-ADObjectFromDNHash -ADCatalog $DomainObjects -DistinguishedName $U.PrimaryGroup -Type 'SamAccountName')
            "Member Of"                         = (Get-ADObjectFromDNHash -ADCatalog $DomainObjects -DistinguishedName $U.MemberOf -Type 'SamAccountName' -Splitter $Splitter)
            "Domain"                            = $Domain
        }
        $Name = -join ($Domaininformation.NetBIOSName, "\", $User.SamAccountName)
        $DomainObjectsNetbios[$Name] = $User
        $User
    }
}