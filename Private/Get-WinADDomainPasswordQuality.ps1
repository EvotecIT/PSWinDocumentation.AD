function Get-WinADDomainPasswordQuality {
    [CmdletBinding()]
    param (
        [string] $DnsRoot,
        [Array] $DomainUsersAll,
        [Array] $DomainComputersAll,
        [string] $DomainDistinguishedName,

        [Array] $PasswordQualityUsers,
        [string] $FilePath,
        [switch] $UseHashes,
        [switch] $PasswordQuality
    )
    if ($FilePath -eq '' -and $PasswordQuality.IsPresent -eq $true) {
        $FilePath = "$PSScriptRoot\..\Resources\PasswordList.txt"
    }

    if ($FilePath -eq '') {
        Write-Verbose "Get-WinADDomainPasswordQuality - File path not given, using hashes set to $UseHashes"
        return $null
    }
    if (-not (Test-Path -Path $FilePath)) {
        Write-Verbose "Get-WinADDomainPasswordQuality - File path doesn't exists, using hashes set to $UseHashes"
        return $null
    }
    # if ($null -eq $DomainInformation) {
    #      Write-Verbose "Get-WinADDomainPasswordQuality - No DomainInformation given, no alternative approach either. Terminating password quality check."
    #      return $null
    # }
    $Data = [ordered] @{}
    if ($PasswordQualityUsers) {
        $Data.PasswordQualityUsers = $PasswordQualityUsers
    } else {
        $Data.PasswordQualityUsers = Get-ADReplAccount -All -Server $DnsRoot -NamingContext $DomainDistinguishedName
    }
    $Data.PasswordQuality = Invoke-Command -ScriptBlock {
        if ($UseHashes) {
            $Results = $Data.PasswordQualityUsers | Test-PasswordQuality -WeakPasswordHashesFile $FilePath -IncludeDisabledAccounts
        } else {
            $Results = $Data.PasswordQualityUsers | Test-PasswordQuality -WeakPasswordsFile $FilePath -IncludeDisabledAccounts
        }
        return $Results
    }
    $Data.DomainPasswordClearTextPassword = Invoke-Command -ScriptBlock {
        $ADAccounts = Get-WinADAccounts -UserNameList $Data.PasswordQuality.ClearTextPassword -ADCatalog $DomainUsersAll, $DomainComputersAll
        return $ADAccounts | Select-Object 'Name', 'UserPrincipalName', 'Enabled', 'Password Last Changed', "DaysToExpire", `
            'PasswordExpired', 'PasswordNeverExpires', 'PasswordNotRequired', 'DateExpiry', 'PasswordLastSet', 'SamAccountName', `
            'EmailAddress', 'Display Name', 'Given Name', 'Surname', 'Manager', 'Manager Email', `
            "AccountExpirationDate", "AccountLockoutTime", "AllowReversiblePasswordEncryption", "BadLogonCount", `
            "CannotChangePassword", "CanonicalName", "Description", "DistinguishedName", "EmployeeID", "EmployeeNumber", "LastBadPasswordAttempt", `
            "LastLogonDate", "Created", "Modified", "Protected", "Primary Group", "Member Of", "Domain"
    }
    $Data.DomainPasswordClearTextPasswordEnabled = Invoke-Command -ScriptBlock {
        return $Data.DomainPasswordClearTextPassword | Where-Object { $_.Enabled -eq $true }
    }
    $Data.DomainPasswordClearTextPasswordDisabled = Invoke-Command -ScriptBlock {
        return $Data.DomainPasswordClearTextPassword | Where-Object { $_.Enabled -eq $false }
    }
    $Data.DomainPasswordLMHash = Invoke-Command -ScriptBlock {
        $ADAccounts = Get-WinADAccounts -UserNameList  $Data.PasswordQuality.LMHash  -ADCatalog $DomainUsersAll, $DomainComputersAll
        return $ADAccounts | Select-Object 'Name', 'UserPrincipalName', 'Enabled', 'Password Last Changed', "DaysToExpire", `
            'PasswordExpired', 'PasswordNeverExpires', 'PasswordNotRequired', 'DateExpiry', 'PasswordLastSet', 'SamAccountName', `
            'EmailAddress', 'Display Name', 'Given Name', 'Surname', 'Manager', 'Manager Email', `
            "AccountExpirationDate", "AccountLockoutTime", "AllowReversiblePasswordEncryption", "BadLogonCount", `
            "CannotChangePassword", "CanonicalName", "Description", "DistinguishedName", "EmployeeID", "EmployeeNumber", "LastBadPasswordAttempt", `
            "LastLogonDate", "Created", "Modified", "Protected", "Primary Group", "Member Of", "Domain"
    }
    $Data.DomainPasswordEmptyPassword = Invoke-Command -ScriptBlock {
        $ADAccounts = Get-WinADAccounts -UserNameList $Data.PasswordQuality.EmptyPassword  -ADCatalog $DomainUsersAll, $DomainComputersAll
        return $ADAccounts | Select-Object 'Name', 'UserPrincipalName', 'Enabled', 'Password Last Changed', "DaysToExpire", `
            'PasswordExpired', 'PasswordNeverExpires', 'PasswordNotRequired', 'DateExpiry', 'PasswordLastSet', 'SamAccountName', `
            'EmailAddress', 'Display Name', 'Given Name', 'Surname', 'Manager', 'Manager Email', `
            "AccountExpirationDate", "AccountLockoutTime", "AllowReversiblePasswordEncryption", "BadLogonCount", `
            "CannotChangePassword", "CanonicalName", "Description", "DistinguishedName", "EmployeeID", "EmployeeNumber", "LastBadPasswordAttempt", `
            "LastLogonDate", "Created", "Modified", "Protected", "Primary Group", "Member Of", "Domain"
    }


    $Data.DomainPasswordWeakPassword = Invoke-Command -ScriptBlock {
        $ADAccounts = Get-WinADAccounts -UserNameList  $Data.PasswordQuality.WeakPassword  -ADCatalog $DomainUsersAll, $DomainComputersAll
        return $ADAccounts | Select-Object 'Name', 'UserPrincipalName', 'Enabled', 'Password Last Changed', "DaysToExpire", `
            'PasswordExpired', 'PasswordNeverExpires', 'PasswordNotRequired', 'DateExpiry', 'PasswordLastSet', 'SamAccountName', `
            'EmailAddress', 'Display Name', 'Given Name', 'Surname', 'Manager', 'Manager Email', `
            "AccountExpirationDate", "AccountLockoutTime", "AllowReversiblePasswordEncryption", "BadLogonCount", `
            "CannotChangePassword", "CanonicalName", "Description", "DistinguishedName", "EmployeeID", "EmployeeNumber", "LastBadPasswordAttempt", `
            "LastLogonDate", "Created", "Modified", "Protected", "Primary Group", "Member Of", "Domain"
    }
    $Data.DomainPasswordWeakPasswordEnabled = Invoke-Command -ScriptBlock {
        return $Data.DomainPasswordWeakPassword  | Where-Object { $_.Enabled -eq $true }
    }
    $Data.DomainPasswordWeakPasswordDisabled = Invoke-Command -ScriptBlock {
        return $Data.DomainPasswordWeakPassword  | Where-Object { $_.Enabled -eq $false }
    }
    $Data.DomainPasswordWeakPasswordList = Invoke-Command -ScriptBlock {
        if ($UseHashes) {
            return ''
        } else {
            $Passwords = Get-Content -Path $FilePath
            return $Passwords -join ', '
        }
    }
    $Data.DomainPasswordDefaultComputerPassword = Invoke-Command -ScriptBlock {
        $ADAccounts = Get-WinADAccounts -UserNameList  $Data.PasswordQuality.DefaultComputerPassword  -ADCatalog $DomainUsersAll, $DomainComputersAll
        return $ADAccounts | Select-Object 'Name', 'UserPrincipalName', 'Enabled', 'Password Last Changed', "DaysToExpire", `
            'PasswordExpired', 'PasswordNeverExpires', 'PasswordNotRequired', 'DateExpiry', 'PasswordLastSet', 'SamAccountName', `
            'EmailAddress', 'Display Name', 'Given Name', 'Surname', 'Manager', 'Manager Email', `
            "AccountExpirationDate", "AccountLockoutTime", "AllowReversiblePasswordEncryption", "BadLogonCount", `
            "CannotChangePassword", "CanonicalName", "Description", "DistinguishedName", "EmployeeID", "EmployeeNumber", "LastBadPasswordAttempt", `
            "LastLogonDate", "Created", "Modified", "Protected", "Primary Group", "Member Of", "Domain"
    }
    $Data.DomainPasswordPasswordNotRequired = Invoke-Command -ScriptBlock {
        $ADAccounts = Get-WinADAccounts -UserNameList  $Data.PasswordQuality.PasswordNotRequired  -ADCatalog $DomainUsersAll, $DomainComputersAll
        return $ADAccounts | Select-Object 'Name', 'UserPrincipalName', 'Enabled', 'Password Last Changed', "DaysToExpire", `
            'PasswordExpired', 'PasswordNeverExpires', 'PasswordNotRequired', 'DateExpiry', 'PasswordLastSet', 'SamAccountName', `
            'EmailAddress', 'Display Name', 'Given Name', 'Surname', 'Manager', 'Manager Email', `
            "AccountExpirationDate", "AccountLockoutTime", "AllowReversiblePasswordEncryption", "BadLogonCount", `
            "CannotChangePassword", "CanonicalName", "Description", "DistinguishedName", "EmployeeID", "EmployeeNumber", "LastBadPasswordAttempt", `
            "LastLogonDate", "Created", "Modified", "Protected", "Primary Group", "Member Of", "Domain"
    }
    $Data.DomainPasswordPasswordNeverExpires = Invoke-Command -ScriptBlock {
        $ADAccounts = Get-WinADAccounts -UserNameList $Data.PasswordQuality.PasswordNeverExpires  -ADCatalog $DomainUsersAll, $DomainComputersAll
        return $ADAccounts | Select-Object 'Name', 'UserPrincipalName', 'Enabled', 'Password Last Changed', "DaysToExpire", `
            'PasswordExpired', 'PasswordNeverExpires', 'PasswordNotRequired', 'DateExpiry', 'PasswordLastSet', 'SamAccountName', `
            'EmailAddress', 'Display Name', 'Given Name', 'Surname', 'Manager', 'Manager Email', `
            "AccountExpirationDate", "AccountLockoutTime", "AllowReversiblePasswordEncryption", "BadLogonCount", `
            "CannotChangePassword", "CanonicalName", "Description", "DistinguishedName", "EmployeeID", "EmployeeNumber", "LastBadPasswordAttempt", `
            "LastLogonDate", "Created", "Modified", "Protected", "Primary Group", "Member Of", "Domain"
    }
    $Data.DomainPasswordAESKeysMissing = Invoke-Command -ScriptBlock {
        $ADAccounts = Get-WinADAccounts -UserNameList  $Data.PasswordQuality.AESKeysMissing  -ADCatalog $DomainUsersAll, $DomainComputersAll
        return $ADAccounts | Select-Object 'Name', 'UserPrincipalName', 'Enabled', 'Password Last Changed', "DaysToExpire", `
            'PasswordExpired', 'PasswordNeverExpires', 'PasswordNotRequired', 'DateExpiry', 'PasswordLastSet', 'SamAccountName', `
            'EmailAddress', 'Display Name', 'Given Name', 'Surname', 'Manager', 'Manager Email', `
            "AccountExpirationDate", "AccountLockoutTime", "AllowReversiblePasswordEncryption", "BadLogonCount", `
            "CannotChangePassword", "CanonicalName", "Description", "DistinguishedName", "EmployeeID", "EmployeeNumber", "LastBadPasswordAttempt", `
            "LastLogonDate", "Created", "Modified", "Protected", "Primary Group", "Member Of", "Domain"
    }
    $Data.DomainPasswordPreAuthNotRequired = Invoke-Command -ScriptBlock {
        $ADAccounts = Get-WinADAccounts -UserNameList $Data.PasswordQuality.PreAuthNotRequired  -ADCatalog $DomainUsersAll, $DomainComputersAll
        return $ADAccounts | Select-Object 'Name', 'UserPrincipalName', 'Enabled', 'Password Last Changed', "DaysToExpire", `
            'PasswordExpired', 'PasswordNeverExpires', 'PasswordNotRequired', 'DateExpiry', 'PasswordLastSet', 'SamAccountName', `
            'EmailAddress', 'Display Name', 'Given Name', 'Surname', 'Manager', 'Manager Email', `
            "AccountExpirationDate", "AccountLockoutTime", "AllowReversiblePasswordEncryption", "BadLogonCount", `
            "CannotChangePassword", "CanonicalName", "Description", "DistinguishedName", "EmployeeID", "EmployeeNumber", "LastBadPasswordAttempt", `
            "LastLogonDate", "Created", "Modified", "Protected", "Primary Group", "Member Of", "Domain"
    }
    $Data.DomainPasswordDESEncryptionOnly = Invoke-Command -ScriptBlock {
        $ADAccounts = Get-WinADAccounts -UserNameList $Data.PasswordQuality.DESEncryptionOnly -ADCatalog $DomainUsersAll, $DomainComputersAll
        return $ADAccounts | Select-Object 'Name', 'UserPrincipalName', 'Enabled', 'Password Last Changed', "DaysToExpire", `
            'PasswordExpired', 'PasswordNeverExpires', 'PasswordNotRequired', 'DateExpiry', 'PasswordLastSet', 'SamAccountName', `
            'EmailAddress', 'Display Name', 'Given Name', 'Surname', 'Manager', 'Manager Email', `
            "AccountExpirationDate", "AccountLockoutTime", "AllowReversiblePasswordEncryption", "BadLogonCount", `
            "CannotChangePassword", "CanonicalName", "Description", "DistinguishedName", "EmployeeID", "EmployeeNumber", "LastBadPasswordAttempt", `
            "LastLogonDate", "Created", "Modified", "Protected", "Primary Group", "Member Of", "Domain"
    }
    $Data.DomainPasswordDelegatableAdmins = Invoke-Command -ScriptBlock {
        $ADAccounts = Get-WinADAccounts -UserNameList $Data.PasswordQuality.DelegatableAdmins  -ADCatalog $DomainUsersAll, $DomainComputersAll
        return $ADAccounts | Select-Object 'Name', 'UserPrincipalName', 'Enabled', 'Password Last Changed', "DaysToExpire", `
            'PasswordExpired', 'PasswordNeverExpires', 'PasswordNotRequired', 'DateExpiry', 'PasswordLastSet', 'SamAccountName', `
            'EmailAddress', 'Display Name', 'Given Name', 'Surname', 'Manager', 'Manager Email', `
            "AccountExpirationDate", "AccountLockoutTime", "AllowReversiblePasswordEncryption", "BadLogonCount", `
            "CannotChangePassword", "CanonicalName", "Description", "DistinguishedName", "EmployeeID", "EmployeeNumber", "LastBadPasswordAttempt", `
            "LastLogonDate", "Created", "Modified", "Protected", "Primary Group", "Member Of", "Domain"
    }
    $Data.DomainPasswordDuplicatePasswordGroups = Invoke-Command -ScriptBlock {
        $DuplicateGroups = $Data.PasswordQuality.DuplicatePasswordGroups.ToArray()
        $Count = 0
        $Value = foreach ($DuplicateGroup in $DuplicateGroups) {
            $Count++
            $Name = "Duplicate $Count"
            foreach ($User in $DuplicateGroup) {
                $FoundUser = [pscustomobject] @{
                    'Duplicate Group' = $Name
                    #'Found User'      = $User
                }
                # $FullUserInformation = $DomainUsersAll | Where-Object { $_.SamAccountName -eq $User }
                $FullUserInformation = foreach ($_ in $DomainUsersAll) {
                    if ($_.SamAccountName -eq $User) { $_ }
                }
                #$FullComputerInformation = $DomainComputersAll | Where-Object { $_.SamAccountName -eq $User }
                $FullComputerInformation = foreach ($_ in $DomainComputersAll) {
                    if ($_.SamAccountName -eq $User) { $_ }
                }
                if ($FullUserInformation) {
                    $MergedObject = Merge-Objects -Object1 $FoundUser -Object2 $FullUserInformation
                }
                if ($FullComputerInformation) {
                    $MergedObject = Merge-Objects -Object1 $MergedObject -Object2 $FullComputerInformation
                }
                $MergedObject
            }
        }
        # Added 'Duplicate Group' to standard output of names - without it, it doesn't make sense
        return $Value | Select-Object 'Duplicate Group', 'Name', 'UserPrincipalName', 'Enabled', 'Password Last Changed', "DaysToExpire", `
            'PasswordExpired', 'PasswordNeverExpires', 'PasswordNotRequired', 'DateExpiry', 'PasswordLastSet', 'SamAccountName', `
            'EmailAddress', 'Display Name', 'Given Name', 'Surname', 'Manager', 'Manager Email', `
            "AccountExpirationDate", "AccountLockoutTime", "AllowReversiblePasswordEncryption", "BadLogonCount", `
            "CannotChangePassword", "CanonicalName", "Description", "DistinguishedName", "EmployeeID", "EmployeeNumber", "LastBadPasswordAttempt", `
            "LastLogonDate", "Created", "Modified", "Protected", "Primary Group", "Member Of", "Domain"
    }
    return $Data
}