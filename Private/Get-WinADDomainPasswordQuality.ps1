function Get-WinADDomainPasswordQuality {
    [CmdletBinding()]
    param (
        [string] $DnsRoot,
        [string] $DomainDistinguishedName,

        [Array] $PasswordQualityUsers,
        [string] $FilePath,
        [switch] $UseHashes,
        [switch] $PasswordQuality,
        [Array] $Properties,
        [System.Collections.IDictionary] $DomainObjectsNetbios
    )
    if (-not $DomainObjectsNetbios) {
        Write-Warning "Get-WinADDomainPasswordQuality - DomainobjectsNetbios not passed. Creating new one, but this will skip tests."
        $DomainObjectsNetbios = [ordered] @{}
    }

    if (-not $Properties) {
        $Properties = @(
            'Name', 'UserPrincipalName', 'Enabled', 'Password Last Changed', "DaysToExpire",
            'PasswordExpired', 'PasswordNeverExpires', 'PasswordNotRequired', 'DateExpiry', 'PasswordLastSet', 'SamAccountName',
            'EmailAddress', 'Display Name', 'Given Name', 'Surname', 'Manager', 'Manager Email',
            "AccountExpirationDate", "AccountLockoutTime", "AllowReversiblePasswordEncryption", "BadLogonCount",
            "CannotChangePassword", "CanonicalName", "Description", "DistinguishedName", "EmployeeID", "EmployeeNumber", "LastBadPasswordAttempt",
            "LastLogonDate", "Created", "Modified", "Protected", "Primary Group", "Member Of", "Domain"
        )
    }

    if ($FilePath -eq '' -and $PasswordQuality.IsPresent -eq $true) {
        $FilePath = "$PSScriptRoot\..\Resources\PasswordList.txt"
    }

    if ($FilePath -eq '') {
        Write-Verbose "Get-WinADDomainPasswordQuality - File path not given, using hashes set to $($UseHashes.IsPresent)"
        return $null
    }
    if (-not (Test-Path -Path $FilePath)) {
        Write-Verbose "Get-WinADDomainPasswordQuality - File path doesn't exists, using hashes set to $($UseHashes.IsPresent)"
        return $null
    }
    $Data = [ordered] @{ }
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
        foreach ($User in $Data.PasswordQuality.ClearTextPassword) {
            if ($DomainObjectsNetbios["$User"]) {
                $DomainObjectsNetbios["$User"]
            } else {
                Write-Warning "Get-WinADDomainPasswordQuality - Couldn't find object $User in cache."
            }
        }
    }
    $Data.DomainPasswordClearTextPasswordEnabled = Invoke-Command -ScriptBlock {
        return $Data.DomainPasswordClearTextPassword | Where-Object { $_.Enabled -eq $true }
    }
    $Data.DomainPasswordClearTextPasswordDisabled = Invoke-Command -ScriptBlock {
        return $Data.DomainPasswordClearTextPassword | Where-Object { $_.Enabled -eq $false }
    }
    $Data.DomainPasswordLMHash = Invoke-Command -ScriptBlock {
        foreach ($User in $Data.PasswordQuality.LMHash) {
            if ($DomainObjectsNetbios["$User"]) {
                $DomainObjectsNetbios["$User"]
            } else {
                Write-Warning "Get-WinADDomainPasswordQuality - Couldn't find object $User in cache."
            }
        }
    }
    $Data.DomainPasswordEmptyPassword = Invoke-Command -ScriptBlock {
        foreach ($User in $Data.PasswordQuality.EmptyPassword) {
            if ($DomainObjectsNetbios["$User"]) {
                $DomainObjectsNetbios["$User"]
            } else {
                Write-Warning "Get-WinADDomainPasswordQuality - Couldn't find object $User in cache."
            }
        }
    }
    $Data.DomainPasswordWeakPassword = Invoke-Command -ScriptBlock {
        foreach ($User in $Data.PasswordQuality.WeakPassword) {
            if ($DomainObjectsNetbios["$User"]) {
                $DomainObjectsNetbios["$User"]
            } else {
                Write-Warning "Get-WinADDomainPasswordQuality - Couldn't find object $User in cache."
            }
        }
    }
    $Data.DomainPasswordWeakPasswordEnabled = Invoke-Command -ScriptBlock {
        return $Data.DomainPasswordWeakPassword | Where-Object { $_.Enabled -eq $true }
    }
    $Data.DomainPasswordWeakPasswordDisabled = Invoke-Command -ScriptBlock {
        return $Data.DomainPasswordWeakPassword | Where-Object { $_.Enabled -eq $false }
    }
    $Data.DomainPasswordWeakPasswordList = Invoke-Command -ScriptBlock {
        if ($UseHashes) {
            return ''
        } else {
            $Passwords = Get-Content -Path $FilePath
            return $Passwords -join ', '
        }
    }
    $Data.DomainPasswordAESKeysMissing = Invoke-Command -ScriptBlock {
        foreach ($User in $Data.PasswordQuality.AESKeysMissing) {
            if ($DomainObjectsNetbios["$User"]) {
                $DomainObjectsNetbios["$User"]
            } else {
                Write-Warning "Get-WinADDomainPasswordQuality - Couldn't find object $User in cache."
            }
        }
    }
    $Data.DomainPasswordDefaultComputerPassword = Invoke-Command -ScriptBlock {
        foreach ($User in $Data.PasswordQuality.DefaultComputerPassword) {
            if ($DomainObjectsNetbios["$User"]) {
                $DomainObjectsNetbios["$User"]
            } else {
                Write-Warning "Get-WinADDomainPasswordQuality - Couldn't find object $User in cache."
            }
        }
    }
    $Data.DomainPasswordPasswordNotRequired = Invoke-Command -ScriptBlock {
        foreach ($User in $Data.PasswordQuality.PasswordNotRequired) {
            if ($DomainObjectsNetbios["$User"]) {
                $DomainObjectsNetbios["$User"]
            } else {
                Write-Warning "Get-WinADDomainPasswordQuality - Couldn't find object $User in cache."
            }
        }
    }
    $Data.DomainPasswordPasswordNeverExpires = Invoke-Command -ScriptBlock {
        foreach ($User in $Data.PasswordQuality.PasswordNeverExpires) {
            if ($DomainObjectsNetbios["$User"]) {
                $DomainObjectsNetbios["$User"]
            } else {
                Write-Warning "Get-WinADDomainPasswordQuality - Couldn't find object $User in cache."
            }
        }
    }
    $Data.DomainPasswordPreAuthNotRequired = Invoke-Command -ScriptBlock {
        foreach ($User in $Data.PasswordQuality.PreAuthNotRequired) {
            if ($DomainObjectsNetbios["$User"]) {
                $DomainObjectsNetbios["$User"]
            } else {
                Write-Warning "Get-WinADDomainPasswordQuality - Couldn't find object $User in cache."
            }
        }
    }
    $Data.DomainPasswordDESEncryptionOnly = Invoke-Command -ScriptBlock {
        foreach ($User in $Data.PasswordQuality.DESEncryptionOnly) {
            if ($DomainObjectsNetbios["$User"]) {
                $DomainObjectsNetbios["$User"]
            } else {
                Write-Warning "Get-WinADDomainPasswordQuality - Couldn't find object $User in cache."
            }
        }
    }
    $Data.DomainPasswordDelegatableAdmins = Invoke-Command -ScriptBlock {
        foreach ($User in $Data.PasswordQuality.DelegatableAdmins) {
            if ($DomainObjectsNetbios["$User"]) {
                $DomainObjectsNetbios["$User"]
            } else {
                Write-Warning "Get-WinADDomainPasswordQuality - Couldn't find object $User in cache."
            }
        }
    }

    $Data.DomainPasswordSmartCardUsersWithPassword = & {
        foreach ($User in $Data.PasswordQuality.SmartCardUsersWithPassword) {
            if ($DomainObjectsNetbios["$User"]) {
                $DomainObjectsNetbios["$User"]
            } else {
                Write-Warning "Get-WinADDomainPasswordQuality - Couldn't find object $User in cache."
            }
        }
    }

    $Data.DomainPasswordDuplicatePasswordGroups = Invoke-Command -ScriptBlock {
        $DuplicateGroups = $Data.PasswordQuality.DuplicatePasswordGroups.ToArray()
        $Count = 0
        foreach ($DuplicateGroup in $DuplicateGroups) {
            $Count++
            $Name = "Duplicate $Count"
            foreach ($User in $DuplicateGroup) {
                if ($DomainObjectsNetbios["$User"]) {
                    Add-Member -InputObject $DomainObjectsNetbios["$User"] -MemberType NoteProperty -Name 'Duplicate Group' -Value $Name -Force
                    $DomainObjectsNetbios["$User"]
                } else {
                    Write-Warning "Get-WinADDomainPasswordQuality - Couldn't find object $User in cache."
                }
            }
        }
    }
    return $Data
}