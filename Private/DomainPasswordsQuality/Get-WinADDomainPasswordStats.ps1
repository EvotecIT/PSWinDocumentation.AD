function Get-WinADDomainPasswordStats {
    [CmdletBinding()]
    param(
        [System.Collections.IDictionary]$PasswordsQuality,
        [Array] $TypesRequired,
        $DomainPasswordHashesWeakPassword,
        $DomainPasswordHashesWeakPasswordEnabled,
        $DomainPasswordHashesWeakPasswordDisabled
    )

    $Stats = [ordered] @{ }
    $Stats.'Clear Text Passwords' = Get-ObjectCount -Object $PasswordsQuality.DomainPasswordClearTextPassword
    $Stats.'LM Hashes' = Get-ObjectCount -Object $PasswordsQuality.DomainPasswordLMHash
    $Stats.'Empty Passwords' = Get-ObjectCount -Object $PasswordsQuality.DomainPasswordEmptyPassword
    $Stats.'Weak Passwords' = Get-ObjectCount -Object $PasswordsQuality.DomainPasswordWeakPassword
    $Stats.'Weak Passwords Enabled' = Get-ObjectCount -Object $PasswordsQuality.DomainPasswordWeakPasswordEnabled
    $Stats.'Weak Passwords Disabled' = Get-ObjectCount -Object $PasswordsQuality.DomainPasswordWeakPasswordDisabled
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::DomainPasswordHashesWeakPassword)) {
        $Stats.'Weak Passwords (HASH)' = Get-ObjectCount -Object $DomainPasswordHashesWeakPassword
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::DomainPasswordHashesWeakPasswordEnabled)) {
        $Stats.'Weak Passwords (HASH) Enabled' = Get-ObjectCount -Object $DomainPasswordHashesWeakPasswordEnabled
    }
    if (Find-TypesNeeded -TypesRequired $TypesRequired -TypesNeeded @([PSWinDocumentation.ActiveDirectory]::DomainPasswordHashesWeakPasswordDisabled)) {
        $Stats.'Weak Passwords (HASH) Disabled' = Get-ObjectCount -Object $DomainPasswordHashesWeakPasswordDisabled
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