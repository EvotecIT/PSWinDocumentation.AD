function Get-WinADDomainDefaultPasswordPolicy {
    [CmdletBinding()]
    param(
        [string] $Domain = $Env:USERDNSDOMAIN
    )
    $Policy = Get-ADDefaultDomainPasswordPolicy -Server $Domain

    [ordered] @{
        'Complexity Enabled'            = $Policy.ComplexityEnabled
        'Lockout Duration'              = ($Policy.LockoutDuration).TotalMinutes
        'Lockout Observation Window'    = ($Policy.LockoutObservationWindow).TotalMinutes
        'Lockout Threshold'             = $Policy.LockoutThreshold
        'Max Password Age'              = $($Policy.MaxPasswordAge).TotalDays
        'Min Password Length'           = $Policy.MinPasswordLength
        'Min Password Age'              = $($Policy.MinPasswordAge).TotalDays
        'Password History Count'        = $Policy.PasswordHistoryCount
        'Reversible Encryption Enabled' = $Policy.ReversibleEncryptionEnabled
        'Distinguished Name'            = $Policy.DistinguishedName
    }
}