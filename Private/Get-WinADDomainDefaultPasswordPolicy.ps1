function Get-WinADDomainDefaultPasswordPolicy {
    [CmdletBinding()]
    param(
        [string] $Domain = $Env:USERDNSDOMAIN
    )
    $Policy = Get-ADDefaultDomainPasswordPolicy -Server $Domain

    [ordered] @{
        'Complexity Enabled'            = $Policy.ComplexityEnabled
        'Lockout Duration'              = $Policy.LockoutDuration
        'Lockout Observation Window'    = $Policy.LockoutObservationWindow
        'Lockout Threshold'             = $Policy.LockoutThreshold
        'Max Password Age'              = $Policy.MaxPasswordAge
        'Min Password Length'           = $Policy.MinPasswordLength
        'Min Password Age'              = $Policy.MinPasswordAge
        'Password History Count'        = $Policy.PasswordHistoryCount
        'Reversible Encryption Enabled' = $Policy.ReversibleEncryptionEnabled
        'Distinguished Name'            = $Policy.DistinguishedName
    }
}