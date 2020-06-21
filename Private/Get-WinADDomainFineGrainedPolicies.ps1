function Get-WinADDomainFineGrainedPolicies {
    [CmdletBinding()]
    param(
        [string] $Domain = $Env:USERDNSDOMAIN
    )
    $FineGrainedPoliciesData = Get-ADFineGrainedPasswordPolicy -Filter * -Server $Domain
    $FineGrainedPolicies = foreach ($Policy in $FineGrainedPoliciesData) {
        [PsCustomObject] @{
            'Name'                          = $Policy.Name
            'Complexity Enabled'            = $Policy.ComplexityEnabled
            'Lockout Duration'              = $Policy.LockoutDuration
            'Lockout Observation Window'    = $Policy.LockoutObservationWindow
            'Lockout Threshold'             = $Policy.LockoutThreshold
            'Max Password Age'              = $Policy.MaxPasswordAge
            'Min Password Length'           = $Policy.MinPasswordLength
            'Min Password Age'              = $Policy.MinPasswordAge
            'Password History Count'        = $Policy.PasswordHistoryCount
            'Reversible Encryption Enabled' = $Policy.ReversibleEncryptionEnabled
            'Precedence'                    = $Policy.Precedence
            'Applies To'                    = $Policy.AppliesTo # get all groups / usrs and convert to data TODO
            'Distinguished Name'            = $Policy.DistinguishedName
        }
    }
    return $FineGrainedPolicies

}