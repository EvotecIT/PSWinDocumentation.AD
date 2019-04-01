function Get-WinADKerberosUnconstrainedDelegation {
    param(

    )
    Get-ADObject -filter { (UserAccountControl -BAND 0x0080000) -OR (UserAccountControl -BAND 0x1000000) -OR (msDS-AllowedToDelegateTo -like '*') } `
        -Properties Name, ObjectClass, PrimaryGroupID, UserAccountControl, ServicePrincipalName, msDS-AllowedToDelegateTo
}