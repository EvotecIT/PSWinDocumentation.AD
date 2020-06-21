function Get-WinADDomainUsersAllFiltered {
    [CmdletBinding()]
    param(
        [Array] $DomainUsers
    )

    #$DomainUsers | Where-Object { $_.PasswordNotRequired -eq $False }
    #| Select-Object * #Name, SamAccountName, UserPrincipalName, Enabled
    foreach ($_ in $DomainUsers) {
        if ($_.PasswordNotRequired -eq $False) {
            $_
        }
    }

}