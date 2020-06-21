function Get-WinADDomainUsersSystemAccounts {
    [CmdletBinding()]
    param(
        [Array] $DomainUsers
    )

    #$DomainUsers | Where-Object { $_.PasswordNotRequired -eq $true }
    #| Select-Object * #Name, SamAccountName, UserPrincipalName, Enabled
    foreach ($_ in $DomainUsers) {
        if ($_.PasswordNotRequired -eq $true) {
            $_
        }
    }
}