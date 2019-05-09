function Get-WinADDomainUsersSystemAccounts {
    param(
        [Array] $DomainUsers
    )

    $DomainUsers | Where-Object { $_.PasswordNotRequired -eq $true }
    #| Select-Object * #Name, SamAccountName, UserPrincipalName, Enabled
}