function Get-WinADDomainUsersExpiredInclDisabled {
    param(
        [Array] $DomainUsers
    )

    $DomainUsers | Where-Object { $_.PasswordNeverExpires -eq $false -and $_.DaysToExpire -le 0 -and $_.PasswordNotRequired -eq $false }
    #| Select-Object * #Name, SamAccountName, UserPrincipalName, Enabled
}