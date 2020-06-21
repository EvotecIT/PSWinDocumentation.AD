function Get-WinADDomainUsersExpiredInclDisabled {
    [CmdletBinding()]
    param(
        [Array] $DomainUsers
    )

    #$DomainUsers | Where-Object { $_.PasswordNeverExpires -eq $false -and $_.DaysToExpire -le 0 -and $_.PasswordNotRequired -eq $false }
    foreach ($_ in $DomainUsers) {
        if ($_.PasswordNeverExpires -eq $false -and $_.DaysToExpire -le 0 -and $_.PasswordNotRequired -eq $false) {
            $_
        }
    }
    #| Select-Object * #Name, SamAccountName, UserPrincipalName, Enabled
}