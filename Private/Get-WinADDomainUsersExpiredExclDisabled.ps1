function Get-WinADDomainUsersExpiredExclDisabled {
    [CmdletBinding()]
    param(
        [Array] $DomainUsers
    )

    #$DomainUsers | Where-Object { $_.PasswordNeverExpires -eq $false -and $_.DaysToExpire -le 0 -and $_.Enabled -eq $true -and $_.PasswordNotRequired -eq $false } #| Select-Object * # Name, SamAccountName, UserPrincipalName, Enabled
    foreach ($_ in $DomainUsers) {
        if ($_.PasswordNeverExpires -eq $false -and $_.DaysToExpire -le 0 -and $_.Enabled -eq $true -and $_.PasswordNotRequired -eq $false) {
            $_
        }
    }
}