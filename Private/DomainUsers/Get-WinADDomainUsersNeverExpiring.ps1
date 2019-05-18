function Get-WinADDomainUsersNeverExpiring {
    [CmdletBinding()]
    param(
        [Array] $DomainUsers
    )
    #$DomainUsers | Where-Object { $_.PasswordNeverExpires -eq $true -and $_.Enabled -eq $true -and $_.PasswordNotRequired -eq $false }
    foreach ($_ in $DomainUsers) {
        if ($_.PasswordNeverExpires -eq $true -and $_.Enabled -eq $true -and $_.PasswordNotRequired -eq $false) {
            $_
        }
    }
}