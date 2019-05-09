function Get-WinADDomainUsersNeverExpiring {
    param(
        [Array] $DomainUsers
    )

    $DomainUsers | Where-Object { $_.PasswordNeverExpires -eq $true -and $_.Enabled -eq $true -and $_.PasswordNotRequired -eq $false }
}