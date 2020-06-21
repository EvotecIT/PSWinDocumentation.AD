function Get-WinADDomainAllUsersCount {
    [CmdletBinding()]
    param(
        [Array] $DomainUsers,
        [Array] $DomainUsersAll,
        [Array] $DomainUsersExpiredExclDisabled,
        [Array] $DomainUsersExpiredInclDisabled,
        [Array] $DomainUsersNeverExpiring,
        [Array] $DomainUsersNeverExpiringInclDisabled,
        [Array] $DomainUsersSystemAccounts
    )
    <#
    $DomainUsersCount = [ordered] @{
        'Users Count Incl. System'            = Get-ObjectCount -Object $DomainUsers
        'Users Count'                         = Get-ObjectCount -Object $DomainUsersAll
        'Users Expired'                       = Get-ObjectCount -Object $DomainUsersExpiredExclDisabled
        'Users Expired Incl. Disabled'        = Get-ObjectCount -Object $DomainUsersExpiredInclDisabled
        'Users Never Expiring'                = Get-ObjectCount -Object $DomainUsersNeverExpiring
        'Users Never Expiring Incl. Disabled' = Get-ObjectCount -Object $DomainUsersNeverExpiringInclDisabled
        'Users System Accounts'               = Get-ObjectCount -Object $DomainUsersSystemAccounts
    }
    #>
    $DomainUsersCount = [ordered] @{
        'Users Count Incl. System'            = $DomainUsers.Count
        'Users Count'                         = $DomainUsersAll.Count
        'Users Expired'                       = $DomainUsersExpiredExclDisabled.Count
        'Users Expired Incl. Disabled'        = $DomainUsersExpiredInclDisabled.Count
        'Users Never Expiring'                = $DomainUsersNeverExpiring.Count
        'Users Never Expiring Incl. Disabled' = $DomainUsersNeverExpiringInclDisabled.Count
        'Users System Accounts'               = $DomainUsersSystemAccounts.Count
    }
    return $DomainUsersCount
}
