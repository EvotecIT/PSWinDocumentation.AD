function Get-WinADDomainComputersAll {
    [CmdletBinding()]
    param(
        [Array] $DomainComputersFullList

    )
    foreach ($_ in $DomainComputersFullList) {
        [PSCustomObject] @{
            SamAccountName             = $_.SamAccountName
            Enabled                    = $_.Enabled
            OperatingSystem            = $_.OperatingSystem
            PasswordLastSet            = $_.PasswordLastSet
            IPv4Address                = $_.IPv4Address
            IPv6Address                = $_.IPv6Address
            Name                       = $_.Name
            DNSHostName                = $_.DNSHostName
            ManagedBy                  = $_.ManagedBy
            OperatingSystemVersion     = $_.OperatingSystemVersion
            OperatingSystemHotfix      = $_.OperatingSystemHotfix
            OperatingSystemServicePack = $_.OperatingSystemServicePack
            PasswordNeverExpires       = $_.PasswordNeverExpires
            PasswordNotRequired        = $_.PasswordNotRequired
            UserPrincipalName          = $_.UserPrincipalName
            LastLogonDate              = $_.LastLogonDate
            LockedOut                  = $_.LockedOut
            LogonCount                 = $_.LogonCount
            CanonicalName              = $_.CanonicalName
            SID                        = $_.SID
            Created                    = $_.Created
            Modified                   = $_.Modified
            Deleted                    = $_.Deleted
            MemberOf                   = $_.MemberOf
        }
    }
}