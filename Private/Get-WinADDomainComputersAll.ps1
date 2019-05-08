function Get-WinADDomainComputersAll {
    [CmdletBinding()]
    param(
        [Array] $DomainComputersFullList

    )
    $DomainComputersFullList | Select-Object SamAccountName, Enabled, OperatingSystem, PasswordLastSet, IPv4Address, IPv6Address, Name, DNSHostName, ManagedBy, OperatingSystemVersion, OperatingSystemHotfix, OperatingSystemServicePack , PasswordNeverExpires, PasswordNotRequired, UserPrincipalName, LastLogonDate, LockedOut, LogonCount, CanonicalName, SID, Created, Modified, Deleted, MemberOf
}