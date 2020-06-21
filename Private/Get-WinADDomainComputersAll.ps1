function Get-WinADDomainComputersAll {
    [CmdletBinding()]
    param(
        [Array] $DomainComputersFullList,
        [string] $Splitter,
        [System.Collections.IDictionary] $DomainObjects,
        [System.Collections.IDictionary] $DomainObjectsNetbios,
        [Object] $Domaininformation

    )
    [DateTime] $CurrentDate = Get-Date
    foreach ($_ in $DomainComputersFullList) {
        $Manager = Get-ADObjectFromDNHash -ADCatalog $DomainObjects -DistinguishedName $_.ManagedBy
        $Computer = [PSCustomObject] @{
            SamAccountName              = $_.SamAccountName
            Enabled                     = $_.Enabled
            OperatingSystem             = $_.OperatingSystem
            PasswordLastSet             = $_.PasswordLastSet
            'PasswordLastChanged(Days)' = if ($null -ne $_.PasswordLastSet) { "$(-$($_.PasswordLastSet - $CurrentDate).Days)" } else { }
            IPv4Address                 = $_.IPv4Address
            IPv6Address                 = $_.IPv6Address
            Name                        = $_.Name
            DNSHostName                 = $_.DNSHostName
            'Manager'                   = $Manager.Name
            'ManagerEmail'              = if ($Splitter -ne '') { $Manager.EmailAddress -join $Splitter } else { $Manager.EmailAddress }
            OperatingSystemVersion      = $_.OperatingSystemVersion
            OperatingSystemHotfix       = $_.OperatingSystemHotfix
            OperatingSystemServicePack  = $_.OperatingSystemServicePack
            OperatingSystemBuild        = ConvertTo-OperatingSystem -OperatingSystem $_.OperatingSystem -OperatingSystemVersion $_.OperatingSystemVersion
            PasswordNeverExpires        = $_.PasswordNeverExpires
            PasswordNotRequired         = $_.PasswordNotRequired
            UserPrincipalName           = $_.UserPrincipalName
            LastLogonDate               = $_.LastLogonDate
            'LastLogonDate(Days)'       = if ($null -ne $_.LastLogonDate) { "$(-$($_.LastLogonDate - $CurrentDate).Days)" } else { }
            LockedOut                   = $_.LockedOut
            LogonCount                  = $_.LogonCount
            CanonicalName               = $_.CanonicalName
            SID                         = $_.SID
            Created                     = $_.Created
            Modified                    = $_.Modified
            Deleted                     = $_.Deleted
            "Protected"                 = $_.ProtectedFromAccidentalDeletion
            "PrimaryGroup"              = (Get-ADObjectFromDNHash -ADCatalog $DomainObjects -DistinguishedName $_.PrimaryGroup -Type 'SamAccountName')
            "MemberOf"                  = (Get-ADObjectFromDNHash -ADCatalog $DomainObjects -DistinguishedName $_.MemberOf -Type 'SamAccountName' -Splitter $Splitter)
        }
        $Name = -join ($Domaininformation.NetBIOSName, "\", $Computer.SamAccountName)
        $DomainObjectsNetbios[$Name] = $Computer
        $Computer
    }
}