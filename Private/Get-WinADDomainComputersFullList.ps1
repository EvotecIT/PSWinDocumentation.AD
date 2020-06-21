function Get-WinADDomainComputersFullList {
    [cmdletbinding()]
    param(
        [string] $Domain = $Env:USERDNSDOMAIN,
        [Array] $ForestSchemaComputers,
        [System.Collections.IDictionary] $DomainObjects,
        [int] $ResultPageSize = 500000
    )
    if ($Extended) {
        [string] $Properties = '*'
    } else {
        [string[]] $Properties = @(
            'SamAccountName', 'Enabled', 'OperatingSystem',
            'PasswordLastSet', 'IPv4Address', 'IPv6Address', 'Name', 'DNSHostName',
            'ManagedBy', 'OperatingSystemVersion', 'OperatingSystemHotfix',
            'OperatingSystemServicePack' , 'PasswordNeverExpires',
            'PasswordNotRequired', 'UserPrincipalName',
            'LastLogonDate', 'LockedOut', 'LogonCount',
            'CanonicalName', 'SID', 'Created', 'Modified',
            'Deleted', 'MemberOf', 'PrimaryGroup', 'ProtectedFromAccidentalDeletion'
            if ($ForestSchemaComputers.Name -contains 'ms-Mcs-AdmPwd') {
                'ms-Mcs-AdmPwd'
                'ms-Mcs-AdmPwdExpirationTime'
            }
        )
    }
    $Computers = Get-ADComputer -Server $Domain -Filter * -ResultPageSize $ResultPageSize -Properties $Properties -ErrorAction SilentlyContinue #| Select-Object -Property $Properties -ExcludeProperty $ExcludeProperty
    if ($null -ne $DomainObjects) {
        foreach ($_ in $Computers) {
            $DomainObjects[$_.DistinguishedName] = $_
        }
    }
    $Computers
}