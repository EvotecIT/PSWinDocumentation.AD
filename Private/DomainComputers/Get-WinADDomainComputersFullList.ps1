function Get-WinADDomainComputersFullList {
    [cmdletbinding()]
    param(
        [string] $Domain = $Env:USERDNSDOMAIN,
        [Array] $ForestSchemaComputers,
        [HashTable] $DomainObjects,
        [int] $ResultPageSize = 500000
    )
    #Write-Verbose "Getting domain information - $Domain DomainComputersFullList"
    #$TimeUsers = Start-TimeLog

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
    # [string[]] $ExcludeProperty = '*Certificate', 'PropertyNames', '*Properties', 'PropertyCount', 'Certificates', 'nTSecurityDescriptor'

    $Computers = Get-ADComputer -Server $Domain -Filter * -ResultPageSize $ResultPageSize -Properties $Properties -ErrorAction SilentlyContinue #| Select-Object -Property $Properties -ExcludeProperty $ExcludeProperty
    foreach ($_ in $Computers) {
        #$DomainObjects.$($_.DistinguishedName) = $_
        #$DomainObjects.Add($_.DistinguishedName, $_)
        $DomainObjects[$_.DistinguishedName] = $_
    }
    $Computers
    #$EndUsers = Stop-TimeLog -Time $TimeUsers -Option OneLiner
    # Write-Verbose "Getting domain information - $Domain DomainComputersFullList Time: $EndUsers"
}