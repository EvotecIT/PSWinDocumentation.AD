function Get-WinADDomainDNSData {
    [CmdletBinding()]
    param(
        [string] $Domain = $Env:USERDNSDOMAIN
    )
    $DnsRecords = "_kerberos._tcp.$Domain", "_ldap._tcp.$Domain"
    $DNSData = foreach ($DnsRecord in $DnsRecords) {
        $Value = Resolve-DnsName -Name $DnsRecord -Type SRV -Verbose:$false -ErrorAction SilentlyContinue #| Select-Object *
        if ($null -eq $Value) {
            Write-Warning 'Getting domain information - DomainDNSSRV / DomainDNSA - Failed!'
        }
        $Value
    }
    $ReturnData = @{}
    $ReturnData.Srv = foreach ($V in $DNSData) {
        if ($V.QueryType -eq 'SRV') {
            $V | Select-Object Target, NameTarget, Priority, Weight, Port, Name
        }
    }

    $ReturnData.A = foreach ($V in $DNSData) {
        if ($V.QueryType -ne 'SRV') {
            $V | Select-Object Address, IPAddress, IP4Address, Name, Type, DataLength, TTL
        }
    }
    return $ReturnData
}