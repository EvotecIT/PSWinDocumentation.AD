function Get-WinADDomainDNSData {
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
    $ReturnData.DNSSrv = foreach ($V in $DNSData) {
        if ($V.QueryType -eq 'SRV') {
            $V | Select-Object Target, NameTarget, Priority, Weight, Port, Name
        }
    }

    $ReturnData.DnsA = foreach ($V in $DNSData) {
        if ($V.QueryType -ne 'SRV') {
            $V | Select-Object Address, IPAddress, IP4Address, Name, Type, DataLength, TTL
        }
    }

    #$ReturnData = @{
    # QueryType, Target, NameTarget, Priority, Weight, Port, Name, Type, CharacterSet, Section
    #    SRV = $DnsSrv | Select-Object Target, NameTarget, Priority, Weight, Port, Name # Type, QueryType, CharacterSet, Section
    # Address, IPAddress, QueryType, IP4Address, Name, Type, CharacterSet, Section, DataLength, TTL
    #    A   = $DnsA | Select-Object Address, IPAddress, IP4Address, Name, Type, DataLength, TTL # QueryType, CharacterSet, Section
    #}
    return $ReturnData
}