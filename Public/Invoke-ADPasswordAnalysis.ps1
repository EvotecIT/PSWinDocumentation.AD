﻿function Invoke-ADPasswordAnalysis {
    [CmdletBinding()]
    param(
        [alias('ForestName')][string] $Forest,
        [string[]] $ExcludeDomains,
        [alias('Domain', 'Domains')][string[]] $IncludeDomains,
        [System.Collections.IDictionary] $ExtendedForestInformation
    )
    $Forest = Get-ADForest
    $Output = [ordered] @{ }
    $DomainObjectsNetbios = @{}     # Cache
    $ForestInformation = Get-WinADForestDetails -Extended -Forest $Forest -IncludeDomains $IncludeDomains -ExcludeDomains $ExcludeDomains -ExtendedForestInformation $ExtendedForestInformation
    $ForestSchemaComputers = Get-WinADForestSchemaProperties -Schema 'Computers' -Forest $Forest
    $ForestSchemaUsers = Get-WinADForestSchemaProperties -Schema 'Users' -Forest $Forest
    foreach ($Domain in $ForestInformation.Domains) {
        $Passwords = Get-WinADDomainPassword -DnsRoot $ForestInformation.DomainsExtended[$Domain].DNSRoot -DistinguishedName $ForestInformation.DomainsExtended[$Domain].DistinguishedName
        $Users = Get-WinADDomainUsersFullList -Domain $Domain -Extended:$Extended -ForestSchemaUsers $ForestSchemaUsers -DomainObjects $Data.DomainObjects -ResultPageSize $ResultPageSize
        $Computers = Get-WinADDomainComputersFullList -Domain $Domain -ForestSchemaComputers $ForestSchemaComputers -DomainObjects $Data.DomainObjects -ResultPageSize $ResultPageSize
        # We use null because it returns all data to DomainObjectsNetbios cache which is then used to
        $null = Get-WinADDomainUsersAll -Users $Users -DomainObjectsNetbios $DomainObjectsNetbios -Domaininformation $ForestInformation.DomainsExtended[$Domain]
        $null = Get-WinADDomainComputersAll -DomainComputersFullList $Computers -DomainObjectsNetbios $DomainObjectsNetbios -Domaininformation $ForestInformation.DomainsExtended[$Domain]
        $Quality = Get-WinADDomainPasswordQuality -DnsRoot $ForestInformation.DomainsExtended[$Domain].DnsRoot -DomainObjectsNetbios $DomainObjectsNetbios -PasswordQuality -DomainDistinguishedName $ForestInformation.DomainsExtended[$Domain].DistinguishedName -PasswordQualityUsers $Passwords
        $Output["$($ForestInformation.DomainsExtended[$Domain].DnsRoot)"] = $Quality
    }
    $Output
}