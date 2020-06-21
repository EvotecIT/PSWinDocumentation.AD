function Get-WinADDomainControllersInternal {
    [CmdletBinding()]
    param(
        [string] $Domain
    )
    $DomainControllersClean = Get-ADDomainController -Server $Domain -Filter *
    foreach ($DC in $DomainControllersClean) {
        [PsCustomObject] @{
            'Name'             = $DC.Name
            'Host Name'        = $DC.HostName
            'Operating System' = $DC.OperatingSystem
            'Site'             = $DC.Site
            'Ipv4'             = $DC.Ipv4Address
            'Ipv6'             = $DC.Ipv6Address
            'Global Catalog?'  = $DC.IsGlobalCatalog
            'Read Only?'       = $DC.IsReadOnly
            'Ldap Port'        = $DC.LdapPort
            'SSL Port'         = $DC.SSLPort
        }
    }
}