function Get-WinADForestFSMO {
    [CmdletBinding()]
    param(
        [PSCustomObject] $Forest
    )
    [ordered] @{
        'Domain Naming Master' = $Forest.DomainNamingMaster
        'Schema Master'        = $Forest.SchemaMaster
    }
}