function Get-WinADForestSPNSuffixes {
    [CmdletBinding()]
    param(
        [PSCustomObject] $Forest
    )
    @(
        #[PSCustomObject] @{
        #Name = $Forest.RootDomain
        #Type = 'Primary / Default SPN'
        #}
        foreach ($SPN in $Forest.SPNSuffixes) {
            [PSCustomObject] @{
                Name = $SPN
                #Type = 'Secondary'
            }
        }
    )
}