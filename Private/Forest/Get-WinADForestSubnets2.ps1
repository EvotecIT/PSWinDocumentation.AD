function Get-WinADForestSubnets2 {
    param(
        [Array] $ForestSubnets
    )
    @(
        foreach ($Subnets in $ForestSubnets) {
            [PsCustomObject] @{
                'Name' = $Subnets.Name
                'Site' = $Subnets.Site
            }
        }
    )
}