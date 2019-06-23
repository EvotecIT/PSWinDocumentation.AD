function Get-WinADForestSubnets1 {
    [CmdletBinding()]
    param(
        [Array] $ForestSubnets
    )
     foreach ($Subnets in $ForestSubnets) {
        [PsCustomObject] @{
            'Name'        = $Subnets.Name
            'Description' = $Subnets.Description
            'Protected'   = $Subnets.ProtectedFromAccidentalDeletion
            'Modified'    = $Subnets.Modified
            'Created'     = $Subnets.Created
            'Deleted'     = $Subnets.Deleted
        }
    }
}