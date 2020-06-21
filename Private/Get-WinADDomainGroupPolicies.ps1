function Get-WinADDomainGroupPolicies {
    [CmdletBinding()]
    param(
        [Array] $GroupPolicies,
        [string] $Domain = $Env:USERDNSDOMAIN
    )
    if ($null -eq $GroupPolicies) {
        $GroupPolicies = Get-GPO -Domain $Domain -All
    }
    foreach ($gpo in $GroupPolicies) {
        [PsCustomObject] @{
            'Display Name'      = $gpo.DisplayName
            'Gpo Status'        = $gpo.GPOStatus
            'Creation Time'     = $gpo.CreationTime
            'Modification Time' = $gpo.ModificationTime
            'Description'       = $gpo.Description
            'Wmi Filter'        = $gpo.WmiFilter
        }
    }
}