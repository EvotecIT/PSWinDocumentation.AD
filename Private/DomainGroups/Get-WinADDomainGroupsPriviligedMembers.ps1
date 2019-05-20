function Get-WinADDomainGroupsPriviligedMembers {
    [CmdletBinding()]
    param(
        [Array] $DomainGroupsMembers,
        [Array] $DomainGroupsPriviliged
    )
    # Needs review
    #$DomainGroupsMembers | Where-Object { $DomainGroupsPriviliged.'Group SID' -contains ($_.'Group SID') } | Select-Object * #-Exclude Group*, 'High Privileged Group'

    foreach ($_ in $DomainGroupsMembers) {
        if ($DomainGroupsPriviliged.'Group SID' -contains ($_.'Group SID')) {
            $_
        }
    }
}