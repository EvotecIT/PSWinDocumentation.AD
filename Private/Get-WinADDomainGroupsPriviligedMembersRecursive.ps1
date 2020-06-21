function Get-WinADDomainGroupsPriviligedMembersRecursive {
    [CmdletBinding()]
    param(
        [Array] $DomainGroupsMembersRecursive,
        [Array] $DomainGroupsPriviliged
    )
    # Needs review
    #$DomainGroupsMembersRecursive | Where-Object { $DomainGroupsPriviliged.'Group SID' -contains ($_.'Group SID') } | Select-Object * #-Exclude Group*, 'High Privileged Group'
    foreach ($_ in $DomainGroupsMembersRecursive) {
        if ($DomainGroupsPriviliged.'Group SID' -contains ($_.'Group SID')) {
            $_
        }
    }
}