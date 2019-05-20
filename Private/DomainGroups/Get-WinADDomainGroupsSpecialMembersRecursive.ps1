function Get-WinADDomainGroupsSpecialMembersRecursive {
    [CmdletBinding()]
    param(
        [Array] $DomainGroupsMembersRecursive
    )
    #$DomainGroupsMembersRecursive | Where-Object { ($_.'Group SID').Length -eq 12 } | Select-Object * #-Exclude Group*, 'High Privileged Group'

    foreach ($_ in $DomainGroupsMembersRecursive) {
        if (($_.'Group SID').Length -eq 12) {
            $_
        }
    }
}