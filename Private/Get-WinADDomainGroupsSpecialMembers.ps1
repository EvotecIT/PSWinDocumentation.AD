function Get-WinADDomainGroupsSpecialMembers {
    [CmdletBinding()]
    param(
        [Array] $DomainGroupsMembers
    )
    # $DomainGroupsMembers | Where-Object { ($_.'Group SID').Length -eq 12 } | Select-Object * #-Exclude Group*, 'High Privileged Group'

    foreach ($_ in $DomainGroupsMembers) {
        if (($_.'Group SID').Length -eq 12) {
            $_
        }
    }
}