function Get-WinADDomainGroupsSpecial {
    param(
        [Array] $DomainGroups
    )
    $DomainGroups | Where-Object { ($_.'Group SID').Length -eq 12 }
}