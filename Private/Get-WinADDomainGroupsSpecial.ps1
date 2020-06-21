function Get-WinADDomainGroupsSpecial {
    [CmdletBinding()]
    param(
        [Array] $DomainGroups
    )
    #$DomainGroups | Where-Object { ($_.'Group SID').Length -eq 12 }
    foreach ($_ in $DomainGroups) {
        if (($_.'Group SID').Length -eq 12) {
            $_
        }
    }
}