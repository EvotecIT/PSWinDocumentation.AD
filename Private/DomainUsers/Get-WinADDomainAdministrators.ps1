function Get-WinADDomainAdministrators {
    [CmdletBinding()]
    param(
        [Array] $DomainGroupsMembers,
        $DomainInformation
    )
    $DomainGroupsMembers | Where-Object { $_.'Group SID' -eq $('{0}-512' -f $DomainInformation.DomainSID.Value) } | Select-Object * -Exclude Group*, 'High Privileged Group'
}