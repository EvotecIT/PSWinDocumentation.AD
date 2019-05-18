function Get-WinADDomainAdministratorsRecursive {
    [CmdletBinding()]
    param(
        [Array] $DomainGroupsMembersRecursive,
        $DomainInformation
    )
    $DomainGroupsMembersRecursive | Where-Object { $_.'Group SID' -eq $('{0}-512' -f $DomainInformation.DomainSID.Value) } | Select-Object * -Exclude Group*, 'High Privileged Group'
}