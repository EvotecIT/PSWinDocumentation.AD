function Get-WinADDomainEnterpriseAdministratorsRecursive {
    [CmdletBinding()]
    param(
        [Array] $DomainGroupsMembersRecursive,
        $DomainInformation
    )
   # $DomainGroupsMembersRecursive | Where-Object { $_.'Group SID' -eq $('{0}-519' -f $DomainInformation.DomainSID.Value) } | Select-Object * -Exclude Group*, 'High Privileged Group'
    $Members = foreach ($_ in $DomainGroupsMembersRecursive) {
        if ($_.'Group SID' -eq $('{0}-519' -f $DomainInformation.DomainSID.Value)) {
            $_
        }
    }
    $Members | Select-Object * -Exclude Group*, 'High Privileged Group'
}