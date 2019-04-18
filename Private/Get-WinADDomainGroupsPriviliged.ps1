function Get-DomainGroupsPriviliged {
    [cmdletbinding()]
    param(
        [Microsoft.ActiveDirectory.Management.ADDomain] $DomainInformation,
        $DomainGroups
    )
    $Time = Start-TimeLog
    Write-Verbose "Getting domain information - $Domain DomainGroupsPriviliged"
    $PrivilegedGroupsSID = "S-1-5-32-544", "S-1-5-32-548", "S-1-5-32-549", "S-1-5-32-550", "S-1-5-32-551", "S-1-5-32-552", "S-1-5-32-556", "S-1-5-32-557", "S-1-5-32-573", "S-1-5-32-578", "S-1-5-32-580", "$($DomainInformation.DomainSID)-512", "$($DomainInformation.DomainSID)-518", "$($DomainInformation.DomainSID)D-519", "$($DomainInformation.DomainSID)-520"
    # $DomainGroups | Where-Object { $PrivilegedGroupsSID -contains $_.'Group SID' }
    foreach ($_ in $DomainGroups) {
        if ($PrivilegedGroupsSID -contains $_.'Group SID' ) { $_ }
    }
    $EndTime = Stop-TimeLog -Time $Time -Option OneLiner
    Write-Verbose "Getting domain information - $Domain DomainGroupsPriviliged Time: $EndTime"
}