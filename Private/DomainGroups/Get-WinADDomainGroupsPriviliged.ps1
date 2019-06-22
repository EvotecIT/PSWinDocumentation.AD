function Get-DomainGroupsPriviliged {
    [cmdletbinding()]
    param(
        [Microsoft.ActiveDirectory.Management.ADDomain] $DomainInformation,
        [Array] $DomainGroups
    )
    $PrivilegedGroupsSID = @(
        "S-1-5-32-544"
        "S-1-5-32-548"
        "S-1-5-32-549"
        "S-1-5-32-550"
        "S-1-5-32-551"
        "S-1-5-32-552"
        "S-1-5-32-556"
        "S-1-5-32-557"
        "S-1-5-32-573"
        "S-1-5-32-578"
        "S-1-5-32-580"
        "$($DomainInformation.DomainSID.Value)-512"
        "$($DomainInformation.DomainSID.Value)-518"
        "$($DomainInformation.DomainSID.Value)-519"
        "$($DomainInformation.DomainSID.Value)-520"
    )
    # $DomainGroups | Where-Object { $PrivilegedGroupsSID -contains $_.'Group SID' }
    foreach ($_ in $DomainGroups) {
        if ($PrivilegedGroupsSID -contains $_.'Group SID' ) {
            $_
        }
    }
}