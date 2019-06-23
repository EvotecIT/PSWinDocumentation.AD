function Get-WinGroups {
    [CmdletBinding()]
    param (
        [Array] $Groups,
        # [System.Object[]] $Users,
        [string] $Domain = $Env:USERDNSDOMAIN,
        [string] $Splitter,
        [hashtable] $DomainObjects
    )
    $ReturnGroups = foreach ($Group in $Groups) {
        #$User = $Users | & { process { if ($_.DistinguishedName -eq $Group.ManagedBy ) { $_ } } } # | Where-Object { $_.DistinguishedName -eq $Group.ManagedBy }
        #$User = foreach ($_ in $Users) {
        #    if ($_.DistinguishedName -eq $Group.ManagedBy) { $_ }
        #}
        $Manager = Get-ADObjectFromDNHash -ADCatalog $DomainObjects -DistinguishedName $Group.ManagedBy
        # $GroupMembers = (Get-ADObjectFromDistingusishedName -Splitter $Splitter -ADCatalog $Data.DomainUsersFullList, $Data.DomainComputersFullList, $Data.DomainGroupsFullList -DistinguishedName $Group.Members -Type 'SamAccountName')
        #$GroupMembers = Get-ADObjectFromDNHash -ADCatalog $DomainObjects -DistinguishedName $Group.Members -Splitter $Splitter -Type 'SamAccountName'

        [PsCustomObject] @{
            'Group Name'            = [string] $Group.Name
            #'Group Display Name' = $Group.DisplayName
            'Group Category'        = [string] $Group.GroupCategory
            'Group Scope'           = [string] $Group.GroupScope
            'Group SID'             = [string] $Group.SID.Value
            'High Privileged Group' = if ($Group.adminCount -eq 1) { $True } else { $False }
            'Member Count'          = $Group.Members.Count
            'MemberOf Count'        = $Group.MemberOf.Count
            'Manager'               = $Manager.Name
            'Manager Email'         = if ($Splitter -ne '') { $Manager.EmailAddress -join $Splitter } else { $Manager.EmailAddress }
            'Group Members'         = Get-ADObjectFromDNHash -ADCatalog $DomainObjects -DistinguishedName $Group.Members -Splitter $Splitter -Type 'SamAccountName'
            'Group Members DN'      = $Group.Members #if ($Splitter -ne '') { $Group.Members -join $Splitter } else { $Group.Members }
            "Domain"                = $Domain
        }
    }
    return $ReturnGroups
}