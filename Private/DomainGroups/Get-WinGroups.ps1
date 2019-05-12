function Get-WinGroups {
    [CmdletBinding()]
    param (
        [System.Object[]] $Groups,
        [System.Object[]] $Users,
        [string] $Domain = $Env:USERDNSDOMAIN,
        [string] $Splitter
    )
    $ReturnGroups = foreach ($Group in $Groups) {
        #$User = $Users | & { process { if ($_.DistinguishedName -eq $Group.ManagedBy ) { $_ } } } # | Where-Object { $_.DistinguishedName -eq $Group.ManagedBy }
        $User = foreach ($_ in $Users) {
            if ($_.DistinguishedName -eq $Group.ManagedBy) { $_ }
        }

        [PsCustomObject][ordered] @{
            'Group Name'            = $Group.Name
            #'Group Display Name' = $Group.DisplayName
            'Group Category'        = $Group.GroupCategory
            'Group Scope'           = $Group.GroupScope
            'Group SID'             = $Group.SID.Value
            'High Privileged Group' = if ($Group.adminCount -eq 1) { $True } else { $False }
            'Member Count'          = $Group.Members.Count
            'MemberOf Count'        = $Group.MemberOf.Count
            'Manager'               = $User.Name
            'Manager Email'         = $User.EmailAddress
            'Group Members'         = (Get-ADObjectFromDistingusishedName -Splitter $Splitter -ADCatalog $Data.DomainUsersFullList, $Data.DomainComputersFullList, $Data.DomainGroupsFullList -DistinguishedName $Group.Members -Type 'SamAccountName')
            'Group Members DN'      = if ($Splitter -ne '') { $Group.Members -join $Splitter } else { $Group.Members }
            "Domain"                = $Domain
        }
    }
    return $ReturnGroups
}