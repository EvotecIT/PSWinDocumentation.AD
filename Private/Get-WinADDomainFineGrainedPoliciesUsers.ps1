function Get-WinADDomainFineGrainedPoliciesUsers {
    [CmdletBinding()]
    param(
        [Array] $DomainFineGrainedPolicies,
        [Array] $DomainUsersFullList,
        [Array] $DomainGroupsFullList
    )

    $PolicyUsers = foreach ($Policy in $DomainFineGrainedPolicies) {
        $Users = foreach ($U in $Policy.'Applies To') {
            Get-ADObjectFromDistingusishedName -ADCatalog $DomainUsersFullList -DistinguishedName $U
        }
        $Groups = foreach ($U in $Policy.'Applies To') {
            Get-ADObjectFromDistingusishedName -ADCatalog $DomainGroupsFullList -DistinguishedName $U
        }
        foreach ($User in $Users) {
            [pscustomobject][ordered] @{
                'Policy Name'  = $Policy.Name
                Name           = $User.Name
                SamAccountName = $User.SamAccountName
                Type           = $User.ObjectClass
                SID            = $User.SID
            }
        }
        foreach ($Group in $Groups) {
            [pscustomobject][ordered] @{
                'Policy Name'  = $Policy.Name
                Name           = $Group.Name
                SamAccountName = $Group.SamAccountName
                Type           = $Group.ObjectClass
                SID            = $Group.SID
            }
        }
    }
    #Get-AdFineGrainedPassowrdPolicySubject
    #Get-AdresultantPasswordPolicy -Identity <user>
    return $PolicyUsers
}