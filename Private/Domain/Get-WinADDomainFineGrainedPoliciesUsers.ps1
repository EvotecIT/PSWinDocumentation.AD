function Get-WinADDomainFineGrainedPoliciesUsers {
    [CmdletBinding()]
    param(
        [Array] $DomainFineGrainedPolicies,
        #[Array] $DomainUsersFullList,
        #[Array] $DomainGroupsFullList,
        [hashtable] $DomainObjects
    )

    $PolicyUsers = foreach ($Policy in $DomainFineGrainedPolicies) {
        $AllObjects = foreach ($U in $Policy.'Applies To') {
            Get-ADObjectFromDNHash -ADCatalog $DomainObjects -DistinguishedName $U
            #Get-ADObjectFromDistingusishedName -ADCatalog $DomainUsersFullList -DistinguishedName $U
        }
        #$Groups = foreach ($U in $Policy.'Applies To') {
        #    Get-ADObjectFromDNHash -ADCatalog $DomainObjects -DistinguishedName $U
            #Get-ADObjectFromDistingusishedName -ADCatalog $DomainGroupsFullList -DistinguishedName $U
        #}
        foreach ($_ in $AllObjects) {
            [PsCustomObject] @{
                'Policy Name'  = $Policy.Name
                Name           = $_.Name
                SamAccountName = $_.SamAccountName
                Type           = $_.ObjectClass
                SID            = $_.SID
            }
        }
        <#
        foreach ($Group in $Groups) {
            [PsCustomObject] @{
                'Policy Name'  = $Policy.Name
                Name           = $Group.Name
                SamAccountName = $Group.SamAccountName
                Type           = $Group.ObjectClass
                SID            = $Group.SID
            }
        }
        #>
    }
    #Get-AdFineGrainedPassowrdPolicySubject
    #Get-AdresultantPasswordPolicy -Identity <user>
    return $PolicyUsers
}