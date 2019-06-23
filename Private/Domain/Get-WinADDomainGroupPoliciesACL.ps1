function Get-WinADDomainGroupPoliciesACL {
    [CmdletBinding()]
    param(
        [Array] $GroupPolicies,
        [string] $Domain = $Env:USERDNSDOMAIN
    )
    if ($null -eq $GroupPolicies) {
        $GroupPolicies = Get-GPO -Domain $Domain -All
    }
    $Output = ForEach ($GPO in $GroupPolicies) {
        [xml]$XmlGPReport = $GPO.generatereport('xml')
        $ACLs = $XmlGPReport.GPO.SecurityDescriptor.Permissions.TrusteePermissions
        foreach ($ACL in $ACLS) {
            [PsCustomObject] @{
                'GPO Name'        = $GPO.DisplayName
                'User'            = $ACL.trustee.name.'#Text'
                'Permission Type' = $ACL.type.PermissionType
                'Inherited'       = $ACL.Inherited
                'Permissions'     = $ACL.Standard.GPOGroupedAccessEnum
            }
        }
    }
    return $Output
}