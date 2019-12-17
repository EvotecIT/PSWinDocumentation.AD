function Get-WinADForestGUIDs {
    [alias('Get-WinADDomainGUIDs')]
    [cmdletbinding()]
    param(
        [string] $Domain = $Env:USERDNSDOMAIN,
        [Microsoft.ActiveDirectory.Management.ADEntity] $RootDSE
    )
    if ($null -eq $RootDSE) {
        $RootDSE = Get-ADRootDSE -Server $Domain
    }
    $GUID = @{ }
    $GUID.Add('00000000-0000-0000-0000-000000000000', 'All')
    $Schema = Get-ADObject -SearchBase $RootDSE.schemaNamingContext -LDAPFilter '(schemaIDGUID=*)' -Properties name, schemaIDGUID
    foreach ($S in $Schema) {
        <#
        if ($GUID.Keys -notcontains $S.schemaIDGUID ) {
            $GUID.add([System.GUID]$S.schemaIDGUID, $S.name)
        }
        #>
        $GUID["$(([System.GUID]$S.schemaIDGUID).Guid)"] = $S.name
    }


    $Extended = Get-ADObject -SearchBase "CN=Extended-Rights,$($RootDSE.configurationNamingContext)" -LDAPFilter '(objectClass=controlAccessRight)' -Properties name, rightsGUID
    foreach ($S in $Extended) {
        <#
        if ($GUID.Keys -notcontains $S.rightsGUID ) {
            $GUID.add([System.GUID]$S.rightsGUID, $S.name)
        }
        #>
        $GUID["$(([System.GUID]$S.rightsGUID).Guid)"] = $S.name
    }
    return $GUID
}