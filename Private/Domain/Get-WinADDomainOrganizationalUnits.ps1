function Get-WinADDomainOrganizationalUnits {
    [CmdletBinding()]
    param(
        [string] $Domain = $Env:USERDNSDOMAIN,
        [Array] $OrgnaizationalUnits,
        [hashtable] $DomainObjects
    )
    if ($null -eq $OrgnaizationalUnits) {
        $OrgnaizationalUnits = $(Get-ADOrganizationalUnit -Server $Domain -Properties * -Filter * )
    }
    $Output = foreach ($_ in $OrgnaizationalUnits) {
        $Manager = Get-ADObjectFromDNHash -ADCatalog $DomainObjects -DistinguishedName $_.ManagedBy

        [PSCustomObject] @{
            'Canonical Name'  = $_.CanonicalName
            'Managed'         = $Manager.Name
            'Manager Email'   = $Manager.EmailAddress
            'Protected'       = $_.ProtectedFromAccidentalDeletion
            Description       = $_.Description
            Created           = $_.Created
            Modified          = $_.Modified
            Deleted           = $_.Deleted
            'PostalCode'      = $_.PostalCode
            City              = $_.City
            Country           = $_.Country
            State             = $_.State
            'StreetAddress'   = $_.StreetAddress
            DistinguishedName = $_.DistinguishedName
            ObjectGUID        = $_.ObjectGUID
        }
    }
    $Output | Sort-Object 'Canonical Name'
}