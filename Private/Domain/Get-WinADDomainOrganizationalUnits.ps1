function Get-WinADDomainOrganizationalUnits {
    [CmdletBinding()]
    param(
        [string] $Domain = $Env:USERDNSDOMAIN,
        [Array] $OrgnaizationalUnits,
        [hashtable] $DomainObjects
    )
    # Write-Verbose -Message "Getting domain information - $Domain DomainOrganizationalUnits"
    if ($null -eq $OrgnaizationalUnits) {
        $OrgnaizationalUnits = $(Get-ADOrganizationalUnit -Server $Domain -Properties * -Filter * )
    }
    # $TimeOU = Start-TimeLog
    $Output = foreach ($_ in $OrgnaizationalUnits) {
        $Manager = Get-ADObjectFromDNHash -ADCatalog $DomainObjects -DistinguishedName $_.ManagedBy

        [PSCustomObject] @{
            'Canonical Name'  = $_.CanonicalName
            # 'Managed By'      = (Get-ADObjectFromDistingusishedName -ADCatalog $Data.DomainUsersFullList -DistinguishedName $_.ManagedBy -Verbose).Name
            # 'Manager Email'   = (Get-ADObjectFromDistingusishedName -ADCatalog $Data.DomainUsersFullList -DistinguishedName $_.ManagedBy -Verbose).EmailAddress
            'Managed By'      = $Manager.Name
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
    # $EndOU = Stop-TimeLog -Time $TimeOU -Option OneLiner
    #Write-Verbose -Message "Getting domain information - $Domain DomainOrganizationalUnits Time: $EndOU"
    <#
        $Time44 = Start-TimeLog
    for ($i = 1; $i -lt 1000; $i++) {
        $OrgnaizationalUnits | Select-Object `
        @{ n = 'Canonical Name'; e = { $_.CanonicalName } },
        @{ n = 'Managed By'; e = {
                (Get-ADObjectFromDistingusishedName -ADCatalog $Data.DomainUsersFullList -DistinguishedName $_.ManagedBy -Verbose).Name
            }
        },
        @{ n = 'Manager Email'; e = {
                (Get-ADObjectFromDistingusishedName -ADCatalog $Data.DomainUsersFullList -DistinguishedName $_.ManagedBy -Verbose).EmailAddress
            }
        },
        @{ n = 'Protected'; e = { $_.ProtectedFromAccidentalDeletion } },
        Created,
        Modified,
        Deleted,
        @{ n = 'Postal Code'; e = { $_.PostalCode } },
        City,
        Country,
        State,
        @{ n = 'Street Address'; e = { $_.StreetAddress } },
        DistinguishedName,
        ObjectGUID | Sort-Object 'Canonical Name'

    }
    $End = Stop-TimeLog -Time $Time44 -Option OneLiner
    Write-Verbose $end
    #>
}