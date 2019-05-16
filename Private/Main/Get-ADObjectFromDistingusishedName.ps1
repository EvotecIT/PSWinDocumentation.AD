function Get-ADObjectFromDistingusishedName {
    [CmdletBinding()]
    param (
        [string[]] $DistinguishedName,
        [Object[]] $ADCatalog,
        [string] $Type = '',
        [string] $Splitter # ', ' # Alternative for example [System.Environment]::NewLine
    )
    if ($null -eq $DistinguishedName) {
        return
    }
    $FoundObjects = foreach ($Catalog in $ADCatalog) {
        foreach ($Object in $DistinguishedName) {
            <#
            $ADObject = foreach ($_ in $Catalog) {
                if ($_.DistinguishedName -eq $Object ) { $_ }
            }
            if ($ADObject) {
                if ($Type -eq '') {
                    $ADObject
                } else {
                    $ADObject.$Type
                }
            }
            #>
            foreach ($_ in $Catalog) {
                if ($_.DistinguishedName -eq $Object ) {
                    if ($Type -eq '') {
                        $_
                    } else {
                        $_.$Type
                    }
                }
            }
        }
    }
    if ($Splitter) {
        return ($FoundObjects | Sort-Object) -join $Splitter
    } else {
        return $FoundObjects | Sort-Object
    }
}