function Get-ADObjectFromDNHash {
    [CmdletBinding()]
    param (
        [string[]] $DistinguishedName,
        [hashtable] $ADCatalog,
        [string] $Type = '',
        [string] $Splitter # ', ' # Alternative for example [System.Environment]::NewLine
    )
    if ($null -eq $DistinguishedName) {
        return
    }
    $FoundObjects = foreach ($DN in $DistinguishedName) {
        if ($Type -eq '') {
            $ADCatalog.$DN
        } else {
            $ADCatalog.$DN.$Type
        }
    }
    if ($Splitter) {
        return ($FoundObjects | Sort-Object) -join $Splitter
    } else {
        return $FoundObjects | Sort-Object
    }
}