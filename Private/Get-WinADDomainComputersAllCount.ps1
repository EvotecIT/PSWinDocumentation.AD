function Get-WinADDomainComputersAllCount {
    [CmdletBinding()]
    param(
        [Array] $DomainComputersAll
    )
    $DomainComputersAll | `
        Group-Object -Property OperatingSystem | `
        Select-Object @{ L = 'System Name'; Expression = { if ($_.Name -ne '') { $_.Name } else { 'Unknown' } } } , @{ L = 'System Count'; Expression = { $_.Count } }

}