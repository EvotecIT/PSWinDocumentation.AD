function Get-WinADDomainComputersCount {
    [CmdletBinding()]
    param(
        [Array] $DomainComputers
    )
    $DomainComputers | Group-Object -Property OperatingSystem | Select-Object @{ L = 'System Name'; Expression = { if ($_.Name -ne '') { $_.Name } else { 'N/A' } } } , @{ L = 'System Count'; Expression = { $_.Count } }
}