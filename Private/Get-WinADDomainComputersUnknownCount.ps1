function Get-WinADDomainComputersUnknownCount {
    [CmdletBinding()]
    param(
        [Array] $DomainComputersUnknown
    )
    $DomainComputersUnknown | Group-Object -Property OperatingSystem | Select-Object @{ L = 'System Name'; Expression = { if ($_.Name -ne '') { $_.Name } else { 'Unknown' } } } , @{ L = 'System Count'; Expression = { $_.Count } }
}