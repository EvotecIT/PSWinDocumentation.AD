function Get-WinADDomainComputersAllBuildSummary {
    [CmdletBinding()]
    param(
        [Array] $DomainComputers,
        [switch] $Formatted
    )
    if ($Formatted) {
        $DomainComputers | Group-Object -Property OperatingSystemBuild | Sort-Object -Property Name | `
            Select-Object @{ L = 'System Name'; Expression = { if ($_.Name -ne '') { $_.Name } else { 'N/A' } } } , @{ L = 'System Count'; Expression = { $_.Count } }
    } else {
        $DomainComputers | Group-Object -Property OperatingSystemBuild | Sort-Object -Property Name
    }
}