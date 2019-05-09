function Get-WinADDomainComputers {
    [CmdletBinding()]
    param(
        [Array] $DomainComputersAll
    )
    $DomainComputersAll | & { process { if ($_.OperatingSystem -notlike 'Windows Server*' -and $null -ne $_.OperatingSystem) { $_ } } }   #    | Where-Object { $_.OperatingSystem -notlike 'Windows Server*' -and $_.OperatingSystem -ne $null }
}