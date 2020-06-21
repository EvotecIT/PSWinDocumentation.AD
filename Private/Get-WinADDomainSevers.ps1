function Get-WinADDomainServers {
    [CmdletBinding()]
    param(
        [Array] $DomainComputersAll
    )
    #$DomainComputersAll  | & { process { if ($_.OperatingSystem -like 'Windows Server*') { $_ } } } #| Where-Object { $_.OperatingSystem -like 'Windows Server*' }
    foreach ($_ in $DomainComputersAll) {
        if ($_.OperatingSystem -like 'Windows Server*') {
            $_
        }
    }
}