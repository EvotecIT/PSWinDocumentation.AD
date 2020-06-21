function Get-WinADDomainComputersUnknown {
    [CmdletBinding()]
    param(
        [Array] $DomainComputersAll
    )
    #$DomainComputersAll | & { process { if ( $null -eq $_.OperatingSystem ) { $_ } } } # | Where-Object { $_.OperatingSystem -eq $null }
    foreach ($_ in $DomainComputersAll) {
        if ( $null -eq $_.OperatingSystem ) {
            $_
        }
    }
}