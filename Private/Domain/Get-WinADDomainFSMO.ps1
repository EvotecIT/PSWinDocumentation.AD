function Get-WinADDomainFSMO {
    [CmdletBinding()]
    param(
        [string] $Domain = $Env:USERDNSDOMAIN,
        [Microsoft.ActiveDirectory.Management.ADDomain] $DomainInformation
    )
    #Write-Verbose "Getting domain information - $Domain DomainFSMO"
    #$Time = Start-TimeLog
    # required for multiple use cases FSMO/DomainTrusts
    [ordered] @{
        'PDC Emulator'          = $DomainInformation.PDCEmulator
        'RID Master'            = $DomainInformation.RIDMaster
        'Infrastructure Master' = $DomainInformation.InfrastructureMaster
    }

    #$EndTime = Stop-TimeLog -Time $Time -Option OneLiner
    #Write-Verbose "Getting domain information - $Domain DomainFSMO Time: $EndTime"
}