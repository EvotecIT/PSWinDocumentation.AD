function Get-WinADDomainFSMO {
    [CmdletBinding()]
    param(
        [string] $Domain = $Env:USERDNSDOMAIN,
        [Microsoft.ActiveDirectory.Management.ADDomain] $DomainInformation
    )
    # required for multiple use cases FSMO/DomainTrusts
    [ordered] @{
        'PDC Emulator'          = $DomainInformation.PDCEmulator
        'RID Master'            = $DomainInformation.RIDMaster
        'Infrastructure Master' = $DomainInformation.InfrastructureMaster
    }
}