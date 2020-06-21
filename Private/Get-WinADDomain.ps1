function Get-WinADDomain {
    [CmdletBinding()]
    param(
        [string] $Domain = $Env:USERDNSDOMAIN
    )
    try {
        Get-ADDomain -Server $Domain -ErrorAction Stop
    } catch {
        $null
    }
}