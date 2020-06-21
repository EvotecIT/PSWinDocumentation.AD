function Get-WinADDomainTrustsClean {
    [CmdletBinding()]
    param(
        [string] $Domain = $Env:USERDNSDOMAIN
    )
    Get-ADTrust -Server $Domain -Filter * -Properties * -ErrorAction SilentlyContinue
}