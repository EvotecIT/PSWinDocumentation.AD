function Get-WinADRootDSE {
    [CmdletBinding()]
    param(
        [string] $Domain = ($Env:USERDNSDOMAIN).ToLower()
    )
    try {
        if ($Domain -ne '') {
            Get-ADRootDSE -Properties * -Server $Domain
        } else {
            Get-ADRootDSE -Properties *
        }
    } catch {
        Write-Warning "Getting forest/domain information - $Domain RootDSE Error: $($_.Error)"
    }
}