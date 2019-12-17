function Get-WinADDomainPassword {
    [CmdletBinding()]
    param(
        [alias('DnsRoot')][string] $Server,
        [alias('DomainDN')][string] $DistinguishedName
    )
    try {
        Get-ADReplAccount -All -Server $Server -NamingContext $DistinguishedName
    } catch {
        $ErrorMessage = $_.Exception.Message -replace "`n", " " -replace "`r", " "
        if ($ErrorMessage -like '*is not recognized as the name of a cmdlet*') {
            Write-Warning "Get-ADReplAccount - Please install module DSInternals (Install-Module DSInternals) - Error: $ErrorMessage"
        } else {
            Write-Warning "Get-ADReplAccount - Error occured: $ErrorMessage"
        }
    }
}