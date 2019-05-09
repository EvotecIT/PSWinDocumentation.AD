function Get-WinADDomainPassword {
    [CmdletBinding()]
    param(
        $DnsRoot,
        $DistinguishedName
    )
    try {
        Get-ADReplAccount -All -Server $DnsRoot -NamingContext $DistinguishedName
    } catch {
        $ErrorMessage = $_.Exception.Message -replace "`n", " " -replace "`r", " "
        if ($ErrorMessage -like '*is not recognized as the name of a cmdlet*') {
            Write-Warning "Get-ADReplAccount - Please install module DSInternals (Install-Module DSInternals) - Error: $ErrorMessage"
        } else {
            Write-Warning "Get-ADReplAccount - Error occured: $ErrorMessage"
        }
    }
}

