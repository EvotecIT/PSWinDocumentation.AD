Import-Module .\PSWinDocumentation.AD.psd1 -Force

$TypesRequired = @(
    [PSWinDocumentation.ActiveDirectory].GetEnumValues() | Where-Object { $_ -like 'DomainPassword*' }
)

$Forest = Get-WinADForestInformation -Verbose -PasswordQuality -DontRemoveSupportData -Splitter "`r`n" -TypesRequired $TypesRequired
$Forest.FoundDomains['ad.evotec.xyz']