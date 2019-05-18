Clear-Host
Import-Module .\PSWinDocumentation.AD.psd1 -Force

$Forest = Get-WinADForestInformation -Verbose
$Forest.FoundDomains.'ad.evotec.xyz'