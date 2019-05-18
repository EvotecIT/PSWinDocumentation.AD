Import-Module .\PSWinDocumentation.AD.psd1 -Force

$Forest = Get-WinADForestInformation -Verbose -PasswordQuality -DontRemoveSupportData -Splitter "`r`n" # -TypesRequired DomainUsers
$Forest.FoundDomains.'ad.evotec.xyz'