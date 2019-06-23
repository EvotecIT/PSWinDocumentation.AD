Import-Module .\PSWinDocumentation.AD.psd1 -Force

Clear-Host
$Forest = Get-WinADForestInformation -Verbose -PasswordQuality -DontRemoveSupportData -Splitter "`r`n"  -TypesRequired DomainGroupsPriviliged
$Forest