Import-Module .\PSWinDocumentation.AD.psd1 -Force

$Forest = Get-WinADForestInformation -Verbose -PasswordQuality -DontRemoveEmpty -Parallel -Splitter "`r`n"
$Forest