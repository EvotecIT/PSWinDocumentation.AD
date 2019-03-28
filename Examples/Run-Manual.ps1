Import-Module PSWinDocumentation.AD -Force

$Forest = Get-WinADForestInformation -Verbose
$Forest




#Set-ADUser -PasswordLas