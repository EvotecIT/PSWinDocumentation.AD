Clear-Host
#Import-Module .\PSWinDocumentation.AD.psd1 -Force

#$Forest = Get-WinADForestInformation -Verbose
$Forest.FoundDomains.'ad.evotec.xyz'.DomainUsers | Where-Object { $_.PasswordNeverExpires -eq $false } | Select Name, PasswordExpired, PasswordLastSet, 'PasswordLastChanged(Days)', DaysToExpire, DateExpiry | ft -a