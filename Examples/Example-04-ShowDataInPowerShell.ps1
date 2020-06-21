Clear-Host
Import-Module .\PSWinDocumentation.AD.psd1 -Force

$Forest = Get-WinADForestInformation -RequireTypes DomainGroupsPriviliged -Verbose
$Forest.FoundDomains.'ad.evotec.xyz'.DomainGroups | Format-Table -AutoSize
$Forest.FoundDomains.'ad.evotec.xyz'.DomainGroupsPriviliged | Format-Table -AutoSize
$Forest.FoundDomains.'ad.evotec.xyz'.DomainUsers | Where-Object { $_.PasswordNeverExpires -eq $false } | Select-Object Name, PasswordExpired, PasswordLastSet, 'PasswordLastChanged(Days)', DaysToExpire, DateExpiry | Format-Table -a