Import-Module PSWinDocumentation.AD -Force

#$Forest = Get-WinADForestInformation -Verbose
$Forest.FoundDomains.'ad.evotec.xyz'.DomainUsersExpiredInclDisabled | ft -a
$Forest.FoundDomains.'ad.evotec.xyz'.DomainUsersAll | ft -a

