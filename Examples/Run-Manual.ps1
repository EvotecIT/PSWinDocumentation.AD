Import-Module .\PSWinDocumentation.AD.psd1 -Force

$Forest = Get-WinADForestInformation -Verbose -PasswordQuality
$Forest.FoundDomains.'ad.evotec.xyz'.DomainPasswordClearTextPassword


return
$Forest.FoundDomains.'ad.evotec.xyz'.DomainUsersExpiredInclDisabled | ft -a
$Forest.FoundDomains.'ad.evotec.xyz'.DomainUsersAll | ft -a

