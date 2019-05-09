Import-Module .\PSWinDocumentation.AD.psd1 -Force

$Forest = Get-WinADForestInformation -Verbose -PasswordQuality -DontRemoveSupportData
$Forest

Write-Color 'Ad.evotec.xyz' -Color Red

$Forest.FoundDomains.'ad.evotec.xyz'

Write-Color 'Ad.evotec.pl' -Color Red

$Forest.FoundDomains.'ad.evotec.pl'


return

$Forest.FoundDomains.'ad.evotec.xyz'
$Forest.FoundDomains.'ad.evotec.xyz'.DomainPasswordClearTextPassword


return
$Forest.FoundDomains.'ad.evotec.xyz'.DomainUsersExpiredInclDisabled | ft -a
$Forest.FoundDomains.'ad.evotec.xyz'.DomainUsersAll | ft -a

