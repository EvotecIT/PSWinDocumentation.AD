Clear-Host
Import-Module .\PSWinDocumentation.AD.psd1 -Force

#$Forest = Get-WinADForestInformation -Verbose
$Forest.FoundDomains.'ad.evotec.xyz'

return
#$Forest.FoundDomains.'ad.evotec.xyz'
$Forest.FoundDomains.'ad.evotec.xyz'.DomainDNSA
return

# Below some options are show how to get specific information.

$User = $Forest.FoundDomains.'ad.evotec.xyz'.DomainUsers[20] | Select-Object *
$User | Select-Object DisplayName, PasswordLastSet


$PasswordDaysSinceChange = $User.PasswordLastSet - [DateTime]::Today
$PasswordDaysSinceChange

$Domain = Get-WinADDomainInformation -Domain 'ad.evotec.pl' -Verbose
$Domain.DomainFineGrainedPolicies
$Domain.DomainFineGrainedPoliciesUsers | Format-Table -AutoSize
$Domain.DomainFineGrainedPoliciesUsersExtended | format-Table -AutoSize