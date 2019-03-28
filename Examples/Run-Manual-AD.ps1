Clear-Host
Import-Module PSWinDocumentation.AD

$Forest = Get-WinADForestInformation -Verbose

$User = $Forest.FoundDomains.'ad.evotec.xyz'.DomainUsers[20] | Select *
$User | Select-Object DisplayName, PasswordLastSet


$PasswordDaysSinceChange = $User.PasswordLastSet - [DateTime]::Today
$PasswordDaysSinceChange

$Domain = Get-WinADDomainInformation -Domain 'ad.evotec.pl' -Verbose
$Domain.DomainFineGrainedPolicies
$Domain.DomainFineGrainedPoliciesUsers | Format-Table -AutoSize
$Domain.DomainFineGrainedPoliciesUsersExtended | format-Table -AutoSize