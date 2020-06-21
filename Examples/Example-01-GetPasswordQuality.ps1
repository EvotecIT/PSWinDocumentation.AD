Import-Module .\PSWinDocumentation.AD.psd1 -Force

$Passwords = Invoke-ADPasswordAnalysis
$Passwords.'ad.evotec.xyz'.DomainPasswordDuplicatePasswordGroups | Format-Table -AutoSize