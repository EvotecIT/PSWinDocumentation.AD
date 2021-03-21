Import-Module .\PSWinDocumentation.AD.psd1 -Force

# Using built-in password list (just one password P@ssw0rd!)
$Passwords = Invoke-ADPasswordAnalysis
$Passwords.'ad.evotec.xyz'.DomainPasswordDuplicatePasswordGroups | Format-Table -AutoSize 'Duplicate Group', *

New-HTML {
    New-HTMLTable -DataTable $Passwords.'ad.evotec.xyz'.DomainPasswordDuplicatePasswordGroups -PriorityProperties 'Duplicate Group'
} -Online -FilePath $Env:USERPROFILE\Desktop\Passwords.html -ShowHTML