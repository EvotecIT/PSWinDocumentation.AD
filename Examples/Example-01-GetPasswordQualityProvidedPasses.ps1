Import-Module .\PSWinDocumentation.AD.psd1 -Force

# Using a list of passwords
$PathToPasswords = 'C:\Support\GitHub\PSWinDocumentation.AD\Ignore\Passwords.txt'
$Passwords = Invoke-ADPasswordAnalysis -PathToPasswords $PathToPasswords
$Passwords.'ad.evotec.xyz' | Format-Table