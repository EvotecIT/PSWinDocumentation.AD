Import-Module .\PSWinDocumentation.AD.psd1 -Force

# Using built-in password list (just one password P@ssw0rd!)
$Passwords = Invoke-ADPasswordAnalysis
$Passwords.'ad.evotec.xyz'.DomainPasswordDuplicatePasswordGroups | Format-Table -AutoSize

return
# Using a list of passwords
$PathToPasswords = 'C:\Support\GitHub\PSWinDocumentation.AD\Ignore\Passwords.txt'
$Passwords = Invoke-ADPasswordAnalysis -PathToPasswords $PathToPasswords
$Passwords.'ad.evotec.xyz' | Format-Table

return
# Using Hashes from IHaveBeenPwned
$PathToPasswordsHashes = 'C:\Users\przemyslaw.klys\Downloads\pwned-passwords-ntlm-ordered-by-hash-v6\pwned-passwords-ntlm-ordered-by-hash-v6.txt'
$Passwords = Invoke-ADPasswordAnalysis -PathToPasswords $PathToPasswordsHashes -UseNTLMHashes
$Passwords.'ad.evotec.xyz' | Format-Table