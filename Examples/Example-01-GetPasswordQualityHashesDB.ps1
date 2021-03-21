Import-Module .\PSWinDocumentation.AD.psd1 -Force

# Using Hashes from IHaveBeenPwned
$PathToPasswordsHashes = 'C:\Users\przemyslaw.klys\Downloads\pwned-passwords-ntlm-ordered-by-hash-v6\pwned-passwords-ntlm-ordered-by-hash-v6.txt'
$Passwords = Invoke-ADPasswordAnalysis -PathToPasswords $PathToPasswordsHashes -UseNTLMHashes
$Passwords.'ad.evotec.xyz' | Format-Table