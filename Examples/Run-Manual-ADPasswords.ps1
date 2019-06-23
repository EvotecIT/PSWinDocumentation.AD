#Clear-Host
Import-Module PSWinDocumentation.AD

#$PathToPasswords = 'C:\Users\pklys\OneDrive - Evotec\Support\GitHub\PSWinDocumentation\Ignore\Passwords.txt'
#$PathToPasswordsHashes = 'C:\Users\pklys\Downloads\pwned-passwords-ntlm-ordered-by-count\pwned-passwords-ntlm-ordered-by-count.txt'

$Forest = Get-WinADForestInformation -Verbose -PathToPasswords $PathToPasswords -PasswordQuality

<#
$Domain = Get-WinADDomainInformation -Domain 'ad.evotec.xyz' -Verbose -PathToPasswords $PathToPasswords #-PathToPasswordsHashes $PathToPasswordsHashes
$Domain.DomainPasswordClearTextPassword | Format-Table -Autosize
$Domain.DomainPasswordLMHash | Format-Table -Autosize
$Domain.DomainPasswordEmptyPassword | Format-Table -Autosize
$Domain.DomainPasswordWeakPassword | Format-Table -Autosize
$Domain.DomainPasswordDefaultComputerPassword | Format-Table -Autosize
$Domain.DomainPasswordPasswordNotRequired | Format-Table -Autosize
$Domain.DomainPasswordPasswordNeverExpires | Format-Table -Autosize
$Domain.DomainPasswordAESKeysMissing | Format-Table -Autosize
$Domain.DomainPasswordPreAuthNotRequired | Format-Table -Autosize
$Domain.DomainPasswordDESEncryptionOnly | Format-Table -Autosize
$Domain.DomainPasswordDelegatableAdmins | Format-Table -Autosize
$Domain.DomainPasswordDuplicatePasswordGroups | Format-Table -Autosize
$Domain.DomainPasswordHashesWeakPassword | Format-Table -Autosize
$Domain.DomainPasswordStats | Format-Table -a
$Domain.DomainPasswordHashesStats | Format-Table -a
#>