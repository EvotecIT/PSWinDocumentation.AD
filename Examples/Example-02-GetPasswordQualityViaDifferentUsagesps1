Import-Module .\PSWinDocumentation.AD.psd1 -Force

# If paths are not given it uses builtin Passw0rd! as weak password
#$PathToPasswords = 'C:\Users\pklys\OneDrive - Evotec\Support\GitHub\PSWinDocumentation\Ignore\Passwords.txt'
#$PathToPasswordsHashes = 'C:\Users\pklys\Downloads\pwned-passwords-ntlm-ordered-by-count\pwned-passwords-ntlm-ordered-by-count.txt'

$TypesRequired = @(
    [PSWinDocumentation.ActiveDirectory].GetEnumValues() | Where-Object { $_ -like 'DomainPassword*' }
)

$Forest = Get-WinADDomainInformation -Domain 'ad.evotec.xyz' -Verbose -PathToPasswords $PathToPasswords -PasswordQuality -TypesRequired $TypesRequired
$Forest

$Domain = Get-WinADDomainInformation -Domain 'ad.evotec.xyz' -Verbose -PathToPasswords $PathToPasswords -TypesRequired $TypesRequired -PasswordQuality #-PathToPasswordsHashes $PathToPasswordsHashes
$Domain.DomainPasswordClearTextPassword | Format-Table -AutoSize
$Domain.DomainPasswordLMHash | Format-Table -AutoSize
$Domain.DomainPasswordEmptyPassword | Format-Table -AutoSize
$Domain.DomainPasswordWeakPassword | Format-Table -AutoSize
$Domain.DomainPasswordDefaultComputerPassword | Format-Table -AutoSize
$Domain.DomainPasswordPasswordNotRequired | Format-Table -AutoSize
$Domain.DomainPasswordPasswordNeverExpires | Format-Table -AutoSize
$Domain.DomainPasswordAESKeysMissing | Format-Table -AutoSize
$Domain.DomainPasswordPreAuthNotRequired | Format-Table -AutoSize
$Domain.DomainPasswordDESEncryptionOnly | Format-Table -AutoSize
$Domain.DomainPasswordDelegatableAdmins | Format-Table -AutoSize
$Domain.DomainPasswordDuplicatePasswordGroups | Format-Table -AutoSize
$Domain.DomainPasswordHashesWeakPassword | Format-Table -AutoSize
$Domain.DomainPasswordStats | Format-Table -a
$Domain.DomainPasswordHashesStats | Format-Table -a