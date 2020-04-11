function Get-WinADPasswordAnalysis {
    [CmdletBinding()]
    param(

    )

    $Properties = @(
        'Name', 'UserPrincipalName', 'Enabled', 'PasswordLastChanged', "DaysToExpire",
        'PasswordExpired', 'PasswordNeverExpires', 'PasswordNotRequired', 'DateExpiry', 'PasswordLastSet', 'SamAccountName',
        'EmailAddress', 'Display Name', 'Given Name', 'Surname', 'Manager', 'Manager Email',
        "AccountExpirationDate", "AccountLockoutTime", "AllowReversiblePasswordEncryption", "BadLogonCount",
        "CannotChangePassword", "CanonicalName", "Description", "DistinguishedName", "EmployeeID", "EmployeeNumber", "LastBadPasswordAttempt",
        "LastLogonDate", "Created", "Modified", "Protected", "Primary Group", "Member Of", "Domain"
    )

    $Forest = Get-ADForest
    $Output = [ordered] @{ }

    foreach ($Domain in $Forest.Domains) {
        $DC = Get-ADDomainController -Discover -DomainName $Domain
        if ($DC) {
            $DomainInformation = Get-ADDomain -Identity $Domain
            if ($DomainInformation) {
                $Passwords = Get-WinADDomainPassword -DnsRoot $DomainInformation.DNSRoot -DistinguishedName $DomainInformation.DistinguishedName
                $Users = Get-ADUser -Filter * -Server $DC.Hostname[0] -Properties $Properties
                $Computers = Get-ADComputer -Filter * -Server $DC.Hostname[0] -Properties $Properties

                $Quality = Get-WinADDomainPasswordQuality -DnsRoot $DomainInformation.DnsRoot -DomainUsersAll $Users -DomainComputersAll $Computers -PasswordQuality -DomainDistinguishedName $DomainInformation.DistinguishedName -PasswordQualityUsers $Passwords
                $Output["$($DomainInformation.DnsRoot)"] = $Quality
            }
        }
    }
    $Output
}