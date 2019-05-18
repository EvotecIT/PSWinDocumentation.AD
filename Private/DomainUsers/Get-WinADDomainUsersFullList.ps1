function Get-WinADDomainUsersFullList {
    [CmdletBinding()]
    param(
        [string] $Domain = $Env:USERDNSDOMAIN,
        [switch] $Extended,
        [Array] $ForestSchemaUsers,
        [HashTable] $DomainObjects,
        [int] $ResultPageSize = 500000
    )
    #Write-Verbose "Getting domain information - $Domain DomainUsersFullList"
    #$TimeUsers = Start-TimeLog
    if ($Extended) {
        [string] $Properties = '*'
    } else {
        $Properties = @(
            'Name'
            'UserPrincipalName'
            'SamAccountName'
            'DisplayName'
            'GivenName'
            'Surname'
            'EmailAddress'
            'PasswordExpired'
            'PasswordLastSet'
            'PasswordNotRequired'
            'PasswordNeverExpires'
            'Enabled'
            'Manager'
            'msDS-UserPasswordExpiryTimeComputed'
            'AccountExpirationDate'
            'AccountLockoutTime'
            'AllowReversiblePasswordEncryption'
            'BadLogonCount'
            'CannotChangePassword'
            'CanonicalName'
            'Description'
            'DistinguishedName'
            'EmployeeID'
            'EmployeeNumber'
            'LastBadPasswordAttempt'
            'LastLogonDate'
            'Created'
            'Modified'
            'ProtectedFromAccidentalDeletion'
            'PrimaryGroup'
            'MemberOf'
            if ($ForestSchemaUsers.Name -contains 'ExtensionAttribute1') {
                'ExtensionAttribute1'
                'ExtensionAttribute2'
                'ExtensionAttribute3'
                'ExtensionAttribute4'
                'ExtensionAttribute5'
                'ExtensionAttribute6'
                'ExtensionAttribute7'
                'ExtensionAttribute8'
                'ExtensionAttribute9'
                'ExtensionAttribute10'
                'ExtensionAttribute11'
                'ExtensionAttribute12'
                'ExtensionAttribute13'
                'ExtensionAttribute14'
                'ExtensionAttribute15'
            }
        )
    }

    #[string[]] $ExcludeProperty = '*Certificate', 'PropertyNames', '*Properties', 'PropertyCount', 'Certificates', 'nTSecurityDescriptor'

    $Users = Get-ADUser -Server $Domain -ResultPageSize $ResultPageSize -Filter * -Properties $Properties #| Select-Object -Property $Properties -ExcludeProperty $ExcludeProperty
    foreach ($_ in $Users) {
        $DomainObjects.$($_.DistinguishedName) = $_
    }
    $Users
    #$EndUsers = Stop-TimeLog -Time $TimeUsers -Option OneLiner
    #Write-Verbose "Getting domain information - $Domain DomainUsersFullList Time: $EndUsers"
}