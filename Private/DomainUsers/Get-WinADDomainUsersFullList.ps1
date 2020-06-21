function Get-WinADDomainUsersFullList {
    [CmdletBinding()]
    param(
        [string] $Domain = $Env:USERDNSDOMAIN,
        [switch] $Extended,
        [Array] $ForestSchemaUsers,
        [System.Collections.IDictionary] $DomainObjects,
        [int] $ResultPageSize = 500000
    )
    if ($null -eq $ForestSchemaUsers) {
        $ForestSchemaUsers = @(
            $Schema = [directoryservices.activedirectory.activedirectoryschema]::GetCurrentSchema()
            @(
                $Schema.FindClass("user").MandatoryProperties #| Select-Object name, commonname, description, syntax #| export-csv user-mandatory-attributes.csv -Delimiter ';'
                $Schema.FindClass("user").OptionalProperties #| Select-Object name, commonname, description, syntax #| export-csv user-optional-attributes.csv -Delimiter ';'
                $Schema.FindClass("user").PossibleSuperiors #| Select-Object name, commonname, description, syntax
                $Schema.FindClass("user").PossibleInferiors #| Select-Object name, commonname, description, syntax
                $Schema.FindClass("user").AuxiliaryClasses
            )
            # $Schema.FindClass("user").FindAllProperties() | Select-Object name, commonname, description, syntax
        )

    }

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
    $Users = Get-ADUser -Server $Domain -ResultPageSize $ResultPageSize -Filter * -Properties $Properties #| Select-Object -Property $Properties -ExcludeProperty $ExcludeProperty
    if ($null -ne $DomainObjects) {
        foreach ($_ in $Users) {
            $DomainObjects[$_.DistinguishedName] = $_
        }
    }
    $Users
}