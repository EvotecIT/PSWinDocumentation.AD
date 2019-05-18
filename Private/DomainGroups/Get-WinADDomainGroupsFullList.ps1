function Get-WinADDomainGroupsFullList {
    [CmdletBinding()]
    param(
        [string] $Domain = $Env:USERDNSDOMAIN,
        [HashTable] $DomainObjects,
        [int] $ResultPageSize = 500000
    )
    #[string[]] $Properties = '*'
    #[string[]] $ExcludeProperty = '*Certificate', 'PropertyNames', '*Properties', 'PropertyCount', 'Certificates', 'nTSecurityDescriptor'

    if ($Extended) {
        [string] $Properties = '*'
    } else {
        [string[]] $Properties = @(
            'adminCount'
            'CanonicalName'
            'CN'
            'Created'
            'createTimeStamp'
            'Deleted'
            'Description'
            'DisplayName'
            'DistinguishedName'
            #'dSCorePropagationData'
            'GroupCategory'
            'GroupScope'
            'groupType'
            'HomePage'
            'instanceType'
            'isCriticalSystemObject'
            'isDeleted'
            'LastKnownParent'
            'ManagedBy'
            'member'
            'MemberOf'
            'Members'
            'Modified'
            'modifyTimeStamp'
            'Name'
            'nTSecurityDescriptor'
            'ObjectCategory'
            'ObjectClass'
            'ObjectGUID'
            'objectSid'
            'ProtectedFromAccidentalDeletion'
            'SamAccountName'
            'sAMAccountType'
            'sDRightsEffective'
            'SID'
            'SIDHistory'
            'systemFlags'
            'uSNChanged'
            'uSNCreated'
            'whenChanged'
            'whenCreated'
        )
    }
    $Groups = Get-ADGroup -Server $Domain -Filter * -ResultPageSize $ResultPageSize -Properties $Properties #| Select-Object -Property $Properties -ExcludeProperty $ExcludeProperty
    foreach ($_ in $Groups) {
        $DomainObjects.$($_.DistinguishedName) = $_
    }
    $Groups
}