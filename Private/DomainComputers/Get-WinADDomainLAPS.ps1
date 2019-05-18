function Get-WinADDomainLAPS {
    [CmdletBinding()]
    param(
        [string] $Domain = $Env:USERDNSDOMAIN,
        [Array] $Computers,
        [string] $Splitter
    )
    $Properties = @(
        'Name',
        'OperatingSystem',
        'DistinguishedName',
        'ms-Mcs-AdmPwd',
        'ms-Mcs-AdmPwdExpirationTime'
    )
    [DateTime] $CurrentDate = Get-Date

    if ($null -eq $Computers -or $Computers.Count -eq 0) {
        $Computers = Get-ADComputer -Filter * -Properties $Properties
    }
    foreach ($Computer in $Computers) {
        [PSCustomObject] @{
            'Name'               = $Computer.Name
            'Operating System'   = $Computer.'OperatingSystem'
            'LapsPassword'       = if ($Splitter -ne '') { $Computer.'ms-Mcs-AdmPwd' -join $Splitter } else { $Computer.'ms-Mcs-AdmPwd' } # For some reason it's an array Laps Password        : {}
            'LapsExpire(days)'   = Convert-TimeToDays -StartTime ($CurrentDate) -EndTime (Convert-ToDateTime -Timestring ($Computer.'ms-Mcs-AdmPwdExpirationTime'))
            'LapsExpirationTime' = Convert-ToDateTime -Timestring ($Computer.'ms-Mcs-AdmPwdExpirationTime')
            'DistinguishedName'  = $Computer.'DistinguishedName'
        }
    }
}