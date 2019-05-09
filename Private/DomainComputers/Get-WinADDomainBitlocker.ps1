function Get-WinADDomainBitlocker {
    [CmdletBinding()]
    param(
        [string] $Domain = $Env:USERDNSDOMAIN,
        [Array] $Computers
    )
    $Properties = @(
        'Name',
        'OperatingSystem',
        'DistinguishedName'
    )
    if ($null -eq $Computers) {
        $Computers = Get-ADComputer -Filter * -Properties $Properties -Server $Domain
    }
    foreach ($Computer in $Computers) {
        try {
            $Bitlockers = Get-ADObject -Filter 'objectClass -eq "msFVE-RecoveryInformation"' -SearchBase $Computer.DistinguishedName -Properties 'WhenCreated', 'msFVE-RecoveryPassword' #|  Sort-Object whenCreated -Descending #| Select-Object whenCreated, msFVE-RecoveryPassword
        } catch {
            $ErrorMessage = $_.Exception.Message -replace "`n", " " -replace "`r", " "
            if ($ErrorMessage -like "*The supplied distinguishedName must belong to one of the following partition(s)*") {
                Write-Warning "Getting domain information - $Domain - Couldn't get Bitlocker information. Most likely not enabled."
            } else {
                Write-Warning "Getting domain information - $Domain - Couldn't get Bitlocker information. Error: $ErrorMessage"
            }
            return
        }
        foreach ($Bitlocker in $Bitlockers) {
            [PSCustomObject] @{
                'Name'                        = $Computer.Name
                'Operating System'            = $Computer.'OperatingSystem'
                'Bitlocker Recovery Password' = $Bitlocker.'msFVE-RecoveryPassword'
                'Bitlocker When'              = $Bitlocker.WhenCreated
                'DistinguishedName'           = $Computer.'DistinguishedName'
            }
        }
    }
}