function Get-WinADAccounts {
    [CmdletBinding()]
    param(
        [Object] $UserNameList,
        [Array[]] $ADCatalog
    )
    $Accounts = foreach ($User in $UserNameList) {
        foreach ($Catalog in $ADCatalog) {
            #$Element = $Catalog | & { process { if ($_.SamAccountName -eq $User ) { $_ } } }  #| Where-Object { $_.SamAccountName -eq $User }
            foreach ($_ in $Catalog) {
                if ($_.SamAccountName -eq $User ) { $_ }
            }
            #Add-ToArrayAdvanced -Element $Element -List $Accounts -SkipNull
        }
    }
    return $Accounts
}