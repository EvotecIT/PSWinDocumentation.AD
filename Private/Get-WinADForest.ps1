function Get-WinADForest {
    [CmdletBinding()]
    param()
    # $Time = Start-TimeLog
    #Write-Verbose 'Getting forest information - Forest'
    try {
        Get-ADForest -ErrorAction Stop #| Select-Object -Property * -ExcludeProperty PropertyNames, AddedProperties, RemovedProperties, ModifiedProperties, PropertyCount
    } catch {
        $null
    }
    #$EndTime = Stop-TimeLog -Time $Time -Option OneLiner
    #Write-Verbose "Getting forest information - Forest Time: $EndTime"
}