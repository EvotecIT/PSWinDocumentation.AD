Import-Module PSWinDocumentation.AD -Force

Measure-Collection -Name 'WinAD Forest' {
    $DataSetForest = Get-WinADForestInformation
}