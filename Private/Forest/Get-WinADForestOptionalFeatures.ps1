function Get-WinADForestOptionalFeatures {
    [CmdletBinding()]
    param(
        [Array] $ComputerProperties
    )
    if (-not $ComputerProperties) {
        $ComputerProperties = Get-WinADForestSchemaPropertiesComputers
    }
    $LapsProperties = 'ms-Mcs-AdmPwd' #  'ms-Mcs-AdmPwdExpirationTime'
    $OptionalFeatures = $(Get-ADOptionalFeature -Filter * )
    $Optional = [ordered]@{
        'Recycle Bin Enabled'                          = $false
        'Privileged Access Management Feature Enabled' = $false
        'Laps Enabled'                                 = ($ComputerProperties.Name -contains $LapsProperties)
    }
    foreach ($Feature in $OptionalFeatures) {
        if ($Feature.Name -eq 'Recycle Bin Feature') {
            $Optional.'Recycle Bin Enabled' = $Feature.EnabledScopes.Count -gt 0
        }
        if ($Feature.Name -eq 'Privileged Access Management Feature') {
            $Optional.'Privileged Access Management Feature Enabled' = $Feature.EnabledScopes.Count -gt 0
        }
    }
    return $Optional
}