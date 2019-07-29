function Get-WinADForestSchemaPropertiesComputers {
    [CmdletBinding()]
    param(

    )
    $Schema = [directoryservices.activedirectory.activedirectoryschema]::GetCurrentSchema()
    @(
        $Schema.FindClass("computer").mandatoryproperties | Select-Object name, commonname, description, syntax
        $Schema.FindClass("computer").optionalproperties | Select-Object name, commonname, description, syntax #| Where-Object { $_.Name -eq 'ms-Mcs-AdmPwd' } # ft -AutoSize
    )
}