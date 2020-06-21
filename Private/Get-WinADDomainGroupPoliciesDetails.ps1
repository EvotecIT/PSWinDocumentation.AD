function Get-WinADDomainGroupPoliciesDetails {
    [CmdletBinding()]
    param(
        [Array] $GroupPolicies,
        [string] $Domain = $Env:USERDNSDOMAIN,
        [string] $Splitter
    )
    if ($null -eq $GroupPolicies) {
        $GroupPolicies = Get-GPO -Domain $Domain -All
    }
    ForEach ($GPO in $GroupPolicies) {
        [xml]$XmlGPReport = $GPO.generatereport('xml')
        #GPO version
        if ($XmlGPReport.GPO.Computer.VersionDirectory -eq 0 -and $XmlGPReport.GPO.Computer.VersionSysvol -eq 0) {
            $ComputerSettings = "NeverModified"
        } else {
            $ComputerSettings = "Modified"
        }
        if ($XmlGPReport.GPO.User.VersionDirectory -eq 0 -and $XmlGPReport.GPO.User.VersionSysvol -eq 0) {
            $UserSettings = "NeverModified"
        } else {
            $UserSettings = "Modified"
        }
        #GPO content
        if ($null -eq $XmlGPReport.GPO.User.ExtensionData) {
            $UserSettingsConfigured = $false
        } else {
            $UserSettingsConfigured = $true
        }
        if ($null -eq $XmlGPReport.GPO.Computer.ExtensionData) {
            $ComputerSettingsConfigured = $false
        } else {
            $ComputerSettingsConfigured = $true
        }
        #Output
        [PsCustomObject] @{
            'Name'                   = $XmlGPReport.GPO.Name
            'Links'                  = $XmlGPReport.GPO.LinksTo | Select-Object -ExpandProperty SOMPath
            'Has Computer Settings'  = $ComputerSettingsConfigured
            'Has User Settings'      = $UserSettingsConfigured
            'User Enabled'           = $XmlGPReport.GPO.User.Enabled
            'Computer Enabled'       = $XmlGPReport.GPO.Computer.Enabled
            'Computer Settings'      = $ComputerSettings
            'User Settings'          = $UserSettings
            'Gpo Status'             = $GPO.GpoStatus
            'Creation Time'          = $GPO.CreationTime
            'Modification Time'      = $GPO.ModificationTime
            'WMI Filter'             = $GPO.WmiFilter.name
            'WMI Filter Description' = $GPO.WmiFilter.Description
            'Path'                   = $GPO.Path
            'GUID'                   = $GPO.Id
            'SDDL'                   = if ($Splitter -ne '') { $XmlGPReport.GPO.SecurityDescriptor.SDDL.'#text' -join $Splitter } else { $XmlGPReport.GPO.SecurityDescriptor.SDDL.'#text' }
            #'ACLs'                   = $XmlGPReport.GPO.SecurityDescriptor.Permissions.TrusteePermissions | ForEach-Object -Process {
            #    New-Object -TypeName PSObject -Property @{
            #        'User'            = $_.trustee.name.'#Text'
            #        'Permission Type' = $_.type.PermissionType
            #        'Inherited'       = $_.Inherited
            #        'Permissions'     = $_.Standard.GPOGroupedAccessEnum
            #    }
            #}
        }
    }
}