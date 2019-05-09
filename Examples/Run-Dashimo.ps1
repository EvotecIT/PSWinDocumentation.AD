
Import-Module Dashimo -Force
Import-Module .\PSWinDocumentation.AD.psd1 -Force

if ($null -eq $DataSetForest) {
    $DataSetForest = Get-WinADForestInformation -Verbose -PasswordQuality -DontRemoveEmpty
}

Dashboard -Name 'Dashimo Test' -FilePath $PSScriptRoot\DashboardActiveDirectory.html -Show {
    Tab -Name 'Forest' {
        foreach ($ForestKey in $DataSetForest.Keys | Where-Object { $_ -ne 'FoundDomains' }) {
            Section -Name $ForestKey -Collapsable {
                Table -DataTable $DataSetForest.$ForestKey -HideFooter
            }
        }
    }
    foreach ($Domain in $DataSetForest.FoundDomains.Keys) {
        Tab -Name "$Domain" {
            foreach ($Key in $DataSetForest.FoundDomains.$Domain.Keys | Where-Object { $_ -notlike 'DomainPassword*' } ) {
                Section -Name $Key -Collapsable {
                    Table -DataTable $DataSetForest.FoundDomains.$Domain.$Key -HideFooter
                }
            }
        }
        Tab -Name "$Domain - Password Quality" {
            foreach ($Key in $DataSetForest.FoundDomains.$Domain.Keys | Where-Object { $_ -like 'DomainPassword*' } ) {
                Section -Name $Key -Collapsable {
                    Table -DataTable $DataSetForest.FoundDomains.$Domain.$Key -HideFooter
                }
            }
        }
    }
}