Import-Module .\PSWinDocumentation.AD.psd1 -Force

if ($null -eq $Forest) {
    $Forest = Get-WinADForestInformation -Verbose -PasswordQuality -DontRemoveEmpty -Parallel -Splitter "`r`n"
}

Dashboard -Name 'Dashimo Test' -FilePath $PSScriptRoot\Output\DashboardActiveDirectory.html -Show {
    Tab -Name 'Forest' {
        foreach ($ForestKey in $Forest.Keys | Where-Object { $_ -ne 'FoundDomains' }) {
            Section -Name $ForestKey -Collapsable {
                Table -DataTable $Forest.$ForestKey -HideFooter
            }
        }
    }
    foreach ($Domain in $Forest.FoundDomains.Keys) {
        Tab -Name "$Domain" {
            foreach ($Key in $Forest.FoundDomains.$Domain.Keys | Where-Object { $_ -notlike 'DomainPassword*' -and $_ -ne 'DomainPasswordDataPasswords' } ) {
                Section -Name $Key -Collapsable {
                    Table -DataTable $Forest.FoundDomains.$Domain.$Key -HideFooter
                }
            }
        }
        Tab -Name "$Domain - Password Quality" {
            foreach ($Key in $Forest.FoundDomains.$Domain.Keys | Where-Object { $_ -like 'DomainPassword*' -and $_ -ne 'DomainPasswordDataPasswords' } ) {
                Section -Name $Key -Collapsable {
                    Table -DataTable $Forest.FoundDomains.$Domain.$Key -HideFooter
                }
            }
        }
    }
}