Clear-Host
Import-Module "C:\Users\przemyslaw.klys\OneDrive - Evotec\Support\GitHub\PSPublishModule\PSPublishModule.psm1" -Force

$Configuration = @{
    Information = @{
        ModuleName        = 'PSWinDocumentation.AD'
        DirectoryProjects = 'C:\Support\GitHub'
        FunctionsToExport = 'Public'
        AliasesToExport   = 'Public'
        ScriptsToProcess  = 'Enums'

        Manifest          = @{
            # Version number of this module.
            ModuleVersion              = '0.1.X'
            # ID used to uniquely identify this module
            GUID                       = 'a46f9775-04d2-4423-9631-01cfda42b95d'
            # Author of this module
            Author                     = 'Przemyslaw Klys'
            # Company or vendor of this module
            CompanyName                = 'Evotec'
            # Copyright statement for this module
            Copyright                  = "(c) 2011 - $((Get-Date).Year) Przemyslaw Klys @ Evotec. All rights reserved."
            # Description of the functionality provided by this module
            Description                = 'Useful module that covers extractiong of Active Directory data into a single object that can be later on utilized for reporting or other means.'
            # Minimum version of the Windows PowerShell engine required by this module
            PowerShellVersion          = '5.1'
            # Tags applied to this module. These help with module discovery in online galleries.
            Tags                       = @('Windows', 'ActiveDirectory', 'ad')
            # A URL to the main website for this project.
            ProjectUri                 = 'https://github.com/EvotecIT/PSWinDocumentation.AD'
            # A URL to an icon representing this module.
            IconUri                    = 'https://evotec.xyz/wp-content/uploads/2018/10/PSWinDocumentation.png'
            # Modules that must be imported into the global environment prior to importing this module
            RequiredModules            = @(
                @{ ModuleName = 'PSSharedGoods'; ModuleVersion = "Latest"; Guid = 'ee272aa8-baaa-4edf-9f45-b6d6f7d844fe' }
                @{ ModuleName = 'DSInternals'; ModuleVersion = "Latest"; Guid = '766b3ad8-eb78-48e6-84bd-61b31d96b53e' }
                @{ ModuleName = 'ADEssentials'; ModuleVersion = "Latest"; Guid = '9fc9fd61-7f11-4f4b-a527-084086f1905f' }
                @{ ModuleName = 'GPOZaurr'; ModuleVersion = 'Latest'; Guid = 'f7d4c9e4-0298-4f51-ad77-e8e3febebbde' }
            )
            ExternalModuleDependencies = @(
                "ActiveDirectory"
                "GroupPolicy"
                #"Microsoft.PowerShell.Utility",
                #"Microsoft.PowerShell.Management",
                #"Microsoft.PowerShell.Security"
            )

            LicenseUri                 = 'https://github.com/EvotecIT/PSWinDocumentation.AD/blob/master/License'
        }
    }
    Options     = @{
        Merge             = @{
            Sort           = 'None'
            FormatCodePSM1 = @{
                Enabled           = $true
                RemoveComments    = $false
                FormatterSettings = @{
                    IncludeRules = @(
                        'PSPlaceOpenBrace',
                        'PSPlaceCloseBrace',
                        'PSUseConsistentWhitespace',
                        'PSUseConsistentIndentation',
                        'PSAlignAssignmentStatement',
                        'PSUseCorrectCasing'
                    )

                    Rules        = @{
                        PSPlaceOpenBrace           = @{
                            Enable             = $true
                            OnSameLine         = $true
                            NewLineAfter       = $true
                            IgnoreOneLineBlock = $true
                        }

                        PSPlaceCloseBrace          = @{
                            Enable             = $true
                            NewLineAfter       = $false
                            IgnoreOneLineBlock = $true
                            NoEmptyLineBefore  = $false
                        }

                        PSUseConsistentIndentation = @{
                            Enable              = $true
                            Kind                = 'space'
                            PipelineIndentation = 'IncreaseIndentationAfterEveryPipeline'
                            IndentationSize     = 4
                        }

                        PSUseConsistentWhitespace  = @{
                            Enable          = $true
                            CheckInnerBrace = $true
                            CheckOpenBrace  = $true
                            CheckOpenParen  = $true
                            CheckOperator   = $true
                            CheckPipe       = $true
                            CheckSeparator  = $true
                        }

                        PSAlignAssignmentStatement = @{
                            Enable         = $true
                            CheckHashtable = $true
                        }

                        PSUseCorrectCasing         = @{
                            Enable = $true
                        }
                    }
                }
            }
            FormatCodePSD1 = @{
                Enabled        = $true
                RemoveComments = $false
            }
            Integrate      = @{
                ApprovedModules = 'PSSharedGoods', 'PSWriteColor' , 'Connectimo', 'PSUnifi', 'PSWebToolbox', 'PSMyPassword'
            }
        }
        Standard          = @{
            FormatCodePSM1 = @{

            }
            FormatCodePSD1 = @{
                Enabled = $true
                #RemoveComments = $true
            }
        }
        PowerShellGallery = @{
            ApiKey   = 'C:\Support\Important\PowerShellGalleryAPI.txt'
            FromFile = $true
        }
        GitHub            = @{
            ApiKey   = 'C:\Support\Important\GithubAPI.txt'
            FromFile = $true
            UserName = 'EvotecIT'
            #RepositoryName = 'PSPublishModule' # not required, uses project name
        }
        Documentation     = @{
            Path       = 'Docs'
            PathReadme = 'Docs\Readme.md'
        }
    }
    Steps       = @{
        BuildModule        = @{  # requires Enable to be on to process all of that
            Enable           = $true
            DeleteBefore     = $false
            Merge            = $true
            MergeMissing     = $true
            Releases         = $true
            ReleasesUnpacked = $false
            RefreshPSD1Only  = $false
        }
        BuildDocumentation = $false
        ImportModules      = @{
            Self            = $true
            RequiredModules = $false
            Verbose         = $false
        }
        PublishModule      = @{  # requires Enable to be on to process all of that
            Enabled      = $false
            Prerelease   = ''
            RequireForce = $false
            GitHub       = $false
        }
    }
}

New-PrepareModule -Configuration $Configuration