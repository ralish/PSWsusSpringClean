# PSScriptAnalyzer settings
#
# Last reviewed release: v1.22.0

@{
    IncludeRules = @('*')

    ExcludeRules = @(
        'PSReviewUnusedParameter'
    )

    Rules = @{
        # Compatibility rules
        PSUseCompatibleSyntax = @{
            Enable         = $true
            # Only major versions from v3.0 are supported
            TargetVersions = @('3.0', '4.0', '5.0')
        }

        # General rules
        PSAlignAssignmentStatement = @{
            Enable         = $true
            CheckHashtable = $true
        }

        PSAvoidUsingPositionalParameters = @{
            Enable           = $true
            CommandAllowList = @()
        }

        PSPlaceCloseBrace = @{
            Enable             = $true
            IgnoreOneLineBlock = $true
            NewLineAfter       = $false
            NoEmptyLineBefore  = $false
        }

        PSPlaceOpenBrace = @{
            Enable             = $true
            IgnoreOneLineBlock = $true
            NewLineAfter       = $true
            OnSameLine         = $true
        }

        PSProvideCommentHelp = @{
            Enable                  = $true
            BlockComment            = $true
            ExportedOnly            = $true
            Placement               = 'begin'
            VSCodeSnippetCorrection = $false
        }

        PSUseConsistentIndentation = @{
            Enable              = $true
            IndentationSize     = 4
            Kind                = 'space'
            PipelineIndentation = 'IncreaseIndentationForFirstPipeline'
        }

        PSUseConsistentWhitespace = @{
            Enable                                  = $true
            CheckInnerBrace                         = $true
            CheckOpenBrace                          = $true
            CheckOpenParen                          = $true
            CheckOperator                           = $true
            CheckParameter                          = $true
            CheckPipe                               = $true
            CheckPipeForRedundantWhitespace         = $true
            CheckSeparator                          = $true
            IgnoreAssignmentOperatorInsideHashTable = $true
        }

        PSUseSingularNouns = @{
            Enable        = $true
            # If unset, defaults to: Data, Windows
            NounAllowList = @()
        }
    }
}
