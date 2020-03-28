# See the help for Set-StrictMode for the full details on what this enables.
Set-StrictMode -Version 2.0

# Regular expressions for declining certain types of updates
$RegExClusterUpdates = ' Failover Clustering '
$RegExFarmUpdates = ' Farm[- ]'
$RegExPrereleaseUpdates = ' (Beta|Preview|RC1|Release Candidate) '
$RegExSecurityOnlyUpdates = ' Security Only (Quality )?Update '
$RegExWindowsNextUpdates = ' (Server|Version) Next '

Function Invoke-WsusSpringClean {
    <#
        .SYNOPSIS
        Performs additional WSUS server clean-up beyond the capabilities of the built-in tools

        .DESCRIPTION
        Adds the ability to decline numerous additional commonly unneeded updates as well as discover potentially incorrectly declined updates.

        .PARAMETER CleanupObsoleteComputers
        Specifies that the cmdlet deletes obsolete computers from the database.

        .PARAMETER CleanupObsoleteUpdates
        Specifies that the cmdlet deletes obsolete updates from the database.

        .PARAMETER CleanupUnneededContentFiles
        Specifies that the cmdlet deletes unneeded update files.

        .PARAMETER CompressUpdates
        Specifies that the cmdlet deletes obsolete revisions to updates from the database.

        .PARAMETER DeclineArchitectures
        Array of update architectures to decline.

        Valid options are: x64, ia64, arm64

        We don't support declining x86 updates as there's no mechanism to determine which updates are x86 specific versus multi-architecture.

        .PARAMETER DeclineCategoriesExclude
        Array of update categories in the bundled updates catalogue to not decline.

        .PARAMETER DeclineCategoriesInclude
        Array of update categories in the bundled updates catalogue to decline.

        .PARAMETER DeclineClusterUpdates
        Decline any updates which are exclusively for failover clustering installations.

        .PARAMETER DeclineExpiredUpdates
        Specifies that the cmdlet declines expired updates.

        .PARAMETER DeclineFarmUpdates
        Decline any updates which are exclusively for farm deployment installations.

        .PARAMETER DeclineLanguagesExclude
        Array of update language codes to not decline.

        .PARAMETER DeclineLanguagesInclude
        Array of update language codes to decline.

        .PARAMETER DeclinePrereleaseUpdates
        Decline any updates which are exclusively for pre-release products (e.g. betas).

        .PARAMETER DeclineSecurityOnlyUpdates
        Decline any Security Only updates.

        .PARAMETER DeclineSupersededUpdates
        Specifies that the cmdlet declines superseded updates.

        .PARAMETER DeclineWindowsNextUpdates
        Decline any Windows Next updates.

        .PARAMETER FindSuspectDeclines
        Scan all declined updates for any that may have been inadvertently declined.

        The returned suspect updates are those which:
        - Are not superseded or expired
        - Are not cluster or farm updates (if set to decline)
        - Are not in the filtered list of updates to decline from the bundled catalogue

        .PARAMETER RunDefaultTasks
        Performs all clean-up tasks except for declining any unneeded updates as defined in the included update catalogue CSV file.

        You can disable one or more of the default clean-up tasks by setting the associated switch parameter to false (e.g. -CompressUpdates:$false).

        You can perform a clean-up of unneeded updates by specifying the DeclineCategoriesInclude or DeclineCategoriesExclude parameter with your chosen categories.

        Also note that this does not perform a server synchronisation before clean-up or find suspect declined updates. These tasks can be included via their respective parameters.

        .PARAMETER SynchroniseServer
        Perform a synchronisation against the upstream server before running cleanup.

        .EXAMPLE
        PS C:\>$SuspectDeclines = Invoke-WsusSpringClean -RunDefaultTasks -FindSuspectDeclines

        Runs the default clean-up tasks & checks for declined updates that may not be intentional.

        .EXAMPLE
        PS C:\>Invoke-WsusSpringClean -DeclineCategoriesInclude @('Region - US', 'Superseded')

        Declines all unneeded updates in the "Region - US" & "Superseded" categories.

        .EXAMPLE
        PS C:\>Invoke-WsusSpringClean -DeclineLanguagesExclude @('en-AU')

        Declines all language specific updates excluding those for English (Australia).

        .EXAMPLE
        PS C:\>Invoke-WsusSpringClean -DeclineArchitectures @('arm64', 'ia64')

        Declines all architecture specific updates for ARM64 & IA64 (Itanium) systems.

        .NOTES
        The script intentionally avoids usage of most WSUS cmdlets provided by the UpdateServices module as many are extremely slow. This is particularly true of the Get-WsusUpdate cmdlet.

        The efficiency of the update declining logic could be substantially improved. That said, this script is not typically run frequently (~monthly), so this isn't a major priority.

        .LINK
        https://github.com/ralish/PSWsusSpringClean
    #>

    [CmdletBinding(DefaultParameterSetName='Default', SupportsShouldProcess)]
    Param(
        [Switch]$RunDefaultTasks,
        [Switch]$SynchroniseServer,
        [Switch]$FindSuspectDeclines,

        [Switch]$DeclineClusterUpdates,
        [Switch]$DeclineFarmUpdates,
        [Switch]$DeclinePrereleaseUpdates,
        [Switch]$DeclineSecurityOnlyUpdates,
        [Switch]$DeclineWindowsNextUpdates,

        [String[]]$DeclineCategoriesExclude,
        [String[]]$DeclineCategoriesInclude,

        [ValidateScript( { Test-WsusSpringCleanArchitectures -Architectures $_ } )]
        [String[]]$DeclineArchitectures,

        [ValidateScript( { Test-WsusSpringCleanLanguageCodes -LanguageCodes $_ } )]
        [String[]]$DeclineLanguagesExclude,

        [ValidateScript( { Test-WsusSpringCleanLanguageCodes -LanguageCodes $_ } )]
        [String[]]$DeclineLanguagesInclude,

        # Wrapping of Invoke-WsusServerCleanup
        [Switch]$CleanupObsoleteComputers,
        [Switch]$CleanupObsoleteUpdates,
        [Switch]$CleanupUnneededContentFiles,
        [Switch]$CompressUpdates,
        [Switch]$DeclineExpiredUpdates,
        [Switch]$DeclineSupersededUpdates
    )

    if ($PSBoundParameters.ContainsKey('DeclineCategoriesExclude') -and $PSBoundParameters.ContainsKey('DeclineCategoriesInclude')) {
        throw 'Can only specify one of DeclineCategoriesExclude and DeclineCategoriesInclude.'
    }

    if ($PSBoundParameters.ContainsKey('DeclineLanguagesExclude') -and $PSBoundParameters.ContainsKey('DeclineLanguagesInclude')) {
        throw 'Can only specify one of DeclineLanguagesExclude and DeclineLanguagesInclude.'
    }

    Import-WsusSpringCleanMetadata

    if ($RunDefaultTasks) {
        $DefaultTasks = @(
            'DeclineClusterUpdates',
            'DeclineFarmUpdates',
            'DeclinePrereleaseUpdates',
            'DeclineSecurityOnlyUpdates',
            'DeclineWindowsNextUpdates',

            'CleanupObsoleteComputers',
            'CleanupObsoleteUpdates',
            'CleanupUnneededContentFiles',
            'CompressUpdates',
            'DeclineExpiredUpdates',
            'DeclineSupersededUpdates'
        )

        foreach ($Task in $DefaultTasks) {
            if ($PSBoundParameters.ContainsKey($Task)) {
                Set-Variable -Name $Task -Value (Get-Variable -Name $Task).Value -WhatIf:$false
            } else {
                Set-Variable -Name $Task -Value $true -WhatIf:$false
            }
        }
    }

    # Determine which categories of updates to decline (if any)
    if ($PSBoundParameters.ContainsKey('DeclineCategoriesExclude') -or $PSBoundParameters.ContainsKey('DeclineCategoriesInclude')) {
        Import-WsusSpringCleanCatalogue
        $CatalogueCategories = $script:WscCatalogue.Category | Sort-Object | Get-Unique

        if ($PSBoundParameters.ContainsKey('DeclineCategoriesExclude')) {
            $DeclineCategories = $CatalogueCategories | Where-Object { $_ -notin $DeclineCategoriesExclude }
        } else {
            $DeclineCategories = $CatalogueCategories | Where-Object { $_ -in $DeclineCategoriesInclude }
        }
    }

    # Fetch the metadata for any architectures we're going to decline
    if ($PSBoundParameters.ContainsKey('DeclineArchitectures')) {
        $DeclineArchitecturesMetadata = @()
        foreach ($Architecture in $DeclineArchitectures) {
            $DeclineArchitecturesMetadata += $script:WscMetadata.Architectures.Architecture | Where-Object { $_.name -eq $Architecture }
        }
    }

    # Fetch the metadata for any languages we're going to decline
    if ($PSBoundParameters.ContainsKey('DeclineLanguagesExclude')) {
        $DeclineLanguagesMetadata = $script:WscMetadata.Languages.Language | Where-Object { $_.code -notin $DeclineLanguagesExclude }
    } elseif ($PSBoundParameters.ContainsKey('DeclineLanguagesInclude')) {
        $DeclineLanguagesMetadata = $script:WscMetadata.Languages.Language | Where-Object { $_.code -in $DeclineLanguagesInclude }
    }

    if ($SynchroniseServer) {
        Write-Host -ForegroundColor Green "`r`nStarting WSUS server synchronisation ..."
        Invoke-WsusServerSynchronisation
    }

    Write-Host -ForegroundColor Green "`r`nBeginning WSUS server cleanup (Phase 1) ..."
    $CleanupWrapperParams = @{
        CleanupObsoleteUpdates=$CleanupObsoleteUpdates
        CompressUpdates=$CompressUpdates
        DeclineExpiredUpdates=$DeclineExpiredUpdates
        DeclineSupersededUpdates=$DeclineSupersededUpdates
    }
    Invoke-WsusServerCleanupWrapper @CleanupWrapperParams

    Write-Host -ForegroundColor Green "`r`nBeginning WSUS server cleanup (Phase 2) ..."
    $SpringCleanParams = @{
        DeclineClusterUpdates=$DeclineClusterUpdates
        DeclineFarmUpdates=$DeclineFarmUpdates
        DeclinePrereleaseUpdates=$DeclinePrereleaseUpdates
        DeclineSecurityOnlyUpdates=$DeclineSecurityOnlyUpdates
        DeclineWindowsNextUpdates=$DeclineWindowsNextUpdates
    }

    if ($PSBoundParameters.ContainsKey('DeclineCategoriesExclude') -or $PSBoundParameters.ContainsKey('DeclineCategoriesInclude')) {
        $SpringCleanParams += @{ DeclineCategories=$DeclineCategories }
    }

    if ($PSBoundParameters.ContainsKey('DeclineArchitectures')) {
        $SpringCleanParams += @{ DeclineArchitectures=$DeclineArchitecturesMetadata }
    }

    if ($PSBoundParameters.ContainsKey('DeclineLanguagesExclude') -or $PSBoundParameters.ContainsKey('DeclineLanguagesInclude')) {
        $SpringCleanParams += @{ DeclineLanguages=$DeclineLanguagesMetadata }
    }

    Invoke-WsusServerSpringClean @SpringCleanParams

    Write-Host -ForegroundColor Green "`r`nBeginning WSUS server cleanup (Phase 3) ..."
    $CleanupWrapperParams = @{
        CleanupObsoleteComputers=$CleanupObsoleteComputers
        CleanupUnneededContentFiles=$CleanupUnneededContentFiles
    }
    Invoke-WsusServerCleanupWrapper @CleanupWrapperParams

    if ($FindSuspectDeclines) {
        Get-WsusSuspectDeclines @SpringCleanParams
    }
}

Function Get-WsusSuspectDeclines {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    Param(
        [Switch]$DeclineClusterUpdates,
        [Switch]$DeclineFarmUpdates,
        [Switch]$DeclinePrereleaseUpdates,
        [Switch]$DeclineSecurityOnlyUpdates,
        [Switch]$DeclineWindowsNextUpdates,

        [String[]]$DeclineCategories,
        [Xml.XmlElement[]]$DeclineArchitectures,
        [Xml.XmlElement[]]$DeclineLanguages
    )

    $WsusServer = Get-WsusServer
    $UpdateScope = New-Object -TypeName Microsoft.UpdateServices.Administration.UpdateScope

    Write-Host -ForegroundColor Green '[*] Retrieving declined updates ...'
    $UpdateScope.ApprovedStates = [Microsoft.UpdateServices.Administration.ApprovedStates]::Declined
    $WsusDeclined = $WsusServer.GetUpdates($UpdateScope)

    # Ignore all updates corresponding to architectures, categories or languages we declined
    if ($PSBoundParameters.ContainsKey('DeclineCategories')) {
        $IgnoredCatalogueCategories = $script:WscCatalogue | Where-Object { $_.Category -in $DeclineCategories }
    }
    if ($PSBoundParameters.ContainsKey('DeclineArchitectures')) {
        $IgnoredArchitecturesRegEx = ' ({0})' -f [String]::Join('|', $DeclineArchitectures.regex)
    }
    if ($PSBoundParameters.ContainsKey('DeclineLanguages')) {
        $IgnoredLanguagesRegEx = ' [\[]?({0})(_LP|_LIP)?[\]]?' -f [String]::Join('|', $DeclineLanguages.code)
    }

    Write-Host -ForegroundColor Green '[*] Finding suspect declined updates ...'
    $SuspectDeclines = @()
    foreach ($Update in $WsusDeclined) {
        # Ignore superseded and expired updates
        if ($Update.IsSuperseded -or $Update.PublicationState -eq 'Expired') {
            continue
        }

        # Ignore cluster updates if they were declined
        if ($DeclineClusterUpdates -and $Update.Title -match $RegExClusterUpdates) {
            continue
        }

        # Ignore farm updates if they were declined
        if ($DeclineFarmUpdates -and $Update.Title -match $RegExFarmUpdates) {
            continue
        }

        # Ignore pre-release updates if they were declined
        if ($DeclinePrereleaseUpdates -and $Update.Title -match $RegExPrereleaseUpdates) {
            continue
        }

        # Ignore Security Only Quality updates if they were declined
        if ($DeclineSecurityOnlyUpdates -and $Update.Title -match $RegExSecurityOnlyUpdates) {
            continue
        }

        # Ignore Windows Next updates if they were declined
        if ($DeclineWindowsNextUpdates -and $Update.Title -match $RegExWindowsNextUpdates) {
            continue
        }

        # Ignore any update categories which were declined
        if ($PSBoundParameters.ContainsKey('DeclineCategories')) {
            if ($Update.Title -in $IgnoredCatalogueCategories.Title) {
                continue
            }
        }

        # Ignore any update architectures which were declined
        if ($PSBoundParameters.ContainsKey('DeclineArchitectures')) {
            if ($Update.Title -match $IgnoredArchitecturesRegEx) {
                continue
            }
        }

        # Ignore any update languages which were declined
        if ($PSBoundParameters.ContainsKey('DeclineLanguages')) {
            if ($Update.Title -match $IgnoredLanguagesRegEx) {
                continue
            }
        }

        $SuspectDeclines += $Update
    }

    return $SuspectDeclines
}

Function Import-WsusSpringCleanMetadata {
    [CmdletBinding()]
    Param()

    if (Get-Variable -Name WscCatalogue -Scope Script -ErrorAction SilentlyContinue) {
        return
    }

    Write-Verbose -Message '[*] Importing module metadata ...'
    $MetadataPath = Join-Path -Path $PSScriptRoot -ChildPath 'PSWsusSpringClean.xml'
    $script:WscMetadata = ([Xml](Get-Content -Path $MetadataPath)).PSWsusSpringClean
}

Function Invoke-WsusDeclineUpdatesByCatalogue {
    [CmdletBinding(SupportsShouldProcess)]
    Param(
        [Parameter(Mandatory)]
        [Microsoft.UpdateServices.Internal.BaseApi.Update[]]$Updates,

        [Parameter(Mandatory)]
        [String]$Category
    )

    Write-Host -ForegroundColor Green ('[*] Declining updates in category: {0}' -f $Category)
    $UpdatesToDecline = $script:WscCatalogue | Where-Object { $_.Category -eq $Category }
    $MatchingUpdates = $Updates | Where-Object { $_.Title -in $UpdatesToDecline.Title }

    foreach ($Update in $MatchingUpdates) {
        if ($PSCmdlet.ShouldProcess($Update.Title, 'Decline')) {
            Write-Host -ForegroundColor Cyan ('[-] Declining update: {0}' -f $Update.Title)
            $Update.Decline()
        }
    }
}

Function Invoke-WsusDeclineUpdatesByRegEx {
    [CmdletBinding(SupportsShouldProcess)]
    Param(
        [Parameter(Mandatory)]
        [Microsoft.UpdateServices.Internal.BaseApi.Update[]]$Updates,

        [Parameter(Mandatory)]
        [String]$RegEx
    )

    foreach ($Update in $Updates) {
        if ($Update.Title -match $RegEx) {
            if ($PSCmdlet.ShouldProcess($Update.Title, 'Decline')) {
                Write-Host -ForegroundColor Cyan ('[-] Declining update: {0}' -f $Update.Title)
                $Update.Decline()
            }
        }
    }
}

Function Invoke-WsusServerCleanupWrapper {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding(SupportsShouldProcess)]
    Param(
        [Switch]$CleanupObsoleteComputers,
        [Switch]$CleanupObsoleteUpdates,
        [Switch]$CleanupUnneededContentFiles,
        [Switch]$CompressUpdates,
        [Switch]$DeclineExpiredUpdates,
        [Switch]$DeclineSupersededUpdates
    )

    if ($CleanupObsoleteComputers) {
        Write-Host -ForegroundColor Green '[*] Deleting obsolete computers ...'
        Write-Host (Invoke-WsusServerCleanup -CleanupObsoleteComputers)
    }

    if ($CleanupObsoleteUpdates) {
        Write-Host -ForegroundColor Green '[*] Deleting obsolete updates ...'
        Write-Host (Invoke-WsusServerCleanup -CleanupObsoleteUpdates)
    }

    if ($CleanupUnneededContentFiles) {
        Write-Host -ForegroundColor Green '[*] Deleting unneeded update files ...'
        Write-Host (Invoke-WsusServerCleanup -CleanupUnneededContentFiles)
    }

    if ($CompressUpdates) {
        Write-Host -ForegroundColor Green '[*] Deleting obsolete update revisions ...'
        Write-Host (Invoke-WsusServerCleanup -CompressUpdates)
    }

    if ($DeclineExpiredUpdates) {
        Write-Host -ForegroundColor Green '[*] Declining expired updates ...'
        Write-Host (Invoke-WsusServerCleanup -DeclineExpiredUpdates)
    }

    if ($DeclineSupersededUpdates) {
        Write-Host -ForegroundColor Green '[*] Declining superseded updates ...'
        Write-Host (Invoke-WsusServerCleanup -DeclineSupersededUpdates)
    }
}

Function Invoke-WsusServerSynchronisation {
    [CmdletBinding(SupportsShouldProcess)]
    Param()

    $WsusServer = Get-WsusServer

    if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'WSUS synchronization')) {
        $SyncStatus = $WsusServer.GetSubscription().GetSynchronizationStatus()
        if ($SyncStatus -eq 'NotProcessing') {
            $WsusServer.GetSubscription().StartSynchronization()
        } elseif ($SyncStatus -eq 'Running') {
            Write-Warning -Message "[!] A synchronisation appears to already be running! We'll wait for this one to complete ..."
        } else {
            throw ('WSUS server returned unknown synchronisation status: {0}' -f $SyncStatus)
        }

        do {
            Start-Sleep -Seconds 5
        } while ($WsusServer.GetSubscription().GetSynchronizationStatus() -eq 'Running')

        $SyncResult = $WsusServer.GetSubscription().GetLastSynchronizationInfo().Result
        if ($SyncResult -ne 'Succeeded') {
            throw ('WSUS server synchronisation completed with unexpected result: {0}' -f $SyncResult)
        }
    }
}

Function Invoke-WsusServerSpringClean {
    [CmdletBinding(SupportsShouldProcess)]
    Param(
        [Switch]$DeclineClusterUpdates,
        [Switch]$DeclineFarmUpdates,
        [Switch]$DeclinePrereleaseUpdates,
        [Switch]$DeclineSecurityOnlyUpdates,
        [Switch]$DeclineWindowsNextUpdates,

        [String[]]$DeclineCategories,
        [Xml.XmlElement[]]$DeclineArchitectures,
        [Xml.XmlElement[]]$DeclineLanguages
    )

    $WsusServer = Get-WsusServer
    $UpdateScope = New-Object -TypeName Microsoft.UpdateServices.Administration.UpdateScope

    Write-Host -ForegroundColor Green '[*] Retrieving approved updates ...'
    $UpdateScope.ApprovedStates = [Microsoft.UpdateServices.Administration.ApprovedStates]::LatestRevisionApproved
    $WsusApproved = $WsusServer.GetUpdates($UpdateScope)

    Write-Host -ForegroundColor Green '[*] Retrieving unapproved updates ...'
    $UpdateScope.ApprovedStates = [Microsoft.UpdateServices.Administration.ApprovedStates]::NotApproved
    $WsusUnapproved = $WsusServer.GetUpdates($UpdateScope)

    $WsusAnyExceptDeclined = $WsusApproved + $WsusUnapproved

    if ($DeclineClusterUpdates) {
        Write-Host -ForegroundColor Green '[*] Declining cluster updates ...'
        Invoke-WsusDeclineUpdatesByRegEx -Updates $WsusAnyExceptDeclined -RegEx $script:RegExClusterUpdates
    }

    if ($DeclineFarmUpdates) {
        Write-Host -ForegroundColor Green '[*] Declining farm updates ...'
        Invoke-WsusDeclineUpdatesByRegEx -Updates $WsusAnyExceptDeclined -RegEx $script:RegExFarmUpdates
    }

    if ($DeclinePrereleaseUpdates) {
        Write-Host -ForegroundColor Green '[*] Declining pre-release updates ...'
        Invoke-WsusDeclineUpdatesByRegEx -Updates $WsusAnyExceptDeclined -RegEx $script:RegExPrereleaseUpdates
    }

    if ($DeclineSecurityOnlyUpdates) {
        Write-Host -ForegroundColor Green '[*] Declining Security Only updates ...'
        Invoke-WsusDeclineUpdatesByRegEx -Updates $WsusAnyExceptDeclined -RegEx $script:RegExSecurityOnlyUpdates
    }

    if ($DeclineWindowsNextUpdates) {
        Write-Host -ForegroundColor Green '[*] Declining Windows Next updates ...'
        Invoke-WsusDeclineUpdatesByRegEx -Updates $WsusAnyExceptDeclined -RegEx $script:RegExWindowsNextUpdates
    }

    if ($PSBoundParameters.ContainsKey('DeclineCategories')) {
        foreach ($Category in $DeclineCategories) {
            Invoke-WsusDeclineUpdatesByCatalogue -Updates $WsusAnyExceptDeclined -Category $Category
        }
    }

    if ($PSBoundParameters.ContainsKey('DeclineArchitectures')) {
        foreach ($Architecture in $DeclineArchitectures) {
            Write-Host -ForegroundColor Green ('[*] Declining updates with architecture: {0}' -f $Architecture.name)
            $ArchitectureRegEx = ' ({0})' -f $Architecture.regex
            Invoke-WsusDeclineUpdatesByRegEx -Updates $WsusAnyExceptDeclined -RegEx $ArchitectureRegEx
        }
    }

    if ($PSBoundParameters.ContainsKey('DeclineLanguages')) {
        foreach ($Language in $DeclineLanguages) {
            Write-Host -ForegroundColor Green ('[*] Declining updates with language: {0}' -f $Language.code)
            $LanguageRegEx = ' [\[]?{0}(_LP|_LIP)?[\]]?' -f $Language.code
            Invoke-WsusDeclineUpdatesByRegEx -Updates $WsusAnyExceptDeclined -RegEx $LanguageRegEx
        }
    }
}

Function Test-WsusSpringCleanArchitectures {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    Param(
        [Parameter(Mandatory)]
        [String[]]$Architectures
    )

    Import-WsusSpringCleanMetadata

    $KnownArchitectures = $script:WscMetadata.Architectures.Architecture.name
    foreach ($Architecture in $Architectures) {
        if ($Architecture -notin $KnownArchitectures) {
            throw 'Unknown architecture specified: {0}' -f $Architecture
        }
    }

    return $true
}

Function Test-WsusSpringCleanLanguageCodes {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    Param(
        [Parameter(Mandatory)]
        [String[]]$LanguageCodes
    )

    Import-WsusSpringCleanMetadata

    $KnownLanguageCodes = $script:WscMetadata.Languages.Language.code
    foreach ($LanguageCode in $LanguageCodes) {
        if ($LanguageCode -notin $KnownLanguageCodes) {
            throw 'Unknown language code specified: {0}' -f $LanguageCode
        }
    }

    return $true
}

Function ConvertTo-WsusSpringCleanCatalogue {
    Param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [Microsoft.UpdateServices.Internal.BaseApi.Update[]]$Updates
    )

    Process {
        foreach ($Update in $Updates) {
            [String[]]$ProductTitles = @()
            foreach ($ProductTitle in $Update.ProductTitles) {
                $ProductTitles += $ProductTitle
            }

            [PSCustomObject]@{
                'Category'      = 'Unknown'
                'Title'         = $Update.Title
                'ProductTitles' = [String]::Join(', ', $ProductTitles)
            }
        }
    }
}

Function Import-WsusSpringCleanCatalogue {
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [String]$CataloguePath
    )

    if (!$PSBoundParameters.ContainsKey('CataloguePath')) {
        $CataloguePath = Join-Path -Path $PSScriptRoot -ChildPath 'PSWsusSpringClean.csv'
    }

    Write-Verbose -Message '[*] Importing update catalogue ...'
    $script:WscCatalogue = Import-Csv -Path $CataloguePath
}

Function Test-WsusSpringCleanCatalogue {
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [String]$CataloguePath,

        [Parameter(ParameterSetName='MarkedAsSuperseded')]
        [Switch]$MarkedAsSuperseded,

        [Parameter(ParameterSetName='NotPresentInWsus')]
        [Switch]$NotPresentInWsus
    )

    if ($PSBoundParameters.ContainsKey('CataloguePath')) {
        Import-WsusSpringCleanCatalogue @PSBoundParameters
    } else {
        Import-WsusSpringCleanCatalogue
    }

    Write-Host -ForegroundColor Green '[*] Retrieving all updates ...'
    $WsusServer = Get-WsusServer
    $WsusUpdateScope = New-Object -TypeName Microsoft.UpdateServices.Administration.UpdateScope
    $WsusUpdateScope.ApprovedStates = [Microsoft.UpdateServices.Administration.ApprovedStates]::Any
    $WsusUpdates = $WsusServer.GetUpdates($WsusUpdateScope)

    if ($MarkedAsSuperseded) {
        Write-Host -ForegroundColor Green '[*] Scanning for updates marked as superseded ...'

        $Results = @()
        foreach ($Update in ($script:WscCatalogue | Where-Object Category -eq 'Superseded')) {
            if ($Update.Title -in $WsusUpdates.Title) {
                $MatchedUpdates = @()
                $SupersededUpdates = @()

                $MatchedUpdates += $WsusUpdates | Where-Object Title -eq $Update.Title
                $SupersededUpdates += $MatchedUpdates | Where-Object IsSuperseded -eq $true

                if ($MatchedUpdates.Count -eq $SupersededUpdates.Count) {
                    $Results += $Update
                }
            }
        }
    }

    if ($NotPresentInWsus) {
        Write-Host -ForegroundColor Green '[*] Scanning for updates not present in WSUS ...'

        $Results = @()
        foreach ($Update in $script:WscCatalogue) {
            if ($Update.Title -notin $WsusUpdates.Title) {
                $Results += $Update
            }
        }
    }

    return $Results
}
