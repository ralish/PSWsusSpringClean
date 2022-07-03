# See the help for Set-StrictMode for what this enables
Set-StrictMode -Version 3.0

# Regular expressions for declining certain types of updates
$RegExClusterUpdates = '\bFailover Clustering\b'
$RegExFarmUpdates = '\bfarm-deployment\b'
$RegExPrereleaseUpdates = '\b(Beta|Pre-release|Preview|RC1|Release Candidate)\b'
$RegExSecurityOnlyUpdates = '\bSecurity Only (Quality )?Update\b'
$RegExWindowsNextUpdates = '\b(Server|Version) Next\b'

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
        Perform a synchronisation against the upstream server before running clean-up.

        .PARAMETER UpdateServer
        The WSUS server to perform operations on as returned by Get-WsusServer.

        If omitted we'll attempt to connect to a WSUS server on the local system.

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

    [CmdletBinding(DefaultParameterSetName = 'Default', SupportsShouldProcess)]
    [OutputType([Void], [Microsoft.UpdateServices.Internal.BaseApi.Update[]])]
    Param(
        [Microsoft.UpdateServices.Internal.BaseApi.UpdateServer]$UpdateServer,

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

    if (!$PSBoundParameters.ContainsKey('UpdateServer')) {
        try {
            $UpdateServer = Get-WsusServer
        } catch {
            throw 'Failed to connect to local WSUS server via Get-WsusServer.'
        }
    }

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

    Import-WsusSpringCleanMetadata

    # Determine which categories of updates to decline (if any)
    if ($PSBoundParameters.ContainsKey('DeclineCategoriesExclude') -or $PSBoundParameters.ContainsKey('DeclineCategoriesInclude')) {
        Import-WsusSpringCleanCatalogue
        $CatalogueCategories = $Script:WscCatalogue.Category | Sort-Object | Get-Unique

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
            $DeclineArchitecturesMetadata += $Script:WscMetadata.Architectures.Architecture | Where-Object name -EQ $Architecture
        }
    }

    # Fetch the metadata for any languages we're going to decline
    if ($PSBoundParameters.ContainsKey('DeclineLanguagesExclude')) {
        $DeclineLanguagesMetadata = $Script:WscMetadata.Languages.Language | Where-Object code -NotIn $DeclineLanguagesExclude
    } elseif ($PSBoundParameters.ContainsKey('DeclineLanguagesInclude')) {
        $DeclineLanguagesMetadata = $Script:WscMetadata.Languages.Language | Where-Object code -In $DeclineLanguagesInclude
    }

    $WriteProgressParams = @{
        Id       = 0
        Activity = 'Running WSUS spring-clean'
    }

    $TasksDone = 0
    $TasksTotal = 3

    if ($SynchroniseServer) {
        $TasksTotal++
    }

    if ($FindSuspectDeclines) {
        $TasksTotal++
    }

    if ($SynchroniseServer) {
        Write-Progress @WriteProgressParams -Status 'Running server synchronisation' -PercentComplete ($TasksDone / $TasksTotal * 100)
        Invoke-WsusServerSynchronisation -UpdateServer $UpdateServer
        $TasksDone++
    }

    Write-Progress @WriteProgressParams -Status 'Running server clean-up (Phase 1)' -PercentComplete ($TasksDone / $TasksTotal * 100)
    $CleanupWrapperParams = @{
        UpdateServer             = $UpdateServer
        CleanupObsoleteUpdates   = $CleanupObsoleteUpdates
        CompressUpdates          = $CompressUpdates
        DeclineExpiredUpdates    = $DeclineExpiredUpdates
        DeclineSupersededUpdates = $DeclineSupersededUpdates
    }
    Invoke-WsusServerCleanupWrapper @CleanupWrapperParams -ProgressParentId $WriteProgressParams['Id']
    $TasksDone++

    $SpringCleanParams = @{
        UpdateServer               = $UpdateServer
        DeclineClusterUpdates      = $DeclineClusterUpdates
        DeclineFarmUpdates         = $DeclineFarmUpdates
        DeclinePrereleaseUpdates   = $DeclinePrereleaseUpdates
        DeclineSecurityOnlyUpdates = $DeclineSecurityOnlyUpdates
        DeclineWindowsNextUpdates  = $DeclineWindowsNextUpdates
    }

    if ($PSBoundParameters.ContainsKey('DeclineCategoriesExclude') -or $PSBoundParameters.ContainsKey('DeclineCategoriesInclude')) {
        $SpringCleanParams['DeclineCategories'] = $DeclineCategories
    }

    if ($PSBoundParameters.ContainsKey('DeclineArchitectures')) {
        $SpringCleanParams['DeclineArchitectures'] = $DeclineArchitecturesMetadata
    }

    if ($PSBoundParameters.ContainsKey('DeclineLanguagesExclude') -or $PSBoundParameters.ContainsKey('DeclineLanguagesInclude')) {
        $SpringCleanParams['DeclineLanguages'] = $DeclineLanguagesMetadata
    }

    Write-Progress @WriteProgressParams -Status 'Running server clean-up (Phase 2)' -PercentComplete ($TasksDone / $TasksTotal * 100)
    Invoke-WsusServerSpringClean @SpringCleanParams -ProgressParentId $WriteProgressParams['Id']
    $TasksDone++

    Write-Progress @WriteProgressParams -Status 'Running server clean-up (Phase 3)' -PercentComplete ($TasksDone / $TasksTotal * 100)
    $CleanupWrapperParams = @{
        UpdateServer                = $UpdateServer
        CleanupObsoleteComputers    = $CleanupObsoleteComputers
        CleanupUnneededContentFiles = $CleanupUnneededContentFiles
    }
    Invoke-WsusServerCleanupWrapper @CleanupWrapperParams -ProgressParentId $WriteProgressParams['Id']
    $TasksDone++

    Write-Progress @WriteProgressParams -Status 'Searching for suspect declined updates' -PercentComplete ($TasksDone / $TasksTotal * 100)
    if ($FindSuspectDeclines) {
        Get-WsusSuspectDeclines @SpringCleanParams -ProgressParentId $WriteProgressParams['Id']
        $TasksDone++
    }

    Write-Progress @WriteProgressParams -Completed
}

Function Get-WsusSuspectDeclines {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    [OutputType([Void], [Microsoft.UpdateServices.Internal.BaseApi.Update[]])]
    Param(
        [Parameter(Mandatory)]
        [Microsoft.UpdateServices.Internal.BaseApi.UpdateServer]$UpdateServer,

        [Switch]$DeclineClusterUpdates,
        [Switch]$DeclineFarmUpdates,
        [Switch]$DeclinePrereleaseUpdates,
        [Switch]$DeclineSecurityOnlyUpdates,
        [Switch]$DeclineWindowsNextUpdates,

        [String[]]$DeclineCategories,
        [Xml.XmlElement[]]$DeclineArchitectures,
        [Xml.XmlElement[]]$DeclineLanguages,

        [ValidateRange(-1, [Int]::MaxValue)]
        [Int]$ProgressParentId
    )

    $WriteProgressParams = @{
        Activity = 'Searching for suspect declined updates'
    }

    if ($PSBoundParameters.ContainsKey('ProgressParentId')) {
        $WriteProgressParams['ParentId'] = $ProgressParentId
        $WriteProgressParams['Id'] = $ProgressParentId + 1
    }

    $UpdateScope = New-Object -TypeName 'Microsoft.UpdateServices.Administration.UpdateScope'

    Write-Progress @WriteProgressParams -Status 'Retrieving declined updates' -PercentComplete 0
    $UpdateScope.ApprovedStates = [Microsoft.UpdateServices.Administration.ApprovedStates]::Declined
    $WsusDeclined = $UpdateServer.GetUpdates($UpdateScope)

    # Filter superseded and expired updates first as it's likely there will be
    # lots. This will help to improve performance of the remaining filtering.
    Write-Progress @WriteProgressParams -Status 'Filtering superseded and expired updates' -PercentComplete 20
    $WsusDeclined = $WsusDeclined | Where-Object {
        $_.IsSuperseded -EQ $false -and
        $_.PublicationState -NE 'Expired'
    }

    # Filter any declined architectures
    if ($PSBoundParameters.ContainsKey('DeclineArchitectures')) {
        Write-Progress @WriteProgressParams -Status 'Filtering declined architectures' -PercentComplete 30
        $RegExArchitectures = '\s({0})' -f [String]::Join('|', $DeclineArchitectures.regex)
        $WsusDeclined = $WsusDeclined | Where-Object Title -NotMatch $RegExArchitectures
    }

    # Filter any declined languages
    if ($PSBoundParameters.ContainsKey('DeclineLanguages')) {
        foreach ($Language in $DeclineLanguages) {
            $Status = 'Filtering declined language: {0}' -f $Language.code
            Write-Progress @WriteProgressParams -Status $Status -PercentComplete 40

            $RegExLanguage = '\s\[?{0}(_LP|_LIP)?\]?' -f $Language.code
            $WsusDeclined = $WsusDeclined | Where-Object Title -NotMatch $RegExLanguage
        }
    }

    # Ignore declined categories
    if ($PSBoundParameters.ContainsKey('DeclineCategories')) {
        $IgnoredCatalogueCategories = $Script:WscCatalogue | Where-Object Category -In $DeclineCategories
    }

    Write-Progress @WriteProgressParams -Status 'Analyzing declined updates' -PercentComplete 50
    $SuspectDeclines = New-Object -TypeName 'Collections.Generic.List[Microsoft.UpdateServices.Internal.BaseApi.Update]'
    $UpdatesProcessed = 0
    foreach ($Update in $WsusDeclined) {
        # Update progress every 100 updates
        if ($UpdatesProcessed % 100 -eq 0) {
            $PercentComplete = $UpdatesProcessed / $WsusDeclined.Count * 50 + 50
            Write-Progress @WriteProgressParams -PercentComplete $PercentComplete
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

        $SuspectDeclines.Add($Update)
        $UpdatesProcessed++
    }

    Write-Progress @WriteProgressParams -Completed
    return $SuspectDeclines.ToArray()
}

Function Import-WsusSpringCleanMetadata {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    [OutputType([Void])]
    Param()

    if (Get-Variable -Name 'WscCatalogue' -Scope Script -ErrorAction SilentlyContinue) {
        return
    }

    Write-Verbose -Message 'Importing module metadata ...'
    $MetadataPath = Join-Path -Path $PSScriptRoot -ChildPath 'PSWsusSpringClean.xml'
    $Script:WscMetadata = ([Xml](Get-Content -Path $MetadataPath)).PSWsusSpringClean
}

Function Invoke-WsusDeclineUpdatesByCatalogue {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([Void])]
    Param(
        [Parameter(Mandatory)]
        [Microsoft.UpdateServices.Internal.BaseApi.Update[]]$Updates,

        [Parameter(Mandatory)]
        [String]$Category
    )

    $UpdatesToDecline = $Script:WscCatalogue | Where-Object Category -EQ $Category
    $MatchingUpdates = $Updates | Where-Object Title -In $UpdatesToDecline.Title

    foreach ($Update in $MatchingUpdates) {
        if ($PSCmdlet.ShouldProcess($Update.Title, 'Decline')) {
            Write-Verbose -Message ('Declining update: {0}' -f $Update.Title)
            $Update.Decline()
        }
    }
}

Function Invoke-WsusDeclineUpdatesByRegEx {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([Void])]
    Param(
        [Parameter(Mandatory)]
        [Microsoft.UpdateServices.Internal.BaseApi.Update[]]$Updates,

        [Parameter(Mandatory)]
        [String]$RegEx
    )

    foreach ($Update in $Updates) {
        if ($Update.Title -match $RegEx) {
            if ($PSCmdlet.ShouldProcess($Update.Title, 'Decline')) {
                Write-Verbose -Message ('Declining update: {0}' -f $Update.Title)
                $Update.Decline()
            }
        }
    }
}

Function Invoke-WsusServerCleanupWrapper {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([Void])]
    Param(
        [Parameter(Mandatory)]
        [Microsoft.UpdateServices.Internal.BaseApi.UpdateServer]$UpdateServer,

        [Switch]$CleanupObsoleteComputers,
        [Switch]$CleanupObsoleteUpdates,
        [Switch]$CleanupUnneededContentFiles,
        [Switch]$CompressUpdates,
        [Switch]$DeclineExpiredUpdates,
        [Switch]$DeclineSupersededUpdates,

        [ValidateRange(-1, [Int]::MaxValue)]
        [Int]$ProgressParentId
    )

    $WriteProgressParams = @{
        Activity = 'Running Microsoft built-in clean-up tasks'
    }

    if ($PSBoundParameters.ContainsKey('ProgressParentId')) {
        $WriteProgressParams['ParentId'] = $ProgressParentId
        $WriteProgressParams['Id'] = $ProgressParentId + 1
    }

    $TasksDone = 0
    $TasksTotal = 0
    $ValidTasks = @(
        'CleanupObsoleteComputers'
        'CleanupObsoleteUpdates'
        'CleanupUnneededContentFiles'
        'CompressUpdates'
        'DeclineExpiredUpdates'
        'DeclineSupersededUpdates'
    )

    foreach ($SwitchParam in ($MyInvocation.MyCommand.Parameters.Values | Where-Object SwitchParameter)) {
        # This kind of sucks but as we're enumerating switch parameters we'll
        # also get built-in ones like -Verbose. I'm not aware of any way to
        # programmatically filter these out, and a blocklist feels brittle.
        if ($SwitchParam.Name -notin $ValidTasks) {
            continue
        }

        if (Get-Variable -Name $SwitchParam.Name -ValueOnly) {
            $TasksTotal++
        }
    }

    if ($CleanupObsoleteComputers) {
        Write-Progress @WriteProgressParams -Status 'Deleting obsolete computers' -PercentComplete ($TasksDone / $TasksTotal * 100)
        Write-Host (Invoke-WsusServerCleanup -UpdateServer $UpdateServer -CleanupObsoleteComputers)
        $TasksDone++
    }

    if ($CleanupObsoleteUpdates) {
        Write-Progress @WriteProgressParams -Status 'Deleting obsolete updates' -PercentComplete ($TasksDone / $TasksTotal * 100)
        Write-Host (Invoke-WsusServerCleanup -UpdateServer $UpdateServer -CleanupObsoleteUpdates)
        $TasksDone++
    }

    if ($CleanupUnneededContentFiles) {
        Write-Progress @WriteProgressParams -Status 'Deleting unneeded update files' -PercentComplete ($TasksDone / $TasksTotal * 100)
        Write-Host (Invoke-WsusServerCleanup -UpdateServer $UpdateServer -CleanupUnneededContentFiles)
        $TasksDone++
    }

    if ($CompressUpdates) {
        Write-Progress @WriteProgressParams -Status 'Deleting obsolete update revisions' -PercentComplete ($TasksDone / $TasksTotal * 100)
        Write-Host (Invoke-WsusServerCleanup -UpdateServer $UpdateServer -CompressUpdates)
        $TasksDone++
    }

    if ($DeclineExpiredUpdates) {
        Write-Progress @WriteProgressParams -Status 'Declining expired updates' -PercentComplete ($TasksDone / $TasksTotal * 100)
        Write-Host (Invoke-WsusServerCleanup -UpdateServer $UpdateServer -DeclineExpiredUpdates)
        $TasksDone++
    }

    if ($DeclineSupersededUpdates) {
        Write-Progress @WriteProgressParams -Status 'Declining superseded updates' -PercentComplete ($TasksDone / $TasksTotal * 100)
        Write-Host (Invoke-WsusServerCleanup -UpdateServer $UpdateServer -DeclineSupersededUpdates)
        $TasksDone++
    }

    Write-Progress @WriteProgressParams -Completed
}

Function Invoke-WsusServerSynchronisation {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([Void])]
    Param(
        [Parameter(Mandatory)]
        [Microsoft.UpdateServices.Internal.BaseApi.UpdateServer]$UpdateServer
    )

    if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'WSUS synchronization')) {
        $SyncStatus = $UpdateServer.GetSubscription().GetSynchronizationStatus()
        if ($SyncStatus -eq 'NotProcessing') {
            $UpdateServer.GetSubscription().StartSynchronization()
        } elseif ($SyncStatus -eq 'Running') {
            Write-Warning -Message 'A synchronisation appears to already be running! Waiting for it to complete ...'
        } else {
            throw 'WSUS server returned unknown synchronisation status: {0}' -f $SyncStatus
        }

        do {
            Start-Sleep -Seconds 5
        } while ($UpdateServer.GetSubscription().GetSynchronizationStatus() -eq 'Running')

        $SyncResult = $UpdateServer.GetSubscription().GetLastSynchronizationInfo().Result
        if ($SyncResult -ne 'Succeeded') {
            throw 'WSUS server synchronisation completed with unexpected result: {0}' -f $SyncResult
        }
    }
}

Function Invoke-WsusServerSpringClean {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([Void])]
    Param(
        [Parameter(Mandatory)]
        [Microsoft.UpdateServices.Internal.BaseApi.UpdateServer]$UpdateServer,

        [Switch]$DeclineClusterUpdates,
        [Switch]$DeclineFarmUpdates,
        [Switch]$DeclinePrereleaseUpdates,
        [Switch]$DeclineSecurityOnlyUpdates,
        [Switch]$DeclineWindowsNextUpdates,

        [String[]]$DeclineCategories,
        [Xml.XmlElement[]]$DeclineArchitectures,
        [Xml.XmlElement[]]$DeclineLanguages,

        [ValidateRange(-1, [Int]::MaxValue)]
        [Int]$ProgressParentId
    )

    $WriteProgressParams = @{
        Activity = 'Running PSWsusSpringClean custom clean-up tasks'
    }

    if ($PSBoundParameters.ContainsKey('ProgressParentId')) {
        $WriteProgressParams['ParentId'] = $ProgressParentId
        $WriteProgressParams['Id'] = $ProgressParentId + 1
    }

    $TasksDone = 0
    $TasksTotal = 2 # Retrieving approved & unapproved updates
    $ValidTasks = @(
        'DeclineClusterUpdates'
        'DeclineFarmUpdates'
        'DeclinePrereleaseUpdates'
        'DeclineSecurityOnlyUpdates'
        'DeclineWindowsNextUpdates'
        'DeclineCategories'
        'DeclineCategories'
        'DeclineLanguages'
    )

    foreach ($Param in $MyInvocation.MyCommand.Parameters.Values) {
        # This kind of sucks but as we're enumerating switch parameters we'll
        # also get built-in ones like -Verbose. I'm not aware of any way to
        # programmatically filter these out, and a blocklist feels brittle.
        if ($Param.Name -notin $ValidTasks) {
            continue
        }

        if ($Param.SwitchParameter) {
            if ((Get-Variable -Name $Param.Name -ValueOnly) -eq $true) {
                $TasksTotal++
            }
        } else {
            $ArrayVar = Get-Variable -Name $Param.Name -ValueOnly
            if ($null -ne $ArrayVar -and $ArrayVar.Count -gt 0) {
                $TasksTotal++
            }
        }
    }

    $UpdateScope = New-Object -TypeName 'Microsoft.UpdateServices.Administration.UpdateScope'

    Write-Progress @WriteProgressParams -Status 'Retrieving approved updates' -PercentComplete ($TasksDone / $TasksTotal * 100)
    $UpdateScope.ApprovedStates = [Microsoft.UpdateServices.Administration.ApprovedStates]::LatestRevisionApproved
    $WsusApproved = $UpdateServer.GetUpdates($UpdateScope)
    $TasksDone++

    Write-Progress @WriteProgressParams -Status 'Retrieving unapproved updates' -PercentComplete ($TasksDone / $TasksTotal * 100)
    $UpdateScope.ApprovedStates = [Microsoft.UpdateServices.Administration.ApprovedStates]::NotApproved
    $WsusUnapproved = $UpdateServer.GetUpdates($UpdateScope)
    $TasksDone++

    $WsusAnyExceptDeclined = $WsusApproved + $WsusUnapproved

    if ($DeclineClusterUpdates) {
        Write-Progress @WriteProgressParams -Status 'Declining cluster updates' -PercentComplete ($TasksDone / $TasksTotal * 100)
        Invoke-WsusDeclineUpdatesByRegEx -Updates $WsusAnyExceptDeclined -RegEx $Script:RegExClusterUpdates
        $TasksDone++
    }

    if ($DeclineFarmUpdates) {
        Write-Progress @WriteProgressParams -Status 'Declining farm updates' -PercentComplete ($TasksDone / $TasksTotal * 100)
        Invoke-WsusDeclineUpdatesByRegEx -Updates $WsusAnyExceptDeclined -RegEx $Script:RegExFarmUpdates
        $TasksDone++
    }

    if ($DeclinePrereleaseUpdates) {
        Write-Progress @WriteProgressParams -Status 'Declining pre-release updates' -PercentComplete ($TasksDone / $TasksTotal * 100)
        Invoke-WsusDeclineUpdatesByRegEx -Updates $WsusAnyExceptDeclined -RegEx $Script:RegExPrereleaseUpdates
        $TasksDone++
    }

    if ($DeclineSecurityOnlyUpdates) {
        Write-Progress @WriteProgressParams -Status 'Declining Security Only updates' -PercentComplete ($TasksDone / $TasksTotal * 100)
        Invoke-WsusDeclineUpdatesByRegEx -Updates $WsusAnyExceptDeclined -RegEx $Script:RegExSecurityOnlyUpdates
        $TasksDone++
    }

    if ($DeclineWindowsNextUpdates) {
        Write-Progress @WriteProgressParams -Status 'Declining Windows Next updates' -PercentComplete ($TasksDone / $TasksTotal * 100)
        Invoke-WsusDeclineUpdatesByRegEx -Updates $WsusAnyExceptDeclined -RegEx $Script:RegExWindowsNextUpdates
        $TasksDone++
    }

    if ($PSBoundParameters.ContainsKey('DeclineCategories')) {
        $PercentComplete = $TasksDone / $TasksTotal * 100
        foreach ($Category in $DeclineCategories) {
            $Status = 'Declining updates in category: {0}' -f $Category
            Write-Progress @WriteProgressParams -Status $Status -PercentComplete $PercentComplete
            Invoke-WsusDeclineUpdatesByCatalogue -Updates $WsusAnyExceptDeclined -Category $Category
        }
        $TasksDone++
    }

    if ($PSBoundParameters.ContainsKey('DeclineArchitectures')) {
        $PercentComplete = $TasksDone / $TasksTotal * 100
        foreach ($Architecture in $DeclineArchitectures) {
            $Status = 'Declining updates with architecture: {0}' -f $Architecture.name
            Write-Progress @WriteProgressParams -Status $Status -PercentComplete $PercentComplete
            $RegExArchitecture = '\s({0})' -f $Architecture.regex
            Invoke-WsusDeclineUpdatesByRegEx -Updates $WsusAnyExceptDeclined -RegEx $RegExArchitecture
        }
        $TasksDone++
    }

    if ($PSBoundParameters.ContainsKey('DeclineLanguages')) {
        $PercentComplete = $TasksDone / $TasksTotal * 100
        foreach ($Language in $DeclineLanguages) {
            $Status = 'Declining updates with language: {0}' -f $Language.code
            Write-Progress @WriteProgressParams -Status $Status -PercentComplete $PercentComplete
            $RegExLanguage = '\s\[?{0}(_LP|_LIP)?\]?' -f $Language.code
            Invoke-WsusDeclineUpdatesByRegEx -Updates $WsusAnyExceptDeclined -RegEx $RegExLanguage
        }
        $TasksDone++
    }

    Write-Progress @WriteProgressParams -Completed
}

Function Test-WsusSpringCleanArchitectures {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [OutputType([Boolean])]
    Param(
        [Parameter(Mandatory)]
        [String[]]$Architectures
    )

    Import-WsusSpringCleanMetadata

    $KnownArchitectures = $Script:WscMetadata.Architectures.Architecture.name
    foreach ($Architecture in $Architectures) {
        if ($Architecture -notin $KnownArchitectures) {
            throw 'Unknown architecture specified: {0}' -f $Architecture
        }
    }

    return $true
}

Function Test-WsusSpringCleanLanguageCodes {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [OutputType([Boolean])]
    Param(
        [Parameter(Mandatory)]
        [String[]]$LanguageCodes
    )

    Import-WsusSpringCleanMetadata

    $KnownLanguageCodes = $Script:WscMetadata.Languages.Language.code
    foreach ($LanguageCode in $LanguageCodes) {
        if ($LanguageCode -notin $KnownLanguageCodes) {
            throw 'Unknown language code specified: {0}' -f $LanguageCode
        }
    }

    return $true
}

Function ConvertTo-WsusSpringCleanCatalogue {
    [OutputType([PSCustomObject[]])]
    Param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [Microsoft.UpdateServices.Internal.BaseApi.Update[]]$Updates
    )

    Process {
        foreach ($Update in $Updates) {
            $ProductTitles = New-Object -TypeName 'Collections.Generic.List[String]'
            foreach ($ProductTitle in $Update.ProductTitles) {
                $ProductTitles.Add($ProductTitle)
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
    [OutputType([Void])]
    Param(
        [ValidateNotNullOrEmpty()]
        [String]$CataloguePath
    )

    if (!$PSBoundParameters.ContainsKey('CataloguePath')) {
        $CataloguePath = Join-Path -Path $PSScriptRoot -ChildPath 'PSWsusSpringClean.csv'
    }

    Write-Verbose -Message 'Importing update catalogue ...'
    $Script:WscCatalogue = Import-Csv -Path $CataloguePath
}

Function Test-WsusSpringCleanCatalogue {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    Param(
        [Microsoft.UpdateServices.Internal.BaseApi.UpdateServer]$UpdateServer,

        [ValidateNotNullOrEmpty()]
        [String]$CataloguePath
    )

    if (!$PSBoundParameters.ContainsKey('UpdateServer')) {
        try {
            $UpdateServer = Get-WsusServer
        } catch {
            throw 'Failed to connect to local WSUS server via Get-WsusServer.'
        }
    }

    if ($PSBoundParameters.ContainsKey('CataloguePath')) {
        Import-WsusSpringCleanCatalogue @PSBoundParameters
    } else {
        Import-WsusSpringCleanCatalogue
    }

    $WriteProgressParams = @{
        Activity = 'Testing PSWsusSpringClean catalogue'
    }

    $Results = New-Object -TypeName 'Collections.Generic.List[PSCustomObject]'
    $TasksDone = 0
    $TasksTotal = 3

    Write-Progress @WriteProgressParams -Status 'Retrieving all updates' -PercentComplete ($TasksDone / $TasksTotal * 100)
    $WsusUpdateScope = New-Object -TypeName 'Microsoft.UpdateServices.Administration.UpdateScope'
    $WsusUpdateScope.ApprovedStates = [Microsoft.UpdateServices.Administration.ApprovedStates]::Any
    $WsusUpdates = $UpdateServer.GetUpdates($WsusUpdateScope)
    $TasksDone++

    Write-Progress @WriteProgressParams -Status 'Scanning for updates marked as superseded' -PercentComplete ($TasksDone / $TasksTotal * 100)
    foreach ($Update in ($Script:WscCatalogue | Where-Object Category -EQ 'Superseded')) {
        if ($Update.Title -in $WsusUpdates.Title) {
            $MatchedUpdates = @($WsusUpdates | Where-Object Title -EQ $Update.Title)
            $SupersededUpdates = @($MatchedUpdates | Where-Object IsSuperseded -EQ $true)

            if ($MatchedUpdates.Count -eq $SupersededUpdates.Count) {
                $Results.Add($Update)
            }
        }
    }
    $TasksDone++

    Write-Progress @WriteProgressParams -Status 'Scanning for updates not present in WSUS' -PercentComplete ($TasksDone / $TasksTotal * 100)
    foreach ($Update in $Script:WscCatalogue) {
        if ($Update.Title -notin $WsusUpdates.Title) {
            $Results.Add($Update)
        }
    }
    $TasksDone++

    Write-Progress @WriteProgressParams -Completed
    return $Results.ToArray()
}
