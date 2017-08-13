Function Invoke-WsusSpringClean {
    <#
        .SYNOPSIS
        Performs additional WSUS server clean-up beyond the capabilities of the built-in tools.
        .DESCRIPTION
        Adds the ability to decline numerous additional commonly unneeded updates as well as discover potentially incorrectly declined updates.
        .PARAMETER RunDefaultTasks
        Performs all clean-up tasks except for declining any unneeded updates as defined in the included update catalogue CSV file.

        You can disable one or more of the default clean-up tasks by setting the associated switch parameter to false (e.g. -CompressUpdates:$false).

        You can perform a clean-up of unneeded updates by specifying the DeclineCategoriesInclude or DeclineCategoriesExclude parameter with your chosen categories.

        Also note that this does not perform a server synchronisation before clean-up or find suspect declined updates. These tasks can be included via their respective parameters.
        .PARAMETER SynchroniseServer
        Perform a synchronisation against the upstream server before running cleanup.
        .PARAMETER FindSuspectDeclines
        Scan all declined updates for any that may have been inadvertently declined.

        The returned suspect updates are those which:
         - Are not superseded or expired
         - Are not cluster, farm or Itanium updates (if set to decline)
         - Are not in the filtered list of updates to decline from the bundled catalogue
        .PARAMETER DeclineClusterUpdates
        Decline any updates which are exclusively for failover clustering installations.
        .PARAMETER DeclineFarmUpdates
        Decline any updates which are exclusively for farm deployment installations.
        .PARAMETER DeclineItaniumUpdates
        Decline any updates which are exclusively for Itanium architecture installations.
        .PARAMETER DeclinePrereleaseUpdates
        Decline any updates which are exclusively for pre-release products (e.g. betas).
        .PARAMETER DeclineSecurityOnlyUpdates
        Decline any Security Only updates.
        .PARAMETER DeclineCategoriesExclude
        Array of update categories in the bundled updates catalogue to not decline.
        .PARAMETER DeclineCategoriesInclude
        Array of update categories in the bundled updates catalogue to decline.
        .PARAMETER CleanupObsoleteComputers
        Specifies that the cmdlet deletes obsolete computers from the database.
        .PARAMETER CleanupObsoleteUpdates
        Specifies that the cmdlet deletes obsolete updates from the database.
        .PARAMETER CleanupUnneededContentFiles
        Specifies that the cmdlet deletes unneeded update files.
        .PARAMETER CompressUpdates
        Specifies that the cmdlet deletes obsolete revisions to updates from the database.
        .PARAMETER DeclineExpiredUpdates
        Specifies that the cmdlet declines expired updates.
        .PARAMETER DeclineSupersededUpdates
        Specifies that the cmdlet declines superseded updates.
        .EXAMPLE
        PS C:\>$SuspectDeclines = Invoke-WsusSpringClean -RunDefaultTasks -FindSuspectDeclines

        Runs the default clean-up tasks & checks for declined updates that may not be intentional.
        .EXAMPLE
        PS C:\>Invoke-WsusSpringClean -DeclineClusterUpdates -DeclineFarmUpdates -DeclineItaniumUpdates

        Declines all failover clustering, farm server/deployment & Itanium updates.
        .EXAMPLE
        PS C:\>Invoke-WsusSpringClean -DeclineCategoriesInclude @('Region - US', 'Superseded')

        Declines all unneeded updates in the "Region - US" & "Superseded" categories.
        .EXAMPLE
        PS C:\>Invoke-WsusSpringClean -RunDefaultTasks -DeclineCategoriesExclude @() -WhatIf

        Show what updates would be declined if we were to decline all unneeded updates.
        .NOTES
        The script intentionally avoids usage of most WSUS cmdlets provided by the UpdateServices module as many are extremely slow. This is particularly true of the Get-WsusUpdate cmdlet.

        The efficiency of the update declining logic could be substantially improved. That said, this script is not typically run frequently (~monthly), so this isn't a major priority.
        .LINK
        https://github.com/ralish/PSWsusSpringClean
    #>

    [CmdletBinding(DefaultParameterSetName='Default',SupportsShouldProcess)]
    Param(
        [Switch]$RunDefaultTasks,
        [Switch]$SynchroniseServer,
        [Switch]$FindSuspectDeclines,

        [Switch]$DeclineClusterUpdates,
        [Switch]$DeclineFarmUpdates,
        [Switch]$DeclineItaniumUpdates,
        [Switch]$DeclinePrereleaseUpdates,
        [Switch]$DeclineSecurityOnlyUpdates,

        [String[]]$DeclineCategoriesExclude,
        [String[]]$DeclineCategoriesInclude,

        # Wrapping of Invoke-WsusServerCleanup
        [Switch]$CleanupObsoleteComputers,
        [Switch]$CleanupObsoleteUpdates,
        [Switch]$CleanupUnneededContentFiles,
        [Switch]$CompressUpdates,
        [Switch]$DeclineExpiredUpdates,
        [Switch]$DeclineSupersededUpdates
    )

    # Ensure that any errors we receive are considered fatal
    $ErrorActionPreference = 'Stop'

    if ($PSBoundParameters.ContainsKey('DeclineCategoriesExclude') -and $PSBoundParameters.ContainsKey('DeclineCategoriesInclude')) {
        throw 'Can only specify one of DeclineCategoriesExclude and DeclineCategoriesInclude.'
    }

    if ($RunDefaultTasks) {
        $DefaultTasks = @(
            'DeclineClusterUpdates',
            'DeclineFarmUpdates',
            'DeclineItaniumUpdates',
            'DeclinePrereleaseUpdates',
            'DeclineSecurityOnlyUpdates',

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

    # Regular expressions for declining certain types of updates
    $script:RegExClusterUpdates = ' Failover Clustering '
    $script:RegExFarmUpdates = ' Farm[- ]'
    $script:RegExItaniumUpdates = '(IA64|Itanium)'
    $script:RegExPrereleaseUpdates = ' (Beta|Preview|RC1|Release Candidate) '
    $script:RegExSecurityOnlyUpdates = ' Security Only (Quality )?Update '

    # Determine which categories of updates to decline (if any)
    if ($PSBoundParameters.ContainsKey('DeclineCategoriesExclude') -or $PSBoundParameters.ContainsKey('DeclineCategoriesInclude')) {
        Import-WsusSpringCleanCatalogue

        if ($PSBoundParameters.ContainsKey('DeclineCategoriesExclude')) {
            $DeclineCategories = $script:WscCategories | Where-Object { $_ -notin $DeclineCategoriesExclude }
        } else {
            $DeclineCategories = $script:WscCategories | Where-Object { $_ -in $DeclineCategoriesInclude }
        }
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
        DeclineItaniumUpdates=$DeclineItaniumUpdates
        DeclinePrereleaseUpdates=$DeclinePrereleaseUpdates
        DeclineSecurityOnlyUpdates=$DeclineSecurityOnlyUpdates
    }

    if ($DeclineCategories) {
        $SpringCleanParams += @{DeclineCategories=$DeclineCategories}
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
    [CmdletBinding()]
    Param(
        [Switch]$DeclineClusterUpdates,
        [Switch]$DeclineFarmUpdates,
        [Switch]$DeclineItaniumUpdates,
        [Switch]$DeclinePrereleaseUpdates,
        [Switch]$DeclineSecurityOnlyUpdates,

        [String[]]$DeclineCategories
    )

    $WsusServer = Get-WsusServer
    $UpdateScope = New-Object -TypeName Microsoft.UpdateServices.Administration.UpdateScope

    Write-Host -ForegroundColor Green '[*] Retrieving declined updates ...'
    $UpdateScope.ApprovedStates = [Microsoft.UpdateServices.Administration.ApprovedStates]::Declined
    $WsusDeclined = $WsusServer.GetUpdates($UpdateScope)

    $IgnoredDeclines = $script:WscCatalogue | Where-Object { $_.Category -in $DeclineCategories }

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

        # Ignore Itanium updates if they were declined
        if ($DeclineItaniumUpdates -and $Update.Title -match $RegExItaniumUpdates) {
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

        # Ignore any update categories which were declined
        if ($Update.Title -in $IgnoredDeclines.Title) {
            continue
        }

        $SuspectDeclines += $Update
    }

    return $SuspectDeclines
}


Function Invoke-WsusDeclineUpdatesByCategory {
    [CmdletBinding(SupportsShouldProcess)]
    Param(
        [Parameter(Mandatory)]
        [Microsoft.UpdateServices.Internal.BaseApi.Update[]]$Updates,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
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
        [ValidateNotNullOrEmpty()]
        [String]$RegEx,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String]$Description
    )

    Write-Host -ForegroundColor Green ('[*] Declining {0} updates ...' -f $Description)
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


Function Invoke-WsusServerSpringClean {
    [CmdletBinding(SupportsShouldProcess)]
    Param(
        [Switch]$DeclineClusterUpdates,
        [Switch]$DeclineFarmUpdates,
        [Switch]$DeclineItaniumUpdates,
        [Switch]$DeclinePrereleaseUpdates,
        [Switch]$DeclineSecurityOnlyUpdates,

        [String[]]$DeclineCategories
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
        Invoke-WsusDeclineUpdatesByRegEx -Updates $WsusAnyExceptDeclined -RegEx $script:RegExClusterUpdates -Description 'cluster'
    }

    if ($DeclineFarmUpdates) {
        Invoke-WsusDeclineUpdatesByRegEx -Updates $WsusAnyExceptDeclined -RegEx $script:RegExFarmUpdates -Description 'farm'
    }

    if ($DeclineItaniumUpdates) {
        Invoke-WsusDeclineUpdatesByRegEx -Updates $WsusAnyExceptDeclined -RegEx $script:RegExItaniumUpdates -Description 'Itanium'
    }

    if ($DeclinePrereleaseUpdates) {
        Invoke-WsusDeclineUpdatesByRegEx -Updates $WsusAnyExceptDeclined -RegEx $script:RegExPrereleaseUpdates -Description 'pre-release'
    }

    if ($DeclineSecurityOnlyUpdates) {
        Invoke-WsusDeclineUpdatesByRegEx -Updates $WsusAnyExceptDeclined -RegEx $script:RegExSecurityOnlyUpdates -Description 'Security Only'
    }

    if ($PSBoundParameters.ContainsKey('DeclineCategories')) {
        foreach ($Category in $DeclineCategories) {
            Invoke-WsusDeclineUpdatesByCategory -Updates $WsusAnyExceptDeclined -Category $Category
        }
    }
}


Function Invoke-WsusServerSynchronisation {
    [CmdletBinding(SupportsShouldProcess)]

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


Function ConvertTo-WsusSpringCleanCatalogue {
    Param(
        [Parameter(Mandatory,ValueFromPipeline)]
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

    if (!$CataloguePath) {
        $CataloguePath = Join-Path -Path $PSScriptRoot -ChildPath 'PSWsusSpringClean.csv'
    }

    Write-Host -ForegroundColor Green '[*] Importing update catalogue ...'
    $script:WscCatalogue = Import-Csv -Path $CataloguePath
    $script:WscCategories = $WscCatalogue.Category | Sort-Object | Get-Unique
}


Function Test-WsusSpringCleanCatalogue {
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [String]$CataloguePath
    )

    Import-WsusSpringCleanCatalogue @PSBoundParameters

    Write-Host -ForegroundColor Green '[*] Retrieving all updates ...'
    $WsusServer = Get-WsusServer
    $WsusUpdateScope = New-Object -TypeName Microsoft.UpdateServices.Administration.UpdateScope
    $WsusUpdateScope.ApprovedStates = [Microsoft.UpdateServices.Administration.ApprovedStates]::Any
    $WsusUpdates = $WsusServer.GetUpdates($WsusUpdateScope)

    Write-Host -ForegroundColor Green '[*] Scanning for updates only present in catalogue ...'
    $CatalogueOnly = @()
    foreach ($Update in $script:WscCatalogue) {
        if ($Update.Title -notin $WsusUpdates.Title) {
            $CatalogueOnly += $Update
        }
    }

    return $CatalogueOnly
}
