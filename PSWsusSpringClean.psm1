Function Invoke-WsusSpringClean {
    <#
        .SYNOPSIS
        Performs additional WSUS server clean-up beyond the capabilities of the built-in tools.
        .DESCRIPTION
        Adds the ability to decline numerous additional commonly unneeded updates as well as discover potentially incorrectly declined updates.
        .PARAMETER SynchroniseServer
        Perform a synchronisation against the upstream server before running cleanup.
        .PARAMETER DeclineCategoriesExclude
        Array of update categories in the bundled updates catalogue to not decline.
        .PARAMETER DeclineCategoriesInclude
        Array of update categories in the bundled updates catalogue to decline.
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
        .PARAMETER DeclineUnneededUpdates
        Decline any updates in the bundled updates catalogue filtered against the provided inclusion or exclusion categories.
        .PARAMETER FindSuspectDeclines
        Scan all declined updates for any that may have been inadvertently declined.

        The returned suspect updates are those which:
         - Are not superseded or expired
         - Are not cluster, farm or Itanium updates (if set to decline)
         - Are not in the filtered list of updates to decline from the bundled catalogue
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
        PS C:\>Invoke-WsusSpringClean -DeclineClusterUpdates -DeclineFarmUpdates -DeclineItaniumUpdates

        Declines all failover clustering, farm server/deployment & Itanium updates.
        .EXAMPLE
        PS C:\>Invoke-WsusSpringClean -DeclineUnneededUpdates -DeclineCategoriesInclude @('Superseded', 'Pre-release')

        Declines all unneeded updates in the Superseded & Pre-release categories.
        .NOTES
        The script intentionally avoids usage of most WSUS cmdlets provided by the UpdateServices module as many are extremely slow. This is particularly true of the Get-WsusUpdate cmdlet.

        The efficiency of the update declining logic could be substantially improved. That said, this script is not typically run frequently (~monthly), so this isn't a major priority.
        .LINK
        https://github.com/ralish/PSWsusSpringClean
    #>

    [CmdletBinding(DefaultParameterSetName='Include',SupportsShouldProcess)]
    Param(
        [Switch]$SynchroniseServer,

        [Parameter(ParameterSetName='Exclude')]
        [AllowEmptyCollection()]
        [String[]]$DeclineCategoriesExclude=@(),

        [Parameter(ParameterSetName='Include')]
        [AllowEmptyCollection()]
        [String[]]$DeclineCategoriesInclude=@(),

        [Switch]$DeclineClusterUpdates,
        [Switch]$DeclineFarmUpdates,
        [Switch]$DeclineItaniumUpdates,
        [Switch]$DeclinePrereleaseUpdates,
        [Switch]$DeclineSecurityOnlyUpdates,
        [Switch]$DeclineUnneededUpdates,
        [Switch]$FindSuspectDeclines,

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

    if ($SynchroniseServer) {
        Write-Host -ForegroundColor Green "`r`nStarting WSUS server synchronisation ..."
        Invoke-WsusServerSynchronisation
    }

    Write-Host -ForegroundColor Green "`r`nBeginning WSUS server cleanup (Phase 1) ..."
    $CleanupParams = @{
        CleanupObsoleteUpdates=$CleanupObsoleteUpdates
        CompressUpdates=$CompressUpdates
        DeclineExpiredUpdates=$DeclineExpiredUpdates
        DeclineSupersededUpdates=$DeclineSupersededUpdates
    }
    Invoke-WsusServerCleanupWrapper @CleanupParams

    Write-Host -ForegroundColor Green "`r`nBeginning WSUS server cleanup (Phase 2) ..."
    $ExtraCleanupParams = @{
        DeclineClusterUpdates=$DeclineClusterUpdates
        DeclineFarmUpdates=$DeclineFarmUpdates
        DeclineItaniumUpdates=$DeclineItaniumUpdates
        DeclinePrereleaseUpdates=$DeclinePrereleaseUpdates
        DeclineSecurityOnlyUpdates=$DeclineSecurityOnlyUpdates
        DeclineUnneededUpdates=$DeclineUnneededUpdates
        FindSuspectDeclines=$FindSuspectDeclines
    }
    if ($PSCmdlet.ParameterSetName -eq 'Exclude') {
        $SuspectDeclines = Invoke-WsusServerExtraCleanup -DeclineCategoriesExclude $DeclineCategoriesExclude @ExtraCleanupParams
    } else {
        $SuspectDeclines = Invoke-WsusServerExtraCleanup -DeclineCategoriesInclude $DeclineCategoriesInclude @ExtraCleanupParams
    }

    Write-Host -ForegroundColor Green "`r`nBeginning WSUS server cleanup (Phase 3) ..."
    $CleanupParams = @{
        CleanupObsoleteComputers=$CleanupObsoleteComputers
        CleanupUnneededContentFiles=$CleanupUnneededContentFiles
    }
    Invoke-WsusServerCleanupWrapper @CleanupParams

    if ($FindSuspectDeclines) {
        return $SuspectDeclines
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


Function Invoke-WsusServerExtraCleanup {
    [CmdletBinding(SupportsShouldProcess)]
    Param(
        [Parameter(ParameterSetName='Exclude',Mandatory)]
        [AllowEmptyCollection()]
        [String[]]$DeclineCategoriesExclude,

        [Parameter(ParameterSetName='Include',Mandatory)]
        [AllowEmptyCollection()]
        [String[]]$DeclineCategoriesInclude,

        [Switch]$DeclineClusterUpdates,
        [Switch]$DeclineFarmUpdates,
        [Switch]$DeclineItaniumUpdates,
        [Switch]$DeclinePrereleaseUpdates,
        [Switch]$DeclineSecurityOnlyUpdates,
        [Switch]$DeclineUnneededUpdates,
        [Switch]$FindSuspectDeclines
    )

    $WsusServer = Get-WsusServer
    $UpdateScope = New-Object -TypeName Microsoft.UpdateServices.Administration.UpdateScope

    Write-Host -ForegroundColor Green '[*] Importing update catalogue ...'
    $Catalogue = Import-Csv -Path (Join-Path -Path $PSScriptRoot -ChildPath 'PSWsusSpringClean.csv')
    $Categories = $Catalogue.Category | Sort-Object | Get-Unique

    if ($PSCmdlet.ParameterSetName -eq 'Exclude') {
        $FilteredCategories = $Categories | Where-Object { $_ -notin $DeclineCategoriesExclude }
    } else {
        $FilteredCategories = $Categories | Where-Object { $_ -in $DeclineCategoriesInclude }
    }

    Write-Host -ForegroundColor Green '[*] Retrieving approved updates ...'
    $UpdateScope.ApprovedStates = [Microsoft.UpdateServices.Administration.ApprovedStates]::LatestRevisionApproved
    $WsusApproved = $WsusServer.GetUpdates($UpdateScope)

    Write-Host -ForegroundColor Green '[*] Retrieving unapproved updates ...'
    $UpdateScope.ApprovedStates = [Microsoft.UpdateServices.Administration.ApprovedStates]::NotApproved
    $WsusUnapproved = $WsusServer.GetUpdates($UpdateScope)

    $WsusAnyExceptDeclined = $WsusApproved + $WsusUnapproved

    if ($DeclineClusterUpdates) {
        Write-Host -ForegroundColor Green '[*] Declining cluster updates ...'
        foreach ($Update in $WsusAnyExceptDeclined) {
            if ($Update.Title -match 'Failover Clustering') {
                if ($PSCmdlet.ShouldProcess($Update.Title, 'Decline')) {
                    Write-Host -ForegroundColor Cyan ('[-] Declining update: {0}' -f $Update.Title)
                    $Update.Decline()
                }
            }
        }
    }

    if ($DeclineFarmUpdates) {
        Write-Host -ForegroundColor Green '[*] Declining farm updates ...'
        foreach ($Update in $WsusAnyExceptDeclined) {
            if ($Update.Title -match '(Farm( |-deployment))') {
                if ($PSCmdlet.ShouldProcess($Update.Title, 'Decline')) {
                    Write-Host -ForegroundColor Cyan ('[-] Declining update: {0}' -f $Update.Title)
                    $Update.Decline()
                }
            }
        }
    }

    if ($DeclineItaniumUpdates) {
        Write-Host -ForegroundColor Green '[*] Declining Itanium updates ...'
        foreach ($Update in $WsusAnyExceptDeclined) {
            if ($Update.Title -match '(IA64|Itanium)') {
                if ($PSCmdlet.ShouldProcess($Update.Title, 'Decline')) {
                    Write-Host -ForegroundColor Cyan ('[-] Declining update: {0}' -f $Update.Title)
                    $Update.Decline()
                }
            }
        }
    }

    if ($DeclinePrereleaseUpdates) {
        Write-Host -ForegroundColor Green '[*] Declining pre-release updates ...'
        $Prerelease = $Catalogue | Where-Object { $_.'Pre-release' -eq $true }
        $MatchingUpdates = $WsusAnyExceptDeclined | Where-Object { $_.Title -in $Prerelease.Title }
        foreach ($Update in $MatchingUpdates) {
            if ($PSCmdlet.ShouldProcess($Update.Title, 'Decline')) {
                Write-Host -ForegroundColor Cyan ('[-] Declining update: {0}' -f $Update.Title)
                $Update.Decline()
            }
        }
    }

    if ($DeclineSecurityOnlyUpdates) {
        Write-Host -ForegroundColor Green '[*] Declining Security Only updates ...'
        foreach ($Update in $WsusAnyExceptDeclined) {
            if ($Update.Title -match 'Security Only Quality Update') {
                if ($PSCmdlet.ShouldProcess($Update.Title, 'Decline')) {
                    Write-Host -ForegroundColor Cyan ('[-] Declining update: {0}' -f $Update.Title)
                    $Update.Decline()
                }
            }
        }
    }

    if ($DeclineUnneededUpdates) {
        foreach ($Category in $FilteredCategories) {
            Write-Host -ForegroundColor Green ('[*] Declining updates in category: {0}' -f $Category)
            $UpdatesToDecline = $Catalogue | Where-Object { $_.Category -eq $Category }
            $MatchingUpdates = $UpdatesToDecline | Where-Object { $WsusAnyExceptDeclined -contains $_ }
            foreach ($Update in $MatchingUpdates) {
                if ($PSCmdlet.ShouldProcess($Update.Title, 'Decline')) {
                    Write-Host -ForegroundColor Cyan ('[-] Declining update: {0}' -f $Update.Title)
                    $Update.Decline()
                }
            }
        }
    }

    if ($FindSuspectDeclines) {
        Write-Host -ForegroundColor Green '[*] Retrieving declined updates ...'
        $UpdateScope.ApprovedStates = [Microsoft.UpdateServices.Administration.ApprovedStates]::Declined
        $WsusDeclined = $WsusServer.GetUpdates($UpdateScope)

        $IgnoredDeclines = $Catalogue | Where-Object { $_.Category -in $FilteredCategories }

        Write-Host -ForegroundColor Green '[*] Finding suspect declined updates ...'
        $SuspectUpdates = @()
        foreach ($Update in $WsusDeclined) {
            # Ignore superseded and expired updates
            if ($Update.IsSuperseded -or $Update.PublicationState -eq 'Expired') {
                continue
            }

            # Ignore cluster updates if they were declined
            if ($DeclineClusterUpdates -and $Update.Title -match 'Failover Clustering') {
                continue
            }

            # Ignore farm updates if they were declined
            if ($DeclineFarmUpdates -and $Update.Title -match '(Farm( |-deployment))') {
                continue
            }

            # Ignore Itanium updates if they were declined
            if ($DeclineItaniumUpdates -and $Update.Title -match '(IA64|Itanium)') {
                continue
            }

            # Ignore pre-release updates if they were declined
            if ($DeclinePrereleaseUpdates -and $Update.Title -in $Prerelease) {
                continue
            }

            # Ignore Security Only Quality updates if they were declined
            if ($DeclineSecurityOnlyUpdates -and $Update.Title -match 'Security Only Quality Update') {
                continue
            }

            # Ignore any update categories which were declined
            if ($Update.Title -in $IgnoredDeclines.Title) {
                continue
            }

            $SuspectUpdates += $Update
        }

        return $SuspectUpdates
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
            #$WsusServer.GetSubscription().GetSynchronizationProgress()
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
                'Pre-release'   = if ($Update.IsBeta) { 'TRUE' } else { 'FALSE' }
                'Title'         = $Update.Title
                'ProductTitles' = [String]::Join(', ', $ProductTitles)
            }
        }
    }
}


Function Test-WsusSpringCleanCatalogue {
    Param(
        [ValidateNotNullOrEmpty()]
        [String]$CataloguePath
    )

    if (!$PSBoundParameters.ContainsKey('CataloguePath')) {
        $CataloguePath = Join-Path -Path $PSScriptRoot -ChildPath 'PSWsusSpringClean.csv'
    }

    Write-Host -ForegroundColor Green '[*] Importing update catalogue ...'
    $Catalogue = Import-Csv -Path $CataloguePath

    Write-Host -ForegroundColor Green '[*] Retrieving all updates ...'
    $WsusServer = Get-WsusServer
    $WsusUpdateScope = New-Object -TypeName Microsoft.UpdateServices.Administration.UpdateScope
    $WsusUpdateScope.ApprovedStates = [Microsoft.UpdateServices.Administration.ApprovedStates]::Any
    $WsusUpdates = $WsusServer.GetUpdates($WsusUpdateScope)

    Write-Host -ForegroundColor Green '[*] Scanning for updates only present in catalogue ...'
    $CatalogueOnly = @()
    foreach ($Update in $Catalogue) {
        if ($Update.Title -notin $WsusUpdates.Title) {
            $CatalogueOnly += $Update
        }
    }

    return $CatalogueOnly
}
