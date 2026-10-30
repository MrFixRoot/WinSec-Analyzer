# Interactive orchestration over stored results. No provider queries.
function Get-WinSecWorkflowSources {
    param($State,$Context,[ValidateSet('LATEST_ATTEMPT','PREFER_COMPLETE')][string]$SourcePreference='LATEST_ATTEMPT')
    $scope=Get-WinSecCLIViewScope $State
    $section=[pscustomobject]@{Screen='Section';SelectedDeviceId=$State.SelectedDeviceId;SectionIndex=$State.SectionIndex;ControlIndex=0}
    $views=@(Get-WinSecCLIControlViews $section $Context -SourcePreference $SourcePreference)
    foreach($view in $views) {
        if($scope.ScopeType -ceq 'CONTROL' -and $view.CheckId -cne $scope.ScopeKey){continue}
        $key=Get-WinSecScanSessionKey $view.DeviceId $view.ScanId
        $entry=$Context.ScanCoordinator.Sessions[$key]
        if($null -eq $entry){throw 'Missing analysis session.'}
        $public=Get-WinSecCoordinatorPublicResult -Coordinator $Context.ScanCoordinator -DeviceId $view.DeviceId -ScanId $view.ScanId
        $publicKey='{0}:{1}{2}:{3}' -f $view.DeviceId.Length,$view.DeviceId,$view.ScanId.Length,$view.ScanId
        $indexed=Copy-WinSecResultData $Context.PublicScans[$publicKey]
        # Operational receipts are not part of the immutable public record.
        foreach($name in @('EvidenceStorageStatus','EvidenceStoredCount','EvidenceFailedCount','EvidenceSkippedCount','StoredEvidenceCount','FailedEvidenceCount','SkippedEvidenceCount')){
            $public.PSObject.Properties.Remove($name);$indexed.PSObject.Properties.Remove($name)
        }
        if((Get-WinSecPublicHistoryJson $public) -cne (Get-WinSecPublicHistoryJson $indexed)){throw 'Public source cache contradicts its stored session.'}
        $local=Get-WinSecCLIValue $Context LocalDeviceId
        $origin=if($local -ceq $view.DeviceId -and (Get-WinSecCLIValue $entry HistoryOrigin) -cne 'PUBLIC_STORE'){'LIVE'}else{'RECORDS'}
        [pscustomobject]@{CheckId=$view.CheckId;ScanId=$view.ScanId;ScopeType=$view.ScopeType;ScopeKey=$view.ScopeKey;
            CompletedAtUTC=$public.CompletedAtUTC;Origin=$origin;PublicResult=$public;
            CatalogVersion=$entry.Session.CatalogVersion;ExpectedCheckIds=@($entry.Session.ExpectedCheckIds)}
    }
}

function Get-WinSecWorkflowSourceStamp {
    param([object[]]$Sources)
    Get-WinSecReportTextHash (Get-WinSecPublicHistoryJson @($Sources))
}

function Get-WinSecWorkflowControlState {
    param($Source,$Context)
    if($null -eq $Source){return 'PENDING'}
    $control=@($Source.PublicResult.ControlResults|Where-Object CheckId -CEQ $Source.CheckId)
    if($control.Count -ne 1){throw 'Ambiguous control completion.'}
    if($control[0].ObservedStatus -cnotin @('INFORMATIONAL','PASS','FAIL','NOT_APPLICABLE')){return 'PARTIAL'}
    # Completion describes collector execution, not whether optional telemetry or
    # framework coverage is complete. Keep this identical after history reload.
    return 'COMPLETE'
}

function Get-WinSecWorkflowControlRows {
    param($State,$Context)
    $selection=[pscustomobject]@{Screen='Section';SelectedDeviceId=$State.SelectedDeviceId;
        SectionIndex=$State.SectionIndex;ControlIndex=0}
    # Rendering uses already validated public projections, never raw sessions
    # or technical-file loading. Full source agreement is checked by F/P.
    $views=@(Get-WinSecCLIControlViews $selection $Context)
    $sections=@(Get-WinSecMainMenuSections)
    $controls=@(Get-WinSecSectionControls $sections[$State.SectionIndex].Key)
    foreach($control in $controls) {
        $matches=@($views|Where-Object CheckId -CEQ $control.CheckId)
        $source=$null;$mode='-';$last='Never'
        if($matches.Count){
            if($matches.Count -ne 1){throw 'Ambiguous control presentation.'}
            $view=$matches[0];$key=Get-WinSecScanSessionKey $view.DeviceId $view.ScanId
            $entry=$Context.ScanCoordinator.Sessions[$key]
            if($null -eq $entry){throw 'Missing presentation source.'}
            $entryDevice=Get-WinSecCLIStoredValue $entry DeviceId;$entryScan=Get-WinSecCLIStoredValue $entry ScanId
            if($entryDevice -isnot [string] -or $entryScan -isnot [string] -or
                $entryDevice -cne $view.DeviceId -or $entryScan -cne $view.ScanId){throw 'Foreign presentation source.'}
            $origin=Get-WinSecCLIStoredValue $entry HistoryOrigin
            $mode=if((Get-WinSecCLIValue $Context LocalDeviceId) -ceq $view.DeviceId -and $origin -cne 'PUBLIC_STORE'){'LIVE'}else{'RECORDS'}
            $last=$view.CompletedAtUTC
            $source=[pscustomobject]@{CheckId=$control.CheckId;PublicResult=[pscustomobject]@{ControlResults=$view.ControlResults}}
        }
        [pscustomobject]@{Id=$control.Id;CheckId=$control.CheckId;Name=$control.Name;
            Status=(Get-WinSecWorkflowControlState $source $Context);
            Mode=$mode;LastScan=$last}
    }
}

function Get-WinSecWorkflowAggregateState {
    param([object[]]$Rows)
    if(-not $Rows.Count -or @($Rows|Where-Object Status -CNE PENDING).Count -eq 0){return 'PENDING'}
    if(@($Rows|Where-Object Status -CNE COMPLETE).Count){return 'PARTIAL'}
    return 'COMPLETE'
}

function Get-WinSecWorkflowAggregateMode {
    param([object[]]$Rows)
    $collected=@($Rows|Where-Object Status -CNE PENDING)
    if(-not $collected.Count){return '-'}
    if($collected.Count -gt 0 -and @($collected|Where-Object Mode -CNE LIVE).Count -eq 0){return 'LIVE'}
    return 'RECORDS'
}

function Invoke-WinSecCLIFrameworkFindings {
    param($State,$Context,[switch]$ShowProgress)
    $scope=Get-WinSecCLIViewScope $State
    if($ShowProgress){Show-WinSecFrameworkProgress ([pscustomobject]@{Completed=0;
        Total=@(Get-WinSecTechnicalScopeChecks $scope.ScopeType $scope.ScopeKey).Count;Phase='Selecting saved source history'})}
    $sources=@(Get-WinSecWorkflowSources $State $Context)
    $stamp=Get-WinSecWorkflowSourceStamp $sources
    $selectionStamp=Get-WinSecReportTextHash (Get-WinSecPublicHistoryJson ([pscustomobject]@{DeviceId=$State.SelectedDeviceId;Scope=$scope}))
    $preference='LATEST_ATTEMPT'
    $selection=[pscustomobject]@{DeviceId=$State.SelectedDeviceId;ScanId=if($sources.Count){$sources[0].ScanId}else{'no-saved-scan'};
        ScopeType=$scope.ScopeType;ScopeKey=$scope.ScopeKey;SourceCount=$sources.Count}
    $completeSources=@(Get-WinSecWorkflowSources $State $Context -SourcePreference PREFER_COMPLETE)
    if($stamp -cne (Get-WinSecWorkflowSourceStamp $completeSources)){
        $choices=@(Show-WinSecFindingsSourceSelection -Selection $selection)
        if($choices.Count -ne 1){throw 'Invalid source selection.'}
        $choice=Copy-WinSecResultData $choices[0]
        Assert-WinSecConfigurationFields $choice @('Confirmed','SourcePreference')
        if($choice.Confirmed -isnot [bool]){throw 'Invalid source confirmation.'}
        if(-not $choice.Confirmed){if($null -ne $choice.SourcePreference){throw 'Contradictory source cancellation.'};return $false}
        if($choice.SourcePreference -cnotin @('LATEST_ATTEMPT','PREFER_COMPLETE') -or
            $stamp -cne (Get-WinSecWorkflowSourceStamp @(Get-WinSecWorkflowSources $State $Context))){throw 'Saved source selection changed.'}
        $preference=$choice.SourcePreference
        $sources=@(Get-WinSecWorkflowSources $State $Context -SourcePreference $preference)
        $stamp=Get-WinSecWorkflowSourceStamp $sources
    }
    $decision=@(Show-WinSecExportFrameworkSelection -Selection $selection -ForFindings)
    if($decision.Count -ne 1){throw 'Invalid framework decision.'}
    $answer=Copy-WinSecResultData $decision[0]
    Assert-WinSecConfigurationFields $answer @('Confirmed','FrameworkId')
    if($answer.Confirmed -isnot [bool]){throw 'Invalid framework confirmation.'}
    if(-not $answer.Confirmed){if($null -ne $answer.FrameworkId){throw 'Contradictory cancellation.'};return $false}
    if($answer.FrameworkId -cnotin @('nist-csf','cis-controls','mitre-attack') -or
        $stamp -cne (Get-WinSecWorkflowSourceStamp @(Get-WinSecWorkflowSources $State $Context -SourcePreference $preference)) -or
        $selectionStamp -cne (Get-WinSecReportTextHash (Get-WinSecPublicHistoryJson ([pscustomobject]@{DeviceId=$State.SelectedDeviceId;Scope=(Get-WinSecCLIViewScope $State)})))){throw 'Analysis selection changed.'}
    $reports=@();$snapshots=@();$loaded=0
    $projected=(Get-WinSecCLIValue $Context.ScanCoordinator NewTechnicalStorageEnabled) -ceq $true
    $display=[pscustomobject]@{Last=$null;Cancelled=$false;Clock=[Diagnostics.Stopwatch]::StartNew()}
    $progress=$null;$cancellation=$null
    if($ShowProgress) {
        $cancellation={
            for($i=0;$i -lt 32;$i++){$key=Read-WinSecPendingKey;if($null -eq $key){break};
                if($key.KeyDown -cne $false -and ([int]$key.ControlKeyState -band 0x0F) -eq 0 -and $key.VirtualKeyCode -eq 27){$display.Cancelled=$true}}
            return $display.Cancelled
        }
    }
    if($ShowProgress){Show-WinSecFrameworkProgress ([pscustomobject]@{Completed=0;Total=$sources.Count;Phase='Loading saved snapshots'})}
    foreach($source in $sources) {
        if($cancellation -and (& $cancellation)){return $false}
        $key=(Get-WinSecScanSessionKey $State.SelectedDeviceId $source.ScanId)+'|'+$source.CheckId
        $cache=Get-WinSecCLIValue $Context.ScanCoordinator TechnicalSnapshots
        try{$r=if($projected){
            $saved=Read-WinSecProjectionFrameworkSource $Context.ScanCoordinator $source -CancellationAction $cancellation
            if($null -ne $saved.Snapshot){$snapshots+=,$saved.Snapshot};$saved.Report
        }elseif($null -ne $cache -and $cache.ContainsKey($key)){$cache[$key]}else{
            Read-WinSecTechnicalReport $Context.ProjectRoot $State.SelectedDeviceId $source.ScanId $source.CheckId
        }}catch [OperationCanceledException]{return $false}
        if($cancellation -and (& $cancellation)){return $false}
        if($null -ne $r){$reports+=,$r}
        $loaded++
        if($ShowProgress){Show-WinSecFrameworkProgress ([pscustomobject]@{Completed=$loaded;Total=$sources.Count;Phase='Loading saved snapshots'})}
    }
    $device=@($Context.Devices|Where-Object DeviceId -CEQ $State.SelectedDeviceId)
    if($device.Count -ne 1){throw 'Ambiguous analysis device.'}
    $name=Get-WinSecCLIValue $device[0] DisplayName;if(-not $name){$name=$device[0].Hostname}
    if($ShowProgress) {
        $progress={param($event);$display.Last=$event
            if($event.Completed -eq 0 -or $event.Completed -eq $event.Total -or $display.Clock.ElapsedMilliseconds -ge 80) {
                Show-WinSecFrameworkProgress $event;$display.Clock.Restart()
            }
        }
    }
    if($projected){
        $review=New-WinSecProjectionFrameworkAnalysis -ProjectRoot $Context.ProjectRoot -DeviceId $State.SelectedDeviceId -DeviceName $name `
            -ScopeType $scope.ScopeType -ScopeKey $scope.ScopeKey -FrameworkId $answer.FrameworkId -Sources $sources -Reports $reports -Snapshots $snapshots `
            -ProgressCallback $progress -CancellationAction $cancellation
        $analysis=if($null -ne $review){$review.Analysis}else{$null}
    }else{
    $analysis=New-WinSecFrameworkAnalysis -ProjectRoot $Context.ProjectRoot -DeviceId $State.SelectedDeviceId -DeviceName $name `
        -ScopeType $scope.ScopeType -ScopeKey $scope.ScopeKey -FrameworkId $answer.FrameworkId -Sources $sources -Reports $reports `
        -ProgressCallback $progress -CancellationAction $cancellation
    }
    if($null -eq $analysis){return $false}
    if($stamp -cne (Get-WinSecWorkflowSourceStamp @(Get-WinSecWorkflowSources $State $Context -SourcePreference $preference)) -or
        $selectionStamp -cne (Get-WinSecReportTextHash (Get-WinSecPublicHistoryJson ([pscustomobject]@{DeviceId=$State.SelectedDeviceId;Scope=(Get-WinSecCLIViewScope $State)})))){throw 'Analysis sources changed.'}
    $Context|Add-Member FrameworkFindings $analysis -Force
    $Context|Add-Member FrameworkSourcesStamp $stamp -Force
    $Context|Add-Member FrameworkSourcePreference $preference -Force
    if($null -ne $Context.PSObject.Properties['LastExportMessage']){$Context.LastExportMessage=''}
    return $true
}

function Export-WinSecCLIFrameworkFindings {
    param($State,$Context)
    if($State.Screen -cne 'Findings'){throw 'Open Findings before exporting.'}
    $scope=Get-WinSecCLIViewScope $State
    $a=Assert-WinSecFrameworkAnalysis (Get-WinSecCLIValue $Context FrameworkFindings) $State.SelectedDeviceId $scope.ScopeType $scope.ScopeKey
    $preference=Get-WinSecCLIValue $Context FrameworkSourcePreference
    if($null -eq $preference){$preference='LATEST_ATTEMPT'}
    if($preference -cnotin @('LATEST_ATTEMPT','PREFER_COMPLETE')){throw 'Invalid frozen source preference.'}
    if((Get-WinSecCLIValue $Context FrameworkSourcesStamp) -cne (Get-WinSecWorkflowSourceStamp @(Get-WinSecWorkflowSources $State $Context -SourcePreference $preference))){throw 'Sources changed; reopen Findings.'}
    $result=Export-WinSecFrameworkAnalysis $Context.ProjectRoot $a
    $Context|Add-Member LastExportMessage ('Exported: '+$result.RelativePath) -Force
    return $result
}
