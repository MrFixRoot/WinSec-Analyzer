# Interactive orchestration over stored results. No provider queries.
function Get-WinSecWorkflowSources {
    param($State,$Context)
    $scope=Get-WinSecCLIViewScope $State
    $section=[pscustomobject]@{Screen='Section';SelectedDeviceId=$State.SelectedDeviceId;SectionIndex=$State.SectionIndex;ControlIndex=0}
    $views=@(Get-WinSecCLIControlViews $section $Context)
    foreach($view in $views) {
        if($scope.ScopeType -ceq 'CONTROL' -and $view.CheckId -cne $scope.ScopeKey){continue}
        $key=Get-WinSecScanSessionKey $view.DeviceId $view.ScanId
        $entry=$Context.ScanCoordinator.Sessions[$key]
        if($null -eq $entry){throw 'Missing analysis session.'}
        $public=Get-WinSecCoordinatorPublicResult -Coordinator $Context.ScanCoordinator -DeviceId $view.DeviceId -ScanId $view.ScanId
        # Operational receipts are not part of the immutable public record.
        foreach($name in @('EvidenceStorageStatus','EvidenceStoredCount','EvidenceFailedCount','EvidenceSkippedCount')){$public.PSObject.Properties.Remove($name)}
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
    if($control[0].ObservedStatus -cin @('ERROR','UNKNOWN','NOT_EVALUATED','NOT_CHECKED')){return 'PARTIAL'}
    # Completion describes collector execution, not whether optional telemetry or
    # framework coverage is complete. Keep this identical after history reload.
    return 'COMPLETE'
}

function Get-WinSecWorkflowControlRows {
    param($State,$Context)
    $selection=[pscustomobject]@{Screen='Findings';FindingsScope='Section';SelectedDeviceId=$State.SelectedDeviceId;
        SectionIndex=$State.SectionIndex;ControlIndex=0}
    $sources=@(Get-WinSecWorkflowSources $selection $Context)
    $sections=@(Get-WinSecMainMenuSections)
    $controls=@(Get-WinSecSectionControls $sections[$State.SectionIndex].Key)
    foreach($control in $controls) {
        $matches=@($sources|Where-Object CheckId -CEQ $control.CheckId)
        $source=if($matches.Count){$matches[0]}else{$null}
        [pscustomobject]@{Id=$control.Id;CheckId=$control.CheckId;Name=$control.Name;
            Status=(Get-WinSecWorkflowControlState $source $Context);
            Mode=if($null -eq $source){'-'}elseif($source.Origin -ceq 'LIVE'){'LIVE'}else{'RECORDS'};
            LastScan=if($null -ne $source){$source.CompletedAtUTC}else{'Never'}}
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
    $sources=@(Get-WinSecWorkflowSources $State $Context)
    $stamp=Get-WinSecWorkflowSourceStamp $sources
    $selection=[pscustomobject]@{DeviceId=$State.SelectedDeviceId;ScanId=if($sources.Count){$sources[0].ScanId}else{'no-saved-scan'};
        ScopeType=$scope.ScopeType;ScopeKey=$scope.ScopeKey;SourceCount=$sources.Count}
    $decision=@(Show-WinSecExportFrameworkSelection -Selection $selection -ForFindings)
    if($decision.Count -ne 1){throw 'Invalid framework decision.'}
    $answer=Copy-WinSecResultData $decision[0]
    Assert-WinSecConfigurationFields $answer @('Confirmed','FrameworkId')
    if($answer.Confirmed -isnot [bool]){throw 'Invalid framework confirmation.'}
    if(-not $answer.Confirmed){if($null -ne $answer.FrameworkId){throw 'Contradictory cancellation.'};return $false}
    if($answer.FrameworkId -cnotin @('nist-csf','cis-controls','mitre-attack') -or
        $stamp -cne (Get-WinSecWorkflowSourceStamp @(Get-WinSecWorkflowSources $State $Context))){throw 'Analysis selection changed.'}
    $reports=@();$loaded=0
    if($ShowProgress){Show-WinSecFrameworkProgress ([pscustomobject]@{Completed=0;Total=$sources.Count;Phase='Loading saved snapshots'})}
    foreach($source in $sources) {
        $key=(Get-WinSecScanSessionKey $State.SelectedDeviceId $source.ScanId)+'|'+$source.CheckId
        $cache=Get-WinSecCLIValue $Context.ScanCoordinator TechnicalSnapshots
        $r=if($null -ne $cache -and $cache.ContainsKey($key)){$cache[$key]}else{
            Read-WinSecTechnicalReport $Context.ProjectRoot $State.SelectedDeviceId $source.ScanId $source.CheckId
        }
        if($null -ne $r){$reports+=,$r}
        $loaded++
        if($ShowProgress){Show-WinSecFrameworkProgress ([pscustomobject]@{Completed=$loaded;Total=$sources.Count;Phase='Loading saved snapshots'})}
    }
    $device=@($Context.Devices|Where-Object DeviceId -CEQ $State.SelectedDeviceId)
    if($device.Count -ne 1){throw 'Ambiguous analysis device.'}
    $name=Get-WinSecCLIValue $device[0] DisplayName;if(-not $name){$name=$device[0].Hostname}
    $display=[pscustomobject]@{Last=$null;Cancelled=$false;Clock=[Diagnostics.Stopwatch]::StartNew()}
    $progress=$null;$cancellation=$null
    if($ShowProgress) {
        $progress={param($event);$display.Last=$event
            if($event.Completed -eq 0 -or $event.Completed -eq $event.Total -or $display.Clock.ElapsedMilliseconds -ge 80) {
                Show-WinSecFrameworkProgress $event;$display.Clock.Restart()
            }
        }
        $cancellation={
            for($i=0;$i -lt 32;$i++){$key=Read-WinSecPendingKey;if($null -eq $key){break};
                if($key.KeyDown -cne $false -and ([int]$key.ControlKeyState -band 0x0F) -eq 0 -and $key.VirtualKeyCode -eq 27){$display.Cancelled=$true}}
            return $display.Cancelled
        }
    }
    $analysis=New-WinSecFrameworkAnalysis -ProjectRoot $Context.ProjectRoot -DeviceId $State.SelectedDeviceId -DeviceName $name `
        -ScopeType $scope.ScopeType -ScopeKey $scope.ScopeKey -FrameworkId $answer.FrameworkId -Sources $sources -Reports $reports `
        -ProgressCallback $progress -CancellationAction $cancellation
    if($null -eq $analysis){return $false}
    if($stamp -cne (Get-WinSecWorkflowSourceStamp @(Get-WinSecWorkflowSources $State $Context))){throw 'Analysis sources changed.'}
    $Context|Add-Member FrameworkFindings $analysis -Force
    $Context|Add-Member FrameworkSourcesStamp $stamp -Force
    return $true
}

function Export-WinSecCLIFrameworkFindings {
    param($State,$Context)
    if($State.Screen -cne 'Findings'){throw 'Open Findings before exporting.'}
    $scope=Get-WinSecCLIViewScope $State
    $a=Assert-WinSecFrameworkAnalysis (Get-WinSecCLIValue $Context FrameworkFindings) $State.SelectedDeviceId $scope.ScopeType $scope.ScopeKey
    if((Get-WinSecCLIValue $Context FrameworkSourcesStamp) -cne (Get-WinSecWorkflowSourceStamp @(Get-WinSecWorkflowSources $State $Context))){throw 'Sources changed; reopen Findings.'}
    $result=Export-WinSecFrameworkAnalysis $Context.ProjectRoot $a
    $Context|Add-Member LastExportMessage ('Exported: '+$result.RelativePath) -Force
    return $result
}
