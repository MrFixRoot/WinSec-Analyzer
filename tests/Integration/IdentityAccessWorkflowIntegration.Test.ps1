# Real production execution permissions, synthetic providers and disposable internal storage only.
[CmdletBinding()]param()
$ErrorActionPreference='Stop';$sourceRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$tempParent=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\','/')
$sandbox=Join-Path $tempParent ('WinSec-Identity-'+[guid]::NewGuid().ToString('N'));$null=[IO.Directory]::CreateDirectory($sandbox)
$checksHash=(Get-FileHash (Join-Path $sourceRoot 'config/checks.json')).Hash;$oldHostname=$env:COMPUTERNAME;$env:COMPUTERNAME='SYNTHETIC-IDENTITY';$passed=0;$failed=0
function Assert-IdentityIntegration {param([bool]$Value);if(-not $Value){throw 'IdentityAccess integration assertion failed.'}}
function Test-IdentityIntegration {param($Name,[scriptblock]$Action);try{$null=& $Action;$script:passed++;[Console]::WriteLine('[PASS] '+$Name)}catch{$script:failed++;[Console]::WriteLine('[FAIL] '+$Name+': '+$_.Exception.Message);[Console]::WriteLine($_.ScriptStackTrace)}}
try {
    foreach($directory in @('src','config')){Copy-Item -LiteralPath (Join-Path $sourceRoot $directory) -Destination (Join-Path $sandbox $directory) -Recurse}
    foreach($file in @('src/Core/ScanCoordinator.ps1','src/CLI/Invoke-WinSecCLI.ps1','src/UI/Core/NavigationController.ps1','src/UI/Screens/MainMenu.ps1',
        'src/UI/Screens/Results.ps1','src/CLI/FrameworkWorkflow.ps1','src/UI/Core/TerminalRenderer.ps1','src/UI/Screens/ScanProgress.ps1')){. (Join-Path $sandbox $file)}
    . (Join-Path $sourceRoot 'tests/Fixtures/IdentityAccessMemory.ps1')
    function Get-WinSecIdentityFixtureHardware {'local:hw1-'+('b'*64)}
    function Get-CimInstance {throw 'Unmocked Windows query prohibited.'}
    Set-Alias Get-WinSecLocalHardwareDeviceId Get-WinSecIdentityFixtureHardware -Scope Script
    Set-Alias Invoke-WinSecIdentityAccessQuery Invoke-WinSecIdentityFixtureQuery -Scope Script
    Initialize-WinSecIdentityFixture
    $production=Get-WinSecCheckRegistry $sandbox
    Test-IdentityIntegration 'Production enables exactly eleven validated checks including all three IAM controls' {
        $ready=@($production.Checks|Where-Object ExecutionReady)
        Assert-IdentityIntegration (($ready.CheckId -join '|') -ceq 'WSA-IAM-001|WSA-IAM-002|WSA-IAM-003|WSA-NET-001|WSA-NET-002|WSA-NET-003|WSA-NET-004|WSA-NET-005|WSA-SYS-001|WSA-SYS-002|WSA-SYS-003' -and
            @($ready|Where-Object {$_.ImplementationStatus -cne 'VALIDATED' -or -not $_.ExecutionEnabled}).Count -eq 0 -and @($production.Checks|Where-Object {-not $_.ExecutionEnabled}).Count -eq 3)
    }
    $null=Register-WinSecLocalDevice $sandbox;$target=New-WinSecLocalTarget
    $c=New-WinSecScanCoordinator $sandbox;$c.Registry=[pscustomobject]@{schemaVersion='1.0.0';targets=@($target)}
    $c.AssessmentEnabled=$true;$c.PublicHistoryEnabled=$true;$c.TechnicalReportsEnabled=$true
    Test-IdentityIntegration 'Cancelled DEVICE confirmation includes eleven checks without querying any provider' {
        $r=Invoke-WinSecCoordinatedScan $c -DeviceId $target.DeviceId -ScanId cancelled-device -ScopeType DEVICE -ScopeKey ALL -ConfirmAction {
            param($preview);Assert-IdentityIntegration ($preview.ReadOnly -and ($preview.Checks.CheckId -join '|') -ceq 'WSA-IAM-001|WSA-IAM-002|WSA-IAM-003|WSA-NET-001|WSA-NET-002|WSA-NET-003|WSA-NET-004|WSA-NET-005|WSA-SYS-001|WSA-SYS-002|WSA-SYS-003');$false
        }
        Assert-IdentityIntegration ($null -eq $r -and $IdentityCalls.Count -eq 0 -and $c.Sessions.Count -eq 0)
    }
    Test-IdentityIntegration 'Cancelled section confirmation performs no queries and publishes no session' {
        $r=Invoke-WinSecCoordinatedScan $c -DeviceId $target.DeviceId -ScanId cancelled-confirmation -ScopeType SECTION -ScopeKey IdentityAccess -AssessmentProfile WSA-W11-23H2-PRO-DEF-BASE -ConfirmAction {
            param($preview);Assert-IdentityIntegration ($preview.ReadOnly -and ($preview.Checks.CheckId -join '|') -ceq 'WSA-IAM-001|WSA-IAM-002|WSA-IAM-003' -and $preview.EvaluationProfile.Policies.Count -eq 3);$false
        }
        Assert-IdentityIntegration ($null -eq $r -and $IdentityCalls.Count -eq 0 -and $c.Sessions.Count -eq 0)
    }
    foreach($id in @('WSA-IAM-001','WSA-IAM-002','WSA-IAM-003')){Test-IdentityIntegration ('Confirmed CONTROL saves exactly its own immutable Markdown: '+$id){
        $r=Invoke-WinSecCoordinatedScan $c -DeviceId $target.DeviceId -ScanId ('control-'+$id) -ScopeType CONTROL -ScopeKey $id -AssessmentProfile WSA-W11-23H2-PRO-DEF-BASE -ConfirmAction {
            param($preview);Assert-IdentityIntegration ($preview.ReadOnly -and $preview.Checks.Count -eq 1 -and $preview.Checks[0].CheckId -ceq $id);$true
        }
        if($r.ExecutionStatus -cne 'COMPLETED' -or $c.LastTechnicalReports.Status -cne 'SAVED'){
            $entry=$c.Sessions[(Get-WinSecScanSessionKey $target.DeviceId ('control-'+$id))].Session
            foreach($record in @($entry.ControlResults|Where-Object CheckId -CEQ $id)){[Console]::WriteLine('Synthetic diagnostic: '+$record.ErrorMessage)}
            throw ('Unexpected synthetic execution: '+$r.ExecutionStatus+'; technical '+$c.LastTechnicalReports.Status+'; controls '+(($r.ControlResults|ForEach-Object {$_.CheckId+':'+$_.Status}) -join ','))
        }
        Assert-IdentityIntegration ($r.ExecutionStatus -ceq 'COMPLETED' -and $null -eq $r.OverallScore -and $null -eq $r.ConfigurationAssessment -and
            $c.LastTechnicalReports.Status -ceq 'SAVED' -and $c.LastTechnicalReports.Files.Count -eq 1 -and $c.LastTechnicalReports.Files[0].CheckId -ceq $id)
    }}
    Test-IdentityIntegration 'Esc during section rescan preserves previous sessions and files' {
        $before=$c.Sessions.Count;$files=@(Get-ChildItem (Join-Path $sandbox 'reports/exports') -Recurse -File).Count;$script:IdentityCalls.Clear()
        $r=Invoke-WinSecCoordinatedScan $c -DeviceId $target.DeviceId -ScanId cancelled-running -ScopeType SECTION -ScopeKey IdentityAccess -ConfirmAction {$true} -CancellationAction {$IdentityCalls.Count -ge 1}
        Assert-IdentityIntegration ($null -eq $r -and $c.Sessions.Count -eq $before -and @(Get-ChildItem (Join-Path $sandbox 'reports/exports') -Recurse -File).Count -eq $files)
    }
    Test-IdentityIntegration 'Confirmed SECTION uses one Windows context and writes three distinct technical snapshots' {
        $r=Invoke-WinSecCoordinatedScan $c -DeviceId $target.DeviceId -ScanId identity-section -ScopeType SECTION -ScopeKey IdentityAccess -AssessmentProfile WSA-W11-23H2-PRO-DEF-BASE -ConfirmAction {$true}
        Assert-IdentityIntegration ($r.ExecutionStatus -ceq 'COMPLETED' -and $c.LastTechnicalReports.Files.Count -eq 3 -and ($c.LastTechnicalReports.Files.CheckId -join '|') -ceq 'WSA-IAM-001|WSA-IAM-002|WSA-IAM-003')
        foreach($id in @('WSA-IAM-001','WSA-IAM-002','WSA-IAM-003')){$report=Read-WinSecTechnicalReport $sandbox $target.DeviceId identity-section $id;Assert-IdentityIntegration ($report.ScopeKey -ceq 'IdentityAccess' -and $report.ScanId -ceq 'identity-section')}
    }
    foreach($review in @(@{Index=0;Id='WSA-IAM-001';Framework='nist-csf';Rows=1},@{Index=1;Id='WSA-IAM-002';Framework='cis-controls';Rows=1},@{Index=2;Id='WSA-IAM-003';Framework='mitre-attack';Rows=2})){
    Test-IdentityIntegration ('Restored F/P preserves its selected control, framework and saved readings: '+$review.Id) {
        $restored=New-WinSecScanCoordinator $sandbox;$restored.Registry=$c.Registry
        $state=New-WinSecNavigationState;$state.Screen='Section';$state.SelectedDeviceId=$target.DeviceId
        $sections=@(Get-WinSecMainMenuSections);for($i=0;$i -lt $sections.Count;$i++){if($sections[$i].Key -ceq 'IdentityAccess'){$state.SectionIndex=$i}}
        $state.ControlIndex=$review.Index
        $ctx=[pscustomobject]@{ProjectRoot=$sandbox;ScanCoordinator=$restored;Devices=@([pscustomobject]@{DeviceId=$target.DeviceId;Hostname='SYNTHETIC-IDENTITY';DisplayName='SYNTHETIC-IDENTITY'});
            PublicScans=@{};ActiveScanByDevice=@{};ActiveScanByScope=@{};LocalDeviceId=$target.DeviceId;FrameworkWorkflowEnabled=$true;LastExportMessage=''}
        $null=Restore-WinSecPublicHistory $ctx;$before=$IdentityCalls.Count
        function Show-WinSecExportFrameworkSelection {param($Selection,[switch]$ForFindings);[pscustomobject]@{Confirmed=$true;FrameworkId=$review.Framework}}
        Assert-IdentityIntegration (Invoke-WinSecCLIFrameworkFindings $state $ctx)
        $analysis=$ctx.FrameworkFindings.AnalysisId;$state.Screen='Findings';$state.FindingsScope='Control';$artifact=Export-WinSecCLIFrameworkFindings $state $ctx
        Assert-IdentityIntegration ($artifact.Path.EndsWith('.md') -and $ctx.FrameworkFindings.Rows.Count -eq $review.Rows -and $ctx.FrameworkFindings.AnalysisId -ceq $analysis -and
            $ctx.FrameworkFindings.FrameworkId -ceq $review.Framework -and $ctx.FrameworkFindings.Sources[0].CheckId -ceq $review.Id -and
            $ctx.FrameworkFindings.Sources[0].Origin -ceq 'RECORDS' -and $IdentityCalls.Count -eq $before)
    }
    }
    Test-IdentityIntegration 'Confirmed Delete Device recognizes IAM technical Markdown and Findings artifacts' {
        $devices=@((Import-WinSecDeviceInventory $sandbox).targets);$directory=Join-Path $sandbox ('reports/exports/'+(Get-WinSecEvidenceHash $target.DeviceId))
        $result=Remove-WinSecManagedDevice -ProjectRoot $sandbox -DeviceId $target.DeviceId -Coordinator $c -Devices $devices -ConfirmAction {$false};Assert-IdentityIntegration ($null -eq $result -and (Test-Path $directory))
        $result=Remove-WinSecManagedDevice -ProjectRoot $sandbox -DeviceId $target.DeviceId -Coordinator $c -Devices $devices -ConfirmAction {$true};Assert-IdentityIntegration ($result.Status -ceq 'REMOVED' -and -not (Test-Path $directory))
    }
}finally{
    $env:COMPUTERNAME=$oldHostname;Assert-IdentityIntegration ((Get-FileHash (Join-Path $sourceRoot 'config/checks.json')).Hash -ceq $checksHash)
    $absolute=[IO.Path]::GetFullPath($sandbox)
    if([IO.Path]::GetDirectoryName($absolute) -cne $tempParent -or [IO.Path]::GetFileName($absolute) -cnotmatch '\AWinSec-Identity-[a-f0-9]{32}\z'){throw 'Unsafe fixture cleanup.'}
    Remove-Item -LiteralPath $absolute -Recurse -Force
}
[Console]::WriteLine('IdentityAccess integration: '+$passed+' passed; '+$failed+' failed.');if($failed){throw 'IdentityAccess integration failed.'}
