# Real production registry, coordinator, three collectors, evaluation, public history and UI.
# Only Windows providers, storage, terminal and audit timestamps are synthetic.
# No execution-permission overrides, native Windows reads or application-data writes.
[CmdletBinding()]
param([string]$CasePattern='*')
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
foreach($file in @('src/Core/ScanCoordinator.ps1','src/CLI/Invoke-WinSecCLI.ps1',
    'src/UI/Core/NavigationController.ps1','src/UI/Core/LayoutManager.ps1','src/UI/Core/TerminalRenderer.ps1',
    'src/UI/Core/KeyboardController.ps1','src/UI/Core/ResizeHandler.ps1','src/UI/Components/Table.ps1',
    'src/UI/Components/Banner.ps1','src/UI/Components/KeyboardHelp.ps1','src/UI/Screens/MainMenu.ps1',
    'src/UI/Screens/Results.ps1','src/UI/Screens/Findings.ps1','src/UI/Screens/ScanConfirmation.ps1',
    'src/Services/ReportService.ps1','tests/Fixtures/WindowsUpdateMemory.ps1')){. (Join-Path $root $file)}
$script:production=Get-WinSecCheckRegistry $root
$script:auditReader=(Get-Command Invoke-WinSecAudit).ScriptBlock
$script:wuCimReader=(Get-Command Get-CimInstance).ScriptBlock
$script:aliases=New-Object 'System.Collections.Generic.List[string]'
# Alias boundaries survive the collector's function-only implementation scope.
foreach($name in @('Get-WinSecLocalHardwareDeviceId','Open-WinSecWindowsUpdatePolicyKey',
    'Open-WinSecWindowsUpdateVersionKey','Get-WinSecWindowsUpdateRebootRequired','Read-WinSecWindowsUpdateNamedPolicy')) {
    $fake='WinSecSystemTest_'+$name
    Set-Item -Path ('Function:'+ $fake) -Value (Get-Command $name).ScriptBlock
    Set-Alias -Name $name -Value $fake -Scope Script
    $script:aliases.Add($name)
}
function Assert-WinSecUpdateCoordinator {
    param([bool]$Value,[string]$Message='Windows Update coordinator integration assertion failed.')
    if(-not $Value){throw $Message}
}
function Assert-WinSecUpdateCoordinatorRejected {
    param([scriptblock]$Action)
    $caught=$false;try{$null=& $Action}catch{$caught=$true}
    Assert-WinSecUpdateCoordinator $caught
}
function Get-CimInstance {
    [CmdletBinding()]param($Namespace,$ClassName,$Property,$Filter,$OperationTimeoutSec)
    if($ClassName -ceq 'Win32_OperatingSystem' -and $Namespace -ceq 'root/cimv2') {
        $script:osReads++
        Assert-WinSecUpdateCoordinator ($OperationTimeoutSec -eq 10)
        if(($Property -join ',') -ceq 'SystemDrive'){return [pscustomobject]@{SystemDrive='D:'}}
        $system=Copy-WinSecResultData $script:WU.Systems[0]
        $system.Caption='Microsoft Windows 11 Pro'
        return $system
    }
    if($ClassName -ceq 'Win32_EncryptableVolume') {
        $script:volumeReads++
        Assert-WinSecUpdateCoordinator ($Namespace -ceq 'root/cimv2/Security/MicrosoftVolumeEncryption' -and
            $Filter -ceq "DriveLetter = 'D:'" -and $OperationTimeoutSec -eq 10)
        return [pscustomobject]@{DeviceID='\\?\Volume{12345678-1234-4567-89ab-123456789abc}\';DriveLetter='D:';VolumeType=[uint32]0}
    }
    # The fixture throws for every other namespace/class/filter/property set.
    & $script:wuCimReader @PSBoundParameters
}
function Invoke-CimMethod {
    [CmdletBinding()]param($InputObject,$MethodName,$OperationTimeoutSec)
    $script:volumeMethods++
    Assert-WinSecUpdateCoordinator ($InputObject.DriveLetter -ceq 'D:' -and $OperationTimeoutSec -eq 10)
    switch -CaseSensitive ($MethodName) {
        GetProtectionStatus {[pscustomobject]@{ReturnValue=0;ProtectionStatus=0}}
        GetConversionStatus {[pscustomobject]@{ReturnValue=0;ConversionStatus=0;EncryptionPercentage=0}}
        GetEncryptionMethod {[pscustomobject]@{ReturnValue=0;EncryptionMethod=0}}
        GetLockStatus {[pscustomobject]@{ReturnValue=0;LockStatus=0}}
        default {throw 'Forbidden BitLocker method in synthetic System Security test.'}
    }
}
function Get-MpComputerStatus {
    [CmdletBinding()]param()
    $script:defenderReads++
    [pscustomobject]@{AMRunningMode='Normal';AMServiceEnabled=$true;AntivirusEnabled=$true;
        RealTimeProtectionEnabled=$true;BehaviorMonitorEnabled=$true;IsTamperProtected=$true}
}
function Get-MpPreference {
    [CmdletBinding()]param()
    [pscustomobject]@{PUAProtection=1;MAPSReporting=2;AttackSurfaceReductionRules_Ids=@('56a863a9-875e-4185-98a7-b882c64b5ce5');
        AttackSurfaceReductionRules_Actions=@(1);ExclusionPath=@('C:\PRIVATE-SYSTEM-SECURITY')}
}
function Invoke-WinSecAudit {
    param($DeviceId,$ScanId,$CheckIds,$Registry,[switch]$SkipScoring,$ProgressCallback,$CancellationAction)
    $audit=& $script:auditReader @PSBoundParameters
    # Reproducible test clock, inside the installed reference window. Preserve
    # original collector values/identities and the real execution/permission path.
    $script:sequence++
    $start=([datetime]'2026-10-24T12:00:00Z').ToUniversalTime().AddMinutes(2*$script:sequence)
    $audit.StartedAtUTC=$start.ToString('o');$audit.CompletedAtUTC=$start.AddMinutes(1).ToString('o')
    foreach($control in $audit.ControlResults) {
        $control.TimestampUTC=$start.AddSeconds(30).ToString('o')
        if($null -ne $control.Evidence -and $null -ne $control.Evidence.PSObject.Properties['CollectedAtUTC']) {
            $control.Evidence.CollectedAtUTC=$control.TimestampUTC
        }
    }
    return $audit
}
function Import-WinSecDeviceInventory {
    param($ProjectRoot)
    [pscustomobject]@{schemaVersion='1.2.0';targets=@(New-WinSecLocalTarget);removedDeviceHashes=@()}
}
function Open-WinSecDeviceInventoryStore {
    param($ProjectRoot)
    $lease=[pscustomobject]@{};$lease|Add-Member ScriptMethod Dispose {}
    [pscustomobject]@{Lock=$lease}
}
function Save-WinSecPublicHistory {
    param($ProjectRoot,$Session)
    if($script:store.ContainsKey($Session.ScanId)){throw 'Immutable history conflict.'}
    $script:store[$Session.ScanId]=Get-WinSecPublicHistoryJson (New-WinSecPublicHistoryRecord $Session)
}
function Read-WinSecPublicHistoryArtifacts {
    param($ProjectRoot,$Devices,[ref]$TotalBytes)
    foreach($json in $script:store.Values){ConvertFrom-WinSecStoredJson $json}
}
function Save-WinSecCoordinatedEvidence {throw 'Unexpected evidence write.'}
function Write-WinSecPublicHistoryArtifact {throw 'Unexpected native history write.'}
function Write-WinSecMarkdownArtifact {throw 'Unexpected report write.'}
function Get-WinSecTerminalSize {$script:terminal}
function Clear-WinSecScreen {$script:lines.Clear();$null=$script:fragment.Clear()}
function Write-Host {
    param([object[]]$Object,[switch]$NoNewline,$ForegroundColor,$BackgroundColor,[string]$Separator=' ')
    $null=$script:fragment.Append(($Object -join $Separator))
    if(-not $NoNewline){$script:lines.Add($script:fragment.ToString());$null=$script:fragment.Clear()}
}
function Read-WinSecResizeAwareKey {
    param($ResizeState,$RenderAction)
    if(-not $script:keys.Count){throw 'Synthetic keyboard queue exhausted.'}
    return $script:keys.Dequeue()
}
function New-WinSecUpdateCoordinatorContext {
    $device=New-WinSecLocalTarget;$coordinator=New-WinSecScanCoordinator -ProjectRoot $root
    $coordinator.Registry=[pscustomobject]@{schemaVersion='1.0.0';targets=@($device)}
    $coordinator.AssessmentEnabled=$true;$coordinator.PublicHistoryEnabled=$true
    [pscustomobject]@{ProjectRoot=$root;Version='0.9.0';Devices=@($device);ScanCoordinator=$coordinator;
        PublicScans=@{};ActiveScanByDevice=@{};ActiveScanByScope=@{};LastScanMessage=''}
}
function Invoke-WinSecUpdateCoordinatorFixture {
    param($Context,[string]$Id='update-first',[string]$ScopeType='CONTROL',[string]$ScopeKey='WSA-SYS-003',
        [string]$Profile='WSA-W11-25H2-PRO-DEF-BASE',[scriptblock]$ConfirmAction={$true},[scriptblock]$CancellationAction)
    $argsForScan=@{Coordinator=$Context.ScanCoordinator;DeviceId=$Context.Devices[0].DeviceId;ScanId=$Id;
        ScopeType=$ScopeType;ScopeKey=$ScopeKey;AssessmentProfile=$Profile;ConfirmAction=$ConfirmAction}
    if($null -ne $CancellationAction){$argsForScan.CancellationAction=$CancellationAction}
    Invoke-WinSecCoordinatedScan @argsForScan -ProgressCallback {param($event);$script:progress.Add($event)}
}
$script:passed=0;$script:failed=0
function Test-WinSecUpdateCoordinator {
    param([string]$Name,[scriptblock]$Action)
    if($Name -notlike $CasePattern){return}
    Reset-WinSecWindowsUpdateFixture
    $script:WU.Systems[0].Version='10.0.26200';$script:WU.Systems[0].BuildNumber='26200'
    $script:WU.VersionValues.CurrentBuildNumber='26200'
    $script:sequence=0;$script:defenderReads=0;$script:volumeReads=0;$script:volumeMethods=0;$script:osReads=0;$script:store=@{}
    $script:progress=New-Object 'System.Collections.Generic.List[object]'
    $script:keys=New-Object 'System.Collections.Generic.Queue[object]'
    $script:lines=New-Object 'System.Collections.Generic.List[string]';$script:fragment=New-Object Text.StringBuilder
    $script:terminal=[pscustomobject]@{Width=120;ContentWidth=119;Height=55}
    try{$null=& $Action;$script:passed++;[Console]::WriteLine('[PASS] '+$Name)}
    catch{$script:failed++;[Console]::WriteLine('[FAIL] '+$Name+' : '+$_.Exception.Message);[Console]::WriteLine($_.ScriptStackTrace)}
}
try {
    Test-WinSecUpdateCoordinator 'Production enables exactly the three individually validated System Security controls' {
        $ready=@($script:production.Checks|Where-Object ExecutionReady)
        Assert-WinSecUpdateCoordinator ((($ready.CheckId|Sort-Object) -join '|') -ceq 'WSA-SYS-001|WSA-SYS-002|WSA-SYS-003' -and
            @($ready|Where-Object {$_.ImplementationStatus -cne 'VALIDATED' -or -not $_.ExecutionEnabled}).Count -eq 0)
        $ctx=New-WinSecUpdateCoordinatorContext
        Assert-WinSecUpdateCoordinator ($script:osReads -eq 0 -and $script:defenderReads -eq 0 -and $script:WU.NamedPolicyReads -eq 0)
    }
    foreach($scope in @(@{T='DEVICE';K='ALL';Ids='WSA-SYS-001|WSA-SYS-002|WSA-SYS-003'},
        @{T='SECTION';K='SystemSecurity';Ids='WSA-SYS-001|WSA-SYS-002|WSA-SYS-003'},
        @{T='CONTROL';K='WSA-SYS-003';Ids='WSA-SYS-003'})) {
        Test-WinSecUpdateCoordinator ('Actual scope preview cancels before all collection and publication: '+$scope.T) {
            $ctx=New-WinSecUpdateCoordinatorContext
            $r=Invoke-WinSecUpdateCoordinatorFixture $ctx -ScopeType $scope.T -ScopeKey $scope.K -ConfirmAction {
                param($request)
                Assert-WinSecUpdateCoordinator ($request.DeviceId -ceq $script:WU.DeviceId -and $request.ReadOnly -and
                    (($request.Checks.CheckId|Sort-Object) -join '|') -ceq $scope.Ids -and $request.ScopeType -ceq $scope.T)
                $false
            }
            Assert-WinSecUpdateCoordinator ($null -eq $r -and $script:store.Count -eq 0 -and $ctx.ScanCoordinator.Sessions.Count -eq 0 -and
                $script:osReads -eq 0 -and $script:defenderReads -eq 0 -and $script:volumeReads -eq 0 -and $script:WU.NamedPolicyReads -eq 0)
        }
    }
    Test-WinSecUpdateCoordinator 'Legacy unscoped presentation cannot supply a scored section view' {
        function Get-WinSecCLIActiveAssessment {
            param($State,$Context)
            [pscustomobject]@{ScanId='legacy';Warning='';SectionResults=@();ConfigurationAssessment=$null}
        }
        $ctx=New-WinSecUpdateCoordinatorContext;$state=New-WinSecNavigationState;$state.SelectedDeviceId=$ctx.Devices[0].DeviceId
        Assert-WinSecUpdateCoordinator (@(Get-WinSecCLISectionViews $state $ctx).Count -eq 0 -and $script:osReads -eq 0)
    }
    Test-WinSecUpdateCoordinator 'Confirmed control scan executes only Windows Update and enables Rescan for its exact scope' {
        $ctx=New-WinSecUpdateCoordinatorContext;$id=$ctx.Devices[0].DeviceId
        Assert-WinSecUpdateCoordinator ((Get-WinSecScanAction $ctx.ScanCoordinator $id CONTROL WSA-SYS-003) -ceq 'Scan')
        $p=Invoke-WinSecUpdateCoordinatorFixture $ctx
        Assert-WinSecUpdateCoordinator ($p.ConfigurationAssessment.Controls[0].Value -eq 100 -and $script:store.Count -eq 1 -and
            $script:defenderReads -eq 0 -and $script:volumeReads -eq 0 -and $script:WU.NamedPolicyReads -eq 5 -and
            (Get-WinSecScanAction $ctx.ScanCoordinator $id CONTROL WSA-SYS-003) -ceq 'Rescan' -and
            (Get-WinSecScanAction $ctx.ScanCoordinator $id SECTION SystemSecurity) -ceq 'Scan' -and
            (Get-WinSecScanAction $ctx.ScanCoordinator $id CONTROL WSA-SYS-002) -ceq 'Scan')
        Assert-WinSecUpdateCoordinator (@($script:progress|Where-Object Phase -CEQ COMPLETED).Count -eq 1)
    }
    Test-WinSecUpdateCoordinator 'A section evaluates three real collectors and averages their individual configuration scores' {
        $ctx=New-WinSecUpdateCoordinatorContext
        $p=Invoke-WinSecUpdateCoordinatorFixture $ctx -ScopeType SECTION -ScopeKey SystemSecurity
        Assert-WinSecUpdateCoordinator (($p.ConfigurationAssessment.Controls.Value -join '|') -ceq '100|0|100' -and
            $p.ConfigurationAssessment.Sections[0].Value -eq 66.67 -and $p.ConfigurationAssessment.Sections[0].Coverage -eq 100 -and
            $script:defenderReads -eq 1 -and $script:volumeReads -eq 1 -and $script:volumeMethods -eq 4 -and
            $script:WU.NamedPolicyReads -eq 5 -and $null -eq $p.OverallScore)
        $rows=@(Get-WinSecMainMenuSections -SectionResults $p.SectionResults -ConfigurationAssessment $p.ConfigurationAssessment)
        Assert-WinSecUpdateCoordinator (@($rows|Where-Object {$_.Key -ceq 'SystemSecurity' -and $_.Score -ceq '66.67/100' -and $_.Status -ceq 'COMPLETE'}).Count -eq 1)
    }
    Test-WinSecUpdateCoordinator 'A full device scan executes only the three ready controls and preserves independent section rows' {
        $ctx=New-WinSecUpdateCoordinatorContext
        $p=Invoke-WinSecUpdateCoordinatorFixture $ctx -ScopeType DEVICE -ScopeKey ALL
        $system=@($p.ConfigurationAssessment.Sections|Where-Object SectionKey -CEQ SystemSecurity)
        Assert-WinSecUpdateCoordinator ($p.ControlResults.Count -eq 14 -and
            @($p.ControlResults|Where-Object Status -CNE NOT_SELECTED).Count -eq 3 -and
            $p.ConfigurationAssessment.Controls.Count -eq 14) ('Unexpected device manifest counts: public='+$p.ControlResults.Count+'; controls='+$p.ConfigurationAssessment.Controls.Count)
        Assert-WinSecUpdateCoordinator ($system.Count -eq 1 -and $system[0].Value -eq 66.67 -and
            @($p.ConfigurationAssessment.Sections|Where-Object {$_.SectionKey -cne 'SystemSecurity' -and $null -ne $_.Value}).Count -eq 0 -and
            $null -eq $p.OverallScore -and $script:store.Count -eq 1)
        $restart=New-WinSecUpdateCoordinatorContext;Restore-WinSecPublicHistory $restart
        $state=New-WinSecNavigationState;$state.Screen='MainMenu';$state.SelectedDeviceId=$p.DeviceId
        $views=@(Get-WinSecCLISectionViews $state $restart)
        Assert-WinSecUpdateCoordinator ($views.Count -eq 5 -and @($views|Where-Object {$_.ScopeType -cne 'DEVICE' -or $_.ScopeKey -cne 'ALL'}).Count -eq 0)
        foreach($index in @(0,1)) {
            $state.SectionIndex=$index;Show-WinSecCLICurrentScreen $state $restart
            Assert-WinSecUpdateCoordinator (($script:lines -join '|').Contains('66.67/100'))
        }
    }
    Test-WinSecUpdateCoordinator 'An unresolved applicable update criterion keeps the whole section unscored' {
        $script:WU.NamedPolicyFailures=@('AllowAutoUpdate')
        $p=Invoke-WinSecUpdateCoordinatorFixture (New-WinSecUpdateCoordinatorContext) -ScopeType SECTION -ScopeKey SystemSecurity
        Assert-WinSecUpdateCoordinator ($p.ConfigurationAssessment.Controls[0].Value -eq 100 -and $p.ConfigurationAssessment.Controls[1].Value -eq 0 -and
            $null -eq $p.ConfigurationAssessment.Controls[2].Value -and $null -eq $p.ConfigurationAssessment.Sections[0].Value -and
            @($p.Findings|Where-Object {$_.CheckId -ceq 'WSA-SYS-003' -and $_.Kind -ceq 'CONFIGURATION_DEVIATION'}).Count -eq 0)
    }
    Test-WinSecUpdateCoordinator 'Verified support failure excludes patch weight inside the real section mean' {
        $script:WU.Systems[0].Version='10.0.22631';$script:WU.Systems[0].BuildNumber='22631';$script:WU.VersionValues.CurrentBuildNumber='22631'
        $p=Invoke-WinSecUpdateCoordinatorFixture (New-WinSecUpdateCoordinatorContext) -ScopeType SECTION -ScopeKey SystemSecurity -Profile WSA-W11-23H2-PRO-DEF-BASE
        Assert-WinSecUpdateCoordinator ($p.ConfigurationAssessment.Controls[2].Value -eq 23.08 -and
            $p.ConfigurationAssessment.Controls[2].Criteria[1].Status -ceq 'NOT_APPLICABLE' -and
            $p.ConfigurationAssessment.Sections[0].Value -eq 41.03 -and $script:WU.NamedPolicyReads -eq 4)
    }
    Test-WinSecUpdateCoordinator 'Partial rescan updates only its control; original section history and score stay immutable' {
        $ctx=New-WinSecUpdateCoordinatorContext
        $section=Invoke-WinSecUpdateCoordinatorFixture $ctx -Id a-section-original -ScopeType SECTION -ScopeKey SystemSecurity
        $before=$script:store['a-section-original'];$script:WU.Services[0].StartMode='Disabled'
        $control=Invoke-WinSecUpdateCoordinatorFixture $ctx -Id z-update-later
        Assert-WinSecUpdateCoordinator ($control.ConfigurationAssessment.Controls[0].Value -eq 85 -and $before -ceq $script:store['a-section-original'])
        $restart=New-WinSecUpdateCoordinatorContext;Restore-WinSecPublicHistory $restart
        $state=New-WinSecNavigationState;$state.Screen='Section';$state.SelectedDeviceId=$section.DeviceId
        $views=@(Get-WinSecCLIControlViews $state $restart)
        $rows=@(Get-WinSecResultsControlRows SystemSecurity $state -ControlViews $views)
        Assert-WinSecUpdateCoordinator ($rows[2].Score -ceq '85/100' -and $rows[0].Score -ceq '100/100' -and $rows[1].Score -ceq '0/100')
        $state.Screen='MainMenu';$sectionViews=@(Get-WinSecCLISectionViews $state $restart)
        Assert-WinSecUpdateCoordinator ($sectionViews.Count -eq 1 -and $sectionViews[0].ScanId -ceq $section.ScanId -and
            $sectionViews[0].ConfigurationAssessment.Sections[0].Value -eq 66.67)
        foreach($fault in @('Device','Scan','ControlScope','ConfigurationScope','RecordDevice','RecordScanType','Score','Duplicate')) {
            $bad=Copy-WinSecResultData $sectionViews[0]
            if($fault -cin @('RecordDevice','RecordScanType')) {
                $bad.SectionResults=@([pscustomobject]@{DeviceId=$bad.DeviceId;ScanId=$bad.ScanId;SectionKey=$bad.SectionKey;Status='UNKNOWN'})
                $null=Get-WinSecMainMenuSections -SectionViews @($bad) -DeviceId $section.DeviceId
            }
            switch($fault) {
                Device {$bad.DeviceId='local:OTHER'};Scan {$bad.ScanId='foreign-scan'}
                ControlScope {$bad.ScopeType='CONTROL';$bad.ScopeKey='WSA-SYS-003'}
                ConfigurationScope {$bad.ConfigurationAssessment.ScopeKey='NetworkSecurity'}
                RecordDevice {$bad.SectionResults[0].DeviceId='local:OTHER'}
                RecordScanType {$bad.SectionResults[0].ScanId=@($bad.ScanId)}
                Score {$bad.ConfigurationAssessment.Sections[0].Value=100}
            }
            $badViews=if($fault -ceq 'Duplicate'){@($bad,$bad)}else{@($bad)}
            Assert-WinSecUpdateCoordinatorRejected {Get-WinSecMainMenuSections -SectionViews $badViews -DeviceId $section.DeviceId}
        }
        foreach($index in @(0,1)) {
            $state.SectionIndex=$index;Show-WinSecCLICurrentScreen $state $restart
            Assert-WinSecUpdateCoordinator (($script:lines -join '|').Contains('61.67/100') -and
                ($script:lines -join '|').Contains('LATEST_CONTROLS'))
        }
        $reads=$script:osReads;$script:terminal=[pscustomobject]@{Width=40;ContentWidth=39;Height=20}
        Show-WinSecCLICurrentScreen $state $restart
        Assert-WinSecUpdateCoordinator ($script:osReads -eq $reads -and @($script:lines|Where-Object {$_.Length -gt 40}).Count -eq 0)
        $script:terminal=[pscustomobject]@{Width=120;ContentWidth=119;Height=55}
        $state.SectionIndex=0
        $state.Screen='Findings';$state.FindingsScope='Control';$state.ControlIndex=2
        $selection=Get-WinSecCLIFindingsExportSelection $state $restart
        foreach($framework in @('cis-controls','nist-csf','mitre-attack')) {
            $report=New-WinSecFindingsMarkdown $selection -FrameworkId $framework
            Assert-WinSecUpdateCoordinator ($report.Markdown.Contains('85/100') -and $report.Markdown -notmatch 'PRIVATE-|"Evidence"|NamedPolicy|RecoveryPassword')
        }
        $reads=$script:osReads;Show-WinSecCLICurrentScreen $state $restart
        $state=Invoke-WinSecNavigationAction $state Back
        Assert-WinSecUpdateCoordinator ($state.Screen -cne 'Findings' -and $script:osReads -eq $reads)
    }
    Test-WinSecUpdateCoordinator 'Three separate control scans produce a current summary without inventing section history' {
        $ctx=New-WinSecUpdateCoordinatorContext
        foreach($id in @('WSA-SYS-001','WSA-SYS-002','WSA-SYS-003')) {
            $null=Invoke-WinSecUpdateCoordinatorFixture $ctx -Id ('individual-'+$id) -ScopeKey $id
        }
        $before=ConvertTo-Json $script:store -Depth 8 -Compress
        $restart=New-WinSecUpdateCoordinatorContext;Restore-WinSecPublicHistory $restart
        $state=New-WinSecNavigationState;$state.SelectedDeviceId=$ctx.Devices[0].DeviceId;$state.Screen='Section'
        $reads=$script:osReads
        $views=@(Get-WinSecCLIControlViews $state $restart)
        $s=Get-WinSecLatestSystemSecuritySummary $state $views
        Assert-WinSecUpdateCoordinator ($s.Value -eq 66.67 -and $s.Status -ceq 'COMPLETE' -and
            $s.Source -ceq 'LATEST_CONTROLS' -and $s.ScanCount -eq 3 -and $script:store.Count -eq 3)
        Show-WinSecCLICurrentScreen $state $restart
        Assert-WinSecUpdateCoordinator (($script:lines -join '|').Contains('66.67/100') -and
            ($script:lines -join '|').Contains('latest controls (3 scans)'))
        $state.Screen='MainMenu';Show-WinSecCLICurrentScreen $state $restart
        Assert-WinSecUpdateCoordinator (($script:lines -join '|').Contains('66.67/100') -and
            ($script:lines -join '|').Contains('LATEST_CONTROLS'))
        Assert-WinSecUpdateCoordinator ((Get-WinSecScanAction $restart.ScanCoordinator $state.SelectedDeviceId SECTION SystemSecurity) -ceq 'Scan' -and
            $reads -eq $script:osReads -and $before -ceq (ConvertTo-Json $script:store -Depth 8 -Compress))
        $state.Screen='Findings';$state.FindingsScope='Section'
        Assert-WinSecUpdateCoordinator (-not (Test-WinSecCLIFindingsExportEligibility $state $restart))
        $state.FindingsScope='Control';$state.ControlIndex=2
        $selection=Get-WinSecCLIFindingsExportSelection $state $restart
        Assert-WinSecUpdateCoordinator ($selection.ScanId -ceq 'individual-WSA-SYS-003')
        $state.Screen='MainMenu';$script:terminal=[pscustomobject]@{Width=40;ContentWidth=39;Height=20}
        Show-WinSecCLICurrentScreen $state $restart
        Assert-WinSecUpdateCoordinator (@($script:lines|Where-Object {$_.Length -gt 40}).Count -eq 0 -and $reads -eq $script:osReads)
    }
    foreach($fullScope in @(@{T='SECTION';K='SystemSecurity'},@{T='DEVICE';K='ALL'})) {
        Test-WinSecUpdateCoordinator ('A later '+$fullScope.T+' scan refreshes all control views and Findings after independent scans') {
            $ctx=New-WinSecUpdateCoordinatorContext
            $script:WU.Services[0].StartMode='Disabled'
            foreach($id in @('WSA-SYS-001','WSA-SYS-002','WSA-SYS-003')) {
                $null=Invoke-WinSecUpdateCoordinatorFixture $ctx -Id ('older-'+$id) -ScopeKey $id
            }
            $old=$script:store['older-WSA-SYS-003'];$script:WU.Services[0].StartMode='Manual'
            $all=Invoke-WinSecUpdateCoordinatorFixture $ctx -Id newer-complete -ScopeType $fullScope.T -ScopeKey $fullScope.K
            $restart=New-WinSecUpdateCoordinatorContext;Restore-WinSecPublicHistory $restart
            $state=New-WinSecNavigationState;$state.SelectedDeviceId=$ctx.Devices[0].DeviceId;$state.Screen='Section'
            $views=@(Get-WinSecCLIControlViews $state $restart)
            $summary=Get-WinSecLatestSystemSecuritySummary $state $views
            Assert-WinSecUpdateCoordinator ($views.Count -eq 3 -and @($views|Where-Object ScanId -CNE newer-complete).Count -eq 0 -and
                $summary.Value -eq 66.67 -and $summary.Source -ceq 'SESSION' -and
                $old -ceq $script:store['older-WSA-SYS-003'] -and
                @($all.ConfigurationAssessment.Controls|Where-Object CheckId -CEQ WSA-SYS-003)[0].Value -eq 100)
            $state.Screen='Findings';$state.FindingsScope='Control';$state.ControlIndex=2
            $selection=Get-WinSecCLIFindingsExportSelection $state $restart
            Assert-WinSecUpdateCoordinator ($selection.ScanId -ceq 'newer-complete' -and
                @($selection.ConfigurationAssessment.Controls|Where-Object CheckId -CEQ WSA-SYS-003)[0].Criteria[0].Profile -ceq 'WSA-W11-25H2-PRO-DEF-BASE')
        }
    }
    Test-WinSecUpdateCoordinator 'Cancellation during section collection cannot publish partial history or replace the prior result' {
        $ctx=New-WinSecUpdateCoordinatorContext
        $first=Invoke-WinSecUpdateCoordinatorFixture $ctx -ScopeType SECTION -ScopeKey SystemSecurity -Id first-section
        $before=$script:store['first-section'];$count=$ctx.ScanCoordinator.Sessions.Count;$reads=$script:defenderReads
        $cancelled=Invoke-WinSecUpdateCoordinatorFixture $ctx -ScopeType SECTION -ScopeKey SystemSecurity -Id cancelled-section -CancellationAction {
            return ($script:defenderReads -gt $reads)
        }
        Assert-WinSecUpdateCoordinator ($null -eq $cancelled -and $script:store.Count -eq 1 -and
            $ctx.ScanCoordinator.Sessions.Count -eq $count -and $before -ceq $script:store['first-section'])
    }
    foreach($spec in @(@{W=120;H=55;Key=27},@{W=120;H=55;Key=39},@{W=40;H=12;Key=27})) {
        Test-WinSecUpdateCoordinator ('Real confirmation cancels safely with keyboard and terminal size '+$spec.W+'/'+$spec.Key) {
            $ctx=New-WinSecUpdateCoordinatorContext
            $script:terminal=[pscustomobject]@{Width=$spec.W;ContentWidth=($spec.W-1);Height=$spec.H}
            $script:keys.Enqueue([pscustomobject]@{VirtualKeyCode=$spec.Key;Character='';KeyDown=$true;ControlKeyState=0})
            if($spec.Key -eq 39){$script:keys.Enqueue([pscustomobject]@{VirtualKeyCode=13;Character='';KeyDown=$true;ControlKeyState=0})}
            $r=Invoke-WinSecUpdateCoordinatorFixture $ctx -ConfirmAction {param($request);Show-WinSecScanConfirmation -Request $request}
            Assert-WinSecUpdateCoordinator ($null -eq $r -and $script:store.Count -eq 0 -and $script:osReads -eq 0)
        }
    }
} finally {
    foreach($name in $script:aliases){Remove-Item -LiteralPath ('Alias:'+ $name) -Force}
}
[Console]::WriteLine(('Windows Update coordinator integration: {0} passed, {1} failed.' -f $script:passed,$script:failed))
if($script:failed){throw 'Windows Update coordinator integration failed.'}
