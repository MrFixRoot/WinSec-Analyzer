# Real production registry, coordinator, four collectors, evaluation, public history and UI.
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
    'src/Services/ReportService.ps1','src/CLI/FrameworkWorkflow.ps1','src/UI/Screens/FrameworkFindings.ps1',
    'src/UI/Screens/ExportFrameworkSelection.ps1','tests/Fixtures/WindowsUpdateMemory.ps1',
    'tests/Fixtures/FirewallMemory.ps1')){. (Join-Path $root $file)}
Set-Alias Invoke-WinSecFirewallQuery Invoke-WinSecFirewallFixtureQuery -Scope Script
$script:production=Get-WinSecCheckRegistry $root
$script:auditReader=(Get-Command Invoke-WinSecAudit).ScriptBlock
$script:wuCimReader=(Get-Command Get-CimInstance).ScriptBlock
$script:technicalWriter=(Get-Command Write-WinSecTechnicalArtifact).ScriptBlock
$script:reportInstallation=(Get-Command Get-WinSecReportInstallation).ScriptBlock
function Get-WinSecReportInstallation {
    param($ProjectRoot)
    if($script:technicalRoot -and $ProjectRoot -ceq $script:technicalRoot){return $ProjectRoot}
    & $script:reportInstallation @PSBoundParameters
}
function Write-WinSecTechnicalArtifact {
    param($ProjectRoot,$Report)
    if(-not $script:technicalRoot){throw 'Unexpected technical report write.'}
    if($Report.CheckId -ceq $script:technicalFailure){throw 'Synthetic technical disk failure.'}
    & $script:technicalWriter -ProjectRoot $script:technicalRoot -Report $Report
}
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
    if($ClassName -ceq 'Win32_OperatingSystem' -and -not $Namespace) {
        Assert-WinSecUpdateCoordinator ($OperationTimeoutSec -eq 5 -and
            ($Property -join ',') -ceq 'Caption,Version,BuildNumber,OperatingSystemSKU,ProductType')
        $script:FirewallBuild=[int]$script:WU.Systems[0].BuildNumber
        return Get-WinSecFirewallFixtureCim @PSBoundParameters
    }
    if($ClassName -ceq 'Win32_Service' -and $Filter -cin @("Name = 'MpsSvc'","Name = 'BFE'")) {
        Assert-WinSecUpdateCoordinator ($OperationTimeoutSec -eq 5 -and ($Property -join ',') -ceq 'Name,State,StartMode')
        return Get-WinSecFirewallFixtureCim @PSBoundParameters
    }
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
    # Explicit legacy fixture preserves regression coverage of immutable scored
    # sessions. New production-workflow cases below opt into the replacement flow.
    $coordinator.FrameworkWorkflowEnabled=$false
    [pscustomobject]@{ProjectRoot=$root;Version='0.9.0';Devices=@($device);ScanCoordinator=$coordinator;
        PublicScans=@{};ActiveScanByDevice=@{};ActiveScanByScope=@{};LastScanMessage=''}
}
function Invoke-WinSecUpdateCoordinatorFixture {
    param($Context,[string]$Id='update-first',[string]$ScopeType='CONTROL',[string]$ScopeKey='WSA-SYS-003',
        [string]$Profile='WSA-W11-25H2-PRO-DEF-BASE',[scriptblock]$ConfirmAction={$true},[scriptblock]$CancellationAction)
    $argsForScan=@{Coordinator=$Context.ScanCoordinator;DeviceId=$Context.Devices[0].DeviceId;ScanId=$Id;
        ScopeType=$ScopeType;ScopeKey=$ScopeKey;AssessmentProfile=$Profile;ConfirmAction=$ConfirmAction}
    if($null -ne $CancellationAction){$argsForScan.CancellationAction=$CancellationAction}
    $p=Invoke-WinSecCoordinatedScan @argsForScan -ProgressCallback {param($event);$script:progress.Add($event)}
    if($null -ne $p -and (Get-WinSecCLIValue $Context FrameworkWorkflowEnabled) -ceq $true) {
        $key='{0}:{1}{2}:{3}' -f $p.DeviceId.Length,$p.DeviceId,$p.ScanId.Length,$p.ScanId
        $Context.PublicScans[$key]=$p
        if($p.ScopeType -ceq 'DEVICE'){$Context.ActiveScanByDevice[$p.DeviceId]=$p.ScanId}
        else{$Context.ActiveScanByScope[(Get-WinSecCLIScopeKey $p.DeviceId $p.ScopeType $p.ScopeKey)]=$p.ScanId}
    }
    return $p
}
$script:passed=0;$script:failed=0
function Test-WinSecUpdateCoordinator {
    param([string]$Name,[scriptblock]$Action)
    if($Name -notlike $CasePattern){return}
    Reset-WinSecWindowsUpdateFixture
    Initialize-WinSecFirewallFixture
    $script:WU.Systems[0].Version='10.0.26200';$script:WU.Systems[0].BuildNumber='26200'
    $script:WU.VersionValues.CurrentBuildNumber='26200'
    $script:sequence=0;$script:defenderReads=0;$script:volumeReads=0;$script:volumeMethods=0;$script:osReads=0;$script:store=@{}
    $script:technicalRoot=$null;$script:technicalFailure=''
    $script:progress=New-Object 'System.Collections.Generic.List[object]'
    $script:keys=New-Object 'System.Collections.Generic.Queue[object]'
    $script:lines=New-Object 'System.Collections.Generic.List[string]';$script:fragment=New-Object Text.StringBuilder
    $script:terminal=[pscustomobject]@{Width=120;ContentWidth=119;Height=55}
    try{$null=& $Action;$script:passed++;[Console]::WriteLine('[PASS] '+$Name)}
    catch{$script:failed++;[Console]::WriteLine('[FAIL] '+$Name+' : '+$_.Exception.Message);[Console]::WriteLine($_.ScriptStackTrace)}
}
function Test-WinSecTechnicalCoordinator {
    param([string]$Name,[scriptblock]$TechnicalCaseBody)
    Test-WinSecUpdateCoordinator ('Technical TXT: '+$Name) {
        $script:technicalRoot=Join-Path ([IO.Path]::GetTempPath()) ('WinSec-TC-'+[guid]::NewGuid().ToString('N'))
        $null=[IO.Directory]::CreateDirectory($script:technicalRoot)
        try {& $TechnicalCaseBody} finally {
            $absolute=[IO.Path]::GetFullPath($script:technicalRoot)
            $parent=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\','/')
            if(-not [string]::Equals([IO.Path]::GetDirectoryName($absolute),$parent,[StringComparison]::OrdinalIgnoreCase) -or
                [IO.Path]::GetFileName($absolute) -cnotmatch '\AWinSec-TC-[a-f0-9]{32}\z'){throw 'Unsafe technical coordinator cleanup.'}
            Remove-Item -LiteralPath $absolute -Recurse -Force
        }
    }
}
try {
    Test-WinSecTechnicalCoordinator 'section and rescan write three separate files with original identities; control writes one' {
        $ctx=New-WinSecUpdateCoordinatorContext;$ctx.ScanCoordinator.TechnicalReportsEnabled=$true
        $first=Invoke-WinSecUpdateCoordinatorFixture $ctx -ScopeType SECTION -ScopeKey SystemSecurity -Id technical-section -ConfirmAction {
            param($request)
            Assert-WinSecUpdateCoordinator ($request.TechnicalReports.Count -eq 3 -and $request.TechnicalReports.Mode -ceq 'PER_EXECUTED_CONTROL')
            $script:keys.Enqueue([pscustomobject]@{VirtualKeyCode=13;Character='';KeyDown=$true;ControlKeyState=0})
            $accepted=Show-WinSecScanConfirmation $request
            Assert-WinSecUpdateCoordinator (($script:lines -join '|') -match 'Automatic technical Markdown: 3')
            return $accepted
        }
        $receipt=$ctx.ScanCoordinator.LastTechnicalReports
        Assert-WinSecUpdateCoordinator ($null -ne $first -and $receipt.Status -ceq 'SAVED' -and $receipt.Files.Count -eq 3)
        $originals=@{}
        foreach($file in $receipt.Files) {
            $text=[IO.File]::ReadAllText($file.Path);$originals[$file.Path]=$text
            $m=ConvertFrom-WinSecMarkdownArtifact $text $first.DeviceId
            Assert-WinSecUpdateCoordinator ($m.ScanId -ceq $first.ScanId -and $m.CheckId -ceq $file.CheckId -and
                $m.ScopeType -ceq 'SECTION' -and $m.ScopeKey -ceq 'SystemSecurity' -and
                $text -notmatch 'PRIVATE-SYSTEM-SECURITY|RecoveryPassword|ExclusionPath')
        }
        $before=$script:store['technical-section']
        $null=Invoke-WinSecUpdateCoordinatorFixture $ctx -ScopeType SECTION -ScopeKey SystemSecurity -Id technical-rescan
        Assert-WinSecUpdateCoordinator ($ctx.ScanCoordinator.LastTechnicalReports.Files.Count -eq 3 -and $script:store['technical-section'] -ceq $before)
        foreach($path in $originals.Keys){Assert-WinSecUpdateCoordinator ([IO.File]::ReadAllText($path) -ceq $originals[$path])}
        $null=Invoke-WinSecUpdateCoordinatorFixture $ctx -ScopeKey WSA-SYS-002 -Id technical-control
        $receipt=$ctx.ScanCoordinator.LastTechnicalReports
        Assert-WinSecUpdateCoordinator ($receipt.Status -ceq 'SAVED' -and $receipt.Files.Count -eq 1 -and $receipt.Files[0].CheckId -ceq 'WSA-SYS-002' -and
            @(Get-ChildItem -LiteralPath $script:technicalRoot -Recurse -File).Count -eq 7)
        $m=ConvertFrom-WinSecMarkdownArtifact ([IO.File]::ReadAllText($receipt.Files[0].Path)) $first.DeviceId
        Assert-WinSecUpdateCoordinator ($m.ScopeType -ceq 'CONTROL' -and $m.ScopeKey -ceq 'WSA-SYS-002')
    }
    Test-WinSecTechnicalCoordinator 'device scan creates four artifacts; normal coordinators never request persistence' {
        $ctx=New-WinSecUpdateCoordinatorContext
        $null=Invoke-WinSecUpdateCoordinatorFixture $ctx -Id no-technical-output
        Assert-WinSecUpdateCoordinator ($null -eq $ctx.ScanCoordinator.LastTechnicalReports -and
            @(Get-ChildItem -LiteralPath $script:technicalRoot -Recurse -File).Count -eq 0)
        $ctx.ScanCoordinator.TechnicalReportsEnabled=$true
        $deviceScan=Invoke-WinSecUpdateCoordinatorFixture $ctx -Id technical-device -ScopeType DEVICE -ScopeKey ALL
        Assert-WinSecUpdateCoordinator ($deviceScan.ExecutionStatus -ceq 'COMPLETED' -and
            $ctx.ScanCoordinator.LastTechnicalReports.Status -ceq 'SAVED' -and $ctx.ScanCoordinator.LastTechnicalReports.Files.Count -eq 4 -and
            $script:FirewallCalls.Count -eq 25)
    }
    Test-WinSecTechnicalCoordinator 'cancellation before and during collection writes no files and preserves history' {
        $ctx=New-WinSecUpdateCoordinatorContext;$ctx.ScanCoordinator.TechnicalReportsEnabled=$true
        $null=Invoke-WinSecUpdateCoordinatorFixture $ctx -Id rejected-technical -ConfirmAction {$false}
        $null=Invoke-WinSecUpdateCoordinatorFixture $ctx -Id cancelled-technical -ScopeType SECTION -ScopeKey SystemSecurity -CancellationAction {$script:defenderReads -gt 0}
        Assert-WinSecUpdateCoordinator ($script:store.Count -eq 0 -and $ctx.ScanCoordinator.Sessions.Count -eq 0 -and
            @(Get-ChildItem -LiteralPath $script:technicalRoot -Recurse -File).Count -eq 0)
    }
    Test-WinSecTechnicalCoordinator 'a technical disk failure is visible without changing the completed public session' {
        $ctx=New-WinSecUpdateCoordinatorContext;$ctx.ScanCoordinator.TechnicalReportsEnabled=$true;$script:technicalFailure='WSA-SYS-002'
        $p=Invoke-WinSecUpdateCoordinatorFixture $ctx -Id technical-partial -ScopeType SECTION -ScopeKey SystemSecurity
        $receipt=$ctx.ScanCoordinator.LastTechnicalReports
        Assert-WinSecUpdateCoordinator ($null -ne $p -and $p.ExecutionStatus -ceq 'COMPLETED' -and
            $script:store.ContainsKey('technical-partial') -and $receipt.Status -ceq 'PARTIAL' -and $receipt.Files.Count -eq 2 -and
            ($receipt.FailedCheckIds -join '|') -ceq 'WSA-SYS-002' -and $script:store['technical-partial'] -notmatch 'TechnicalReports|TechnicalRows|DefenderPreferences')
    }
    Test-WinSecTechnicalCoordinator 'changing the confirmed output mode rejects publication' {
        $ctx=New-WinSecUpdateCoordinatorContext;$ctx.ScanCoordinator.TechnicalReportsEnabled=$true
        Assert-WinSecUpdateCoordinatorRejected {
            Invoke-WinSecUpdateCoordinatorFixture $ctx -Id technical-tamper -ConfirmAction {
                param($request);$ctx.ScanCoordinator.TechnicalReportsEnabled=$false;$true
            }
        }
        Assert-WinSecUpdateCoordinator ($script:store.Count -eq 0 -and @(Get-ChildItem -LiteralPath $script:technicalRoot -Recurse -File).Count -eq 0)
    }
    Test-WinSecTechnicalCoordinator 'small confirmation and changed output directory cannot authorize writing' {
        $ctx=New-WinSecUpdateCoordinatorContext;$ctx.ScanCoordinator.TechnicalReportsEnabled=$true
        $empty=Get-WinSecScanConfirmationPlan -Coordinator $ctx.ScanCoordinator -ScopeType SECTION -ScopeKey IdentityAccess
        Assert-WinSecUpdateCoordinator ($empty.CheckIds.Count -eq 0 -and (ConvertFrom-Json $empty.RequestJson).TechnicalReports.Count -eq 0)
        $script:terminal=[pscustomobject]@{Width=40;ContentWidth=39;Height=12}
        $script:keys.Enqueue([pscustomobject]@{VirtualKeyCode=13;Character='';KeyDown=$true;ControlKeyState=0})
        $script:keys.Enqueue([pscustomobject]@{VirtualKeyCode=27;Character='';KeyDown=$true;ControlKeyState=0})
        $p=Invoke-WinSecUpdateCoordinatorFixture $ctx -Id small-technical -ConfirmAction {param($request);Show-WinSecScanConfirmation $request}
        Assert-WinSecUpdateCoordinator ($null -eq $p -and @($script:lines|Where-Object {$_.Length -gt 39}).Count -eq 0)
        Assert-WinSecUpdateCoordinatorRejected {
            Invoke-WinSecUpdateCoordinatorFixture $ctx -Id changed-technical -ConfirmAction {
                param($request);$request.TechnicalReports.Directory='reports/exports/foreign';Show-WinSecScanConfirmation $request
            }
        }
        Assert-WinSecUpdateCoordinator ($script:store.Count -eq 0 -and $script:osReads -eq 0 -and @(Get-ChildItem -LiteralPath $script:technicalRoot -Recurse -File).Count -eq 0)
    }
    Test-WinSecTechnicalCoordinator 'CLI section scan announces saved files and partial failures separately from the score' {
        $ctx=New-WinSecUpdateCoordinatorContext;$ctx.ScanCoordinator.TechnicalReportsEnabled=$true
        $state=New-WinSecNavigationState;$state.Screen='MainMenu';$state.SelectedDeviceId=$ctx.Devices[0].DeviceId
        function Show-WinSecAssessmentProfileSelection {
            param($Request,$Profiles,$CurrentSystemLabel)
            [pscustomobject]@{Confirmed=$true;Selection=@($Profiles|Where-Object Profile -CEQ WSA-W11-25H2-PRO-DEF-BASE)[0]}
        }
        foreach($failure in @('','WSA-SYS-002')) {
            $script:technicalFailure=$failure
            $script:keys.Enqueue([pscustomobject]@{VirtualKeyCode=13;Character='';KeyDown=$true;ControlKeyState=0})
            $p=Invoke-WinSecCLILocalRescan -State $state -Context $ctx
            Assert-WinSecUpdateCoordinator ($null -ne $p -and $ctx.LastScanMessage.Contains('Configuration score: 66.67/100'))
            if($failure){Assert-WinSecUpdateCoordinator ($ctx.LastScanMessage.Contains('WARNING: technical Markdown export PARTIAL; saved 2, failed 1.'))}
            else{Assert-WinSecUpdateCoordinator ($ctx.LastScanMessage.Contains('Technical Markdown files saved: 3'))}
        }
    }
    Test-WinSecTechnicalCoordinator 'Framework workflow - confirmed section scan has no rating and F reviews every snapshot' {
        $ctx=New-WinSecUpdateCoordinatorContext
        $ctx.ScanCoordinator.FrameworkWorkflowEnabled=$true;$ctx.ScanCoordinator.TechnicalReportsEnabled=$true
        $ctx|Add-Member FrameworkWorkflowEnabled $true;$ctx|Add-Member LocalDeviceId $ctx.Devices[0].DeviceId
        $p=Invoke-WinSecUpdateCoordinatorFixture $ctx -Id framework-section -ScopeType SECTION -ScopeKey SystemSecurity -ConfirmAction {
            param($request)
            Assert-WinSecUpdateCoordinator ($request.AssessmentMode -ceq 'FRAMEWORK_REVIEW' -and $null -eq $request.ConfigurationScoring)
            $true
        }
        Assert-WinSecUpdateCoordinator ($null -eq $p.ConfigurationAssessment -and $ctx.ScanCoordinator.LastTechnicalReports.Files.Count -eq 3 -and
            @($ctx.ScanCoordinator.LastTechnicalReports.Files|Where-Object {$_.Path -notlike '*.md'}).Count -eq 0)
        $state=New-WinSecNavigationState;$state.Screen='MainMenu';$state.SelectedDeviceId=$p.DeviceId;$state.SelectedDeviceName='SYNTHETIC'
        $before=ConvertTo-Json $script:store -Depth 8 -Compress;$reads=$script:sequence
        $script:keys.Enqueue([pscustomobject]@{VirtualKeyCode=13;Character='';KeyDown=$true;ControlKeyState=0})
        Assert-WinSecUpdateCoordinator (Invoke-WinSecCLIFrameworkFindings $state $ctx)
        $a=$ctx.FrameworkFindings
        Assert-WinSecUpdateCoordinator ($a.FrameworkId -ceq 'cis-controls' -and $a.Sources.Count -eq 3 -and $a.ReadingCount -ge 148 -and $a.Rows.Count -ge 2 -and
            $script:sequence -eq $reads -and $before -ceq (ConvertTo-Json $script:store -Depth 8 -Compress))
        $null=Invoke-WinSecNavigationAction $state ShowFindings -SectionCount 5
        Show-WinSecCLICurrentScreen $state $ctx
        Assert-WinSecUpdateCoordinator (($script:lines -join '|') -match 'FINDINGS - cis-controls' -and ($script:lines -join '|') -notmatch 'SCORE|/100|Config %')
        $null=Invoke-WinSecNavigationAction $state Back
        Assert-WinSecUpdateCoordinator ($state.Screen -ceq 'MainMenu')
    }
    Test-WinSecTechnicalCoordinator 'Framework workflow - control notices follow selection and Q exits without another scan' {
        $ctx=New-WinSecUpdateCoordinatorContext;$ctx.ScanCoordinator.FrameworkWorkflowEnabled=$true;$ctx.ScanCoordinator.TechnicalReportsEnabled=$true
        $ctx|Add-Member FrameworkWorkflowEnabled $true;$ctx|Add-Member LocalDeviceId $ctx.Devices[0].DeviceId
        $state=New-WinSecNavigationState;$state.Screen='Section';$state.SelectedDeviceId=$ctx.Devices[0].DeviceId;$state.SelectedDeviceName='SYNTHETIC'
        function Show-WinSecAssessmentProfileSelection {
            param($Request,$Profiles,$CurrentSystemLabel)
            [pscustomobject]@{Confirmed=$true;Selection=@($Profiles|Where-Object Profile -CEQ WSA-W11-25H2-PRO-DEF-BASE)[0]}
        }
        $script:keys.Enqueue([pscustomobject]@{VirtualKeyCode=13;Character='';KeyDown=$true;ControlKeyState=0})
        $p=Invoke-WinSecCLILocalRescan -State $state -Context $ctx
        $reads=$script:sequence;$history=Get-WinSecPublicHistoryJson $script:store
        Assert-WinSecUpdateCoordinator ($null -ne $p -and $ctx.LastScanMessageContext.ScopeKey -ceq 'WSA-SYS-001' -and $script:defenderReads -eq 1 -and $script:volumeReads -eq 0)
        Show-WinSecCLICurrentScreen $state $ctx
        Assert-WinSecUpdateCoordinator (($script:lines -join '|').Contains('Technical Markdown files saved: 1'))
        $null=Invoke-WinSecNavigationAction $state MoveDown -ControlCount 3
        Show-WinSecCLICurrentScreen $state $ctx
        $rows=@(Get-WinSecWorkflowControlRows $state $ctx)
        Assert-WinSecUpdateCoordinator (($script:lines -join '|') -notmatch 'Scan COMPLETE|Technical Markdown files saved' -and
            $rows[0].Status -ceq 'COMPLETE' -and $rows[1].Status -ceq 'PENDING' -and $rows[2].Status -ceq 'PENDING')
        # Cancelling BitLocker produces a notice for BitLocker only and no new session.
        $script:keys.Enqueue([pscustomobject]@{VirtualKeyCode=27;Character='';KeyDown=$true;ControlKeyState=0})
        $cancelled=Invoke-WinSecCLILocalRescan -State $state -Context $ctx
        Show-WinSecCLICurrentScreen $state $ctx
        Assert-WinSecUpdateCoordinator ($null -eq $cancelled -and ($script:lines -join '|').Contains('Scan cancelled.') -and $ctx.LastScanMessageContext.ScopeKey -ceq 'WSA-SYS-002')
        $null=Invoke-WinSecNavigationAction $state MoveUp -ControlCount 3
        Show-WinSecCLICurrentScreen $state $ctx
        Assert-WinSecUpdateCoordinator (($script:lines -join '|') -notmatch 'Scan cancelled\.' -and $reads -eq $script:sequence -and $history -ceq (Get-WinSecPublicHistoryJson $script:store))
        $key=[pscustomobject]@{VirtualKeyCode=81;Character='q';KeyDown=$true;ControlKeyState=0}
        $action=ConvertTo-WinSecKeyboardAction -KeyInfo $key -Screen Section
        $null=Invoke-WinSecNavigationAction $state $action
        Assert-WinSecUpdateCoordinator ($state.ExitRequested -and $state.PendingCommand -ceq 'Exit' -and $reads -eq $script:sequence)
    }
    Test-WinSecTechnicalCoordinator 'Framework workflow - live and restored records keep completion states without ratings' {
        $ctx=New-WinSecUpdateCoordinatorContext;$ctx.ScanCoordinator.FrameworkWorkflowEnabled=$true;$ctx.ScanCoordinator.TechnicalReportsEnabled=$true
        $ctx|Add-Member FrameworkWorkflowEnabled $true;$ctx|Add-Member LocalDeviceId $ctx.Devices[0].DeviceId
        $state=New-WinSecNavigationState;$state.Screen='Section';$state.SelectedDeviceId=$ctx.Devices[0].DeviceId
        $empty=@(Get-WinSecWorkflowControlRows $state $ctx)
        Assert-WinSecUpdateCoordinator ((Get-WinSecWorkflowAggregateState $empty) -ceq 'PENDING')
        $null=Invoke-WinSecUpdateCoordinatorFixture $ctx -Id framework-one -ScopeKey WSA-SYS-002
        $partial=@(Get-WinSecWorkflowControlRows $state $ctx)
        Assert-WinSecUpdateCoordinator ((Get-WinSecWorkflowAggregateState $partial) -ceq 'PARTIAL' -and $partial[1].Mode -ceq 'LIVE')
        $null=Invoke-WinSecUpdateCoordinatorFixture $ctx -Id framework-all -ScopeType SECTION -ScopeKey SystemSecurity
        $rows=@(Get-WinSecWorkflowControlRows $state $ctx)
        Assert-WinSecUpdateCoordinator ((Get-WinSecWorkflowAggregateState $rows) -ceq 'COMPLETE')
        $restored=New-WinSecUpdateCoordinatorContext;Restore-WinSecPublicHistory $restored
        $restored|Add-Member LocalDeviceId $ctx.Devices[0].DeviceId;$restored|Add-Member FrameworkWorkflowEnabled $true
        $records=@(Get-WinSecWorkflowControlRows $state $restored)
        Assert-WinSecUpdateCoordinator (@($records|Where-Object Mode -CNE RECORDS).Count -eq 0 -and (Get-WinSecWorkflowAggregateState $records) -ceq 'COMPLETE')
        Show-WinSecCLICurrentScreen $state $restored
        Assert-WinSecUpdateCoordinator (($script:lines -join '|') -notmatch 'SCORE|/100|NOT_SCORED')
    }
    Test-WinSecTechnicalCoordinator 'Framework workflow - cancellation keeps the previous selected framework view' {
        $ctx=New-WinSecUpdateCoordinatorContext;$ctx.ScanCoordinator.FrameworkWorkflowEnabled=$true;$ctx.ScanCoordinator.TechnicalReportsEnabled=$true
        $ctx|Add-Member FrameworkWorkflowEnabled $true;$ctx|Add-Member LocalDeviceId $ctx.Devices[0].DeviceId
        $null=Invoke-WinSecUpdateCoordinatorFixture $ctx -Id framework-cancel-source -ScopeKey WSA-SYS-002
        $state=New-WinSecNavigationState;$state.Screen='Section';$state.ControlIndex=1;$state.SelectedDeviceId=$ctx.Devices[0].DeviceId
        $script:keys.Enqueue([pscustomobject]@{VirtualKeyCode=13;Character='';KeyDown=$true;ControlKeyState=0})
        Assert-WinSecUpdateCoordinator (Invoke-WinSecCLIFrameworkFindings $state $ctx)
        $old=Get-WinSecPublicHistoryJson $ctx.FrameworkFindings
        $script:keys.Enqueue([pscustomobject]@{VirtualKeyCode=27;Character='';KeyDown=$true;ControlKeyState=0})
        Assert-WinSecUpdateCoordinator (-not (Invoke-WinSecCLIFrameworkFindings $state $ctx) -and $old -ceq (Get-WinSecPublicHistoryJson $ctx.FrameworkFindings) -and $state.Screen -ceq 'Section')
    }
    Test-WinSecTechnicalCoordinator 'Framework workflow - Esc during comparison preserves the previous view and stored scans' {
        $ctx=New-WinSecUpdateCoordinatorContext;$ctx.ScanCoordinator.FrameworkWorkflowEnabled=$true;$ctx.ScanCoordinator.TechnicalReportsEnabled=$true
        $ctx|Add-Member FrameworkWorkflowEnabled $true;$ctx|Add-Member LocalDeviceId $ctx.Devices[0].DeviceId
        $null=Invoke-WinSecUpdateCoordinatorFixture $ctx -Id framework-midcancel -ScopeKey WSA-SYS-002
        $state=New-WinSecNavigationState;$state.Screen='Section';$state.ControlIndex=1;$state.SelectedDeviceId=$ctx.Devices[0].DeviceId
        $script:keys.Enqueue([pscustomobject]@{VirtualKeyCode=13;Character='';KeyDown=$true;ControlKeyState=0})
        Assert-WinSecUpdateCoordinator (Invoke-WinSecCLIFrameworkFindings $state $ctx)
        $old=Get-WinSecPublicHistoryJson $ctx.FrameworkFindings;$history=Get-WinSecPublicHistoryJson $script:store;$reads=$script:sequence
        $script:comparisonStarted=$false
        function Show-WinSecFrameworkProgress {param($Progress);if($null -eq $Progress.Phase){$script:comparisonStarted=$true}}
        function Read-WinSecPendingKey {if($script:comparisonStarted){[pscustomobject]@{VirtualKeyCode=27;Character='';KeyDown=$true;ControlKeyState=0}}}
        $script:keys.Enqueue([pscustomobject]@{VirtualKeyCode=13;Character='';KeyDown=$true;ControlKeyState=0})
        Assert-WinSecUpdateCoordinator (-not (Invoke-WinSecCLIFrameworkFindings $state $ctx -ShowProgress) -and $script:comparisonStarted -and
            $old -ceq (Get-WinSecPublicHistoryJson $ctx.FrameworkFindings) -and $history -ceq (Get-WinSecPublicHistoryJson $script:store) -and
            $reads -eq $script:sequence -and $state.Screen -ceq 'Section')
    }
    Test-WinSecTechnicalCoordinator 'Framework workflow - P exports exactly the selected view without prompting or collecting' {
        $ctx=New-WinSecUpdateCoordinatorContext;$ctx.ScanCoordinator.FrameworkWorkflowEnabled=$true;$ctx.ScanCoordinator.TechnicalReportsEnabled=$true
        $ctx|Add-Member FrameworkWorkflowEnabled $true;$ctx|Add-Member LocalDeviceId $ctx.Devices[0].DeviceId
        $null=Invoke-WinSecUpdateCoordinatorFixture $ctx -Id framework-print -ScopeType SECTION -ScopeKey SystemSecurity
        $state=New-WinSecNavigationState;$state.Screen='MainMenu';$state.SelectedDeviceId=$ctx.Devices[0].DeviceId
        $script:keys.Enqueue([pscustomobject]@{VirtualKeyCode=40;Character='';KeyDown=$true;ControlKeyState=0})
        $script:keys.Enqueue([pscustomobject]@{VirtualKeyCode=13;Character='';KeyDown=$true;ControlKeyState=0})
        Assert-WinSecUpdateCoordinator (Invoke-WinSecCLIFrameworkFindings $state $ctx)
        Assert-WinSecUpdateCoordinator ($ctx.FrameworkFindings.FrameworkId -ceq 'nist-csf')
        $writer=(Get-Command Export-WinSecFrameworkAnalysis).ScriptBlock
        function Export-WinSecFrameworkAnalysis {param($ProjectRoot,$Analysis);& $writer -ProjectRoot $script:technicalRoot -Analysis $Analysis}
        function Show-WinSecExportFrameworkSelection {throw 'P must not ask for the framework again.'}
        $state.Screen='Findings';$state.FindingsScope='Section';$before=Get-WinSecPublicHistoryJson $ctx.FrameworkFindings;$reads=$script:sequence
        $file=Invoke-WinSecCLIFindingsExport $state $ctx
        $text=[IO.File]::ReadAllText($file.Path);$meta=ConvertFrom-WinSecMarkdownArtifact $text $state.SelectedDeviceId
        Assert-WinSecUpdateCoordinator ($meta.AnalysisId -ceq $ctx.FrameworkFindings.AnalysisId -and $meta.FrameworkId -ceq 'nist-csf' -and
            $before -ceq (Get-WinSecPublicHistoryJson $ctx.FrameworkFindings) -and $reads -eq $script:sequence -and
            $text -notmatch 'NOT_SCORED|/100|PRIVATE-|ConfigurationPercent' -and $text.Contains('## Source scans'))
        foreach($row in $ctx.FrameworkFindings.Rows){Assert-WinSecUpdateCoordinator ($text.Contains($row.Title) -and $text.Contains($row.ScanId))}
        $ctx.FrameworkSourcesStamp='changed-source'
        Assert-WinSecUpdateCoordinatorRejected {Invoke-WinSecCLIFindingsExport $state $ctx}
    }
    Test-WinSecTechnicalCoordinator 'Framework workflow - reloaded history reads technical Markdown without a new audit' {
        $ctx=New-WinSecUpdateCoordinatorContext;$ctx.ScanCoordinator.FrameworkWorkflowEnabled=$true;$ctx.ScanCoordinator.TechnicalReportsEnabled=$true
        $null=Invoke-WinSecUpdateCoordinatorFixture $ctx -Id framework-records -ScopeType SECTION -ScopeKey SystemSecurity
        $restored=New-WinSecUpdateCoordinatorContext;Restore-WinSecPublicHistory $restored
        $restored|Add-Member FrameworkWorkflowEnabled $true;$restored|Add-Member LocalDeviceId $ctx.Devices[0].DeviceId
        $state=New-WinSecNavigationState;$state.Screen='MainMenu';$state.SelectedDeviceId=$ctx.Devices[0].DeviceId
        $reader=(Get-Command Read-WinSecTechnicalReport).ScriptBlock
        function Read-WinSecTechnicalReport {param($ProjectRoot,$DeviceId,$ScanId,$CheckId);& $reader -ProjectRoot $script:technicalRoot -DeviceId $DeviceId -ScanId $ScanId -CheckId $CheckId}
        $reads=$script:sequence;$script:keys.Enqueue([pscustomobject]@{VirtualKeyCode=13;Character='';KeyDown=$true;ControlKeyState=0})
        Assert-WinSecUpdateCoordinator (Invoke-WinSecCLIFrameworkFindings $state $restored)
        Assert-WinSecUpdateCoordinator ($restored.FrameworkFindings.ReadingCount -ge 148 -and $restored.FrameworkFindings.MissingTechnicalCheckIds.Count -eq 0 -and
            @($restored.FrameworkFindings.Sources|Where-Object Origin -CNE RECORDS).Count -eq 0 -and $reads -eq $script:sequence)
    }
    Test-WinSecUpdateCoordinator 'Production enables exactly the four individually validated controls' {
        $ready=@($script:production.Checks|Where-Object ExecutionReady)
        Assert-WinSecUpdateCoordinator ((($ready.CheckId|Sort-Object) -join '|') -ceq 'WSA-NET-001|WSA-SYS-001|WSA-SYS-002|WSA-SYS-003' -and
            @($ready|Where-Object {$_.ImplementationStatus -cne 'VALIDATED' -or -not $_.ExecutionEnabled}).Count -eq 0)
        $ctx=New-WinSecUpdateCoordinatorContext
        Assert-WinSecUpdateCoordinator ($script:osReads -eq 0 -and $script:defenderReads -eq 0 -and $script:WU.NamedPolicyReads -eq 0)
    }
    foreach($scope in @(@{T='DEVICE';K='ALL';Ids='WSA-NET-001|WSA-SYS-001|WSA-SYS-002|WSA-SYS-003'},
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
    Test-WinSecUpdateCoordinator 'A full device scan executes only the four ready controls and preserves independent section rows' {
        $ctx=New-WinSecUpdateCoordinatorContext
        $p=Invoke-WinSecUpdateCoordinatorFixture $ctx -ScopeType DEVICE -ScopeKey ALL
        $system=@($p.ConfigurationAssessment.Sections|Where-Object SectionKey -CEQ SystemSecurity)
        Assert-WinSecUpdateCoordinator ($p.ControlResults.Count -eq 14 -and
            @($p.ControlResults|Where-Object Status -CNE NOT_SELECTED).Count -eq 4 -and $script:FirewallCalls.Count -eq 25 -and
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
    Test-WinSecUpdateCoordinator 'Findings navigation reuses saved results and cached syntax without rerunning collectors' {
        $ctx=New-WinSecUpdateCoordinatorContext
        $p=Invoke-WinSecUpdateCoordinatorFixture $ctx -Id navigation-source -ScopeType SECTION -ScopeKey SystemSecurity
        $restart=New-WinSecUpdateCoordinatorContext;Restore-WinSecPublicHistory $restart
        $state=New-WinSecNavigationState;$state.Screen='Findings';$state.FindingsScope='Control';$state.ControlIndex=0
        $state.SelectedDeviceId=$p.DeviceId
        $reads=@($script:osReads,$script:defenderReads,$script:volumeReads,$script:volumeMethods,$script:WU.NamedPolicyReads,$script:sequence)
        $before=ConvertTo-Json $script:store -Depth 8 -Compress
        $registryReader=(Get-Command Get-WinSecCheckRegistry).ScriptBlock
        function Get-WinSecCheckRegistry {
            param($ProjectRoot,$Path='')
            if($script:forceColdSyntax){$script:WinSecScriptSyntaxCache=@{}}
            & $registryReader @PSBoundParameters
        }
        $outputs=@();$times=@()
        foreach($cold in @($true,$false)) {
            $script:forceColdSyntax=$cold
            $clock=[Diagnostics.Stopwatch]::StartNew()
            $counts=Get-WinSecCLINavigationCounts $state $restart
            $canExport=Test-WinSecCLIFindingsExportEligibility $state $restart
            Show-WinSecCLICurrentScreen $state $restart
            $clock.Stop();$times+=$clock.ElapsedMilliseconds
            $outputs+=($script:lines -join '|')
            Assert-WinSecUpdateCoordinator ($canExport -and $counts.FindingCount -gt 0)
        }
        $script:forceColdSyntax=$false
        $clock=[Diagnostics.Stopwatch]::StartNew()
        $event=Get-WinSecKeyboardAction -KeyInfo ([pscustomobject]@{VirtualKeyCode=38;Character='';KeyDown=$true;ControlKeyState=0}) `
            -Screen Findings -EnableExport
        $fastCounts=Get-WinSecCLINavigationCounts $state $restart -Action $event.Action
        $null=Invoke-WinSecNavigationAction $state $event.Action -FindingCount $fastCounts.FindingCount
        Show-WinSecCLICurrentScreen $state $restart
        $clock.Stop()
        Assert-WinSecUpdateCoordinator ($outputs[0] -ceq $outputs[1] -and
            $outputs[1] -ceq ($script:lines -join '|') -and $event.Action -ceq 'ScrollUp' -and
            ($reads -join '|') -ceq (@($script:osReads,$script:defenderReads,$script:volumeReads,$script:volumeMethods,$script:WU.NamedPolicyReads,$script:sequence) -join '|') -and
            $before -ceq (ConvertTo-Json $script:store -Depth 8 -Compress))
        [Console]::WriteLine(('Synthetic Findings navigation: cold syntax={0} ms; warm syntax={1} ms; optimized up-key={2} ms. No timing threshold.' -f $times[0],$times[1],$clock.ElapsedMilliseconds))
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
