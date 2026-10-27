# Real production permissions and synthetic providers. No native Windows scans.
[CmdletBinding()]param()
$ErrorActionPreference='Stop';$sourceRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$tempParent=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\','/')
$sandbox=[IO.Path]::GetFullPath((Join-Path $tempParent ('WinSec-Rdp-'+[guid]::NewGuid().ToString('N'))))
$null=[IO.Directory]::CreateDirectory($sandbox)
$checksHash=(Get-FileHash (Join-Path $sourceRoot 'config/checks.json')).Hash
$oldHostname=$env:COMPUTERNAME;$env:COMPUTERNAME='SYNTHETIC-RDP';$passed=0;$failed=0
function Assert-RdpIntegration {param([bool]$Value);if(-not $Value){throw 'RDP integration assertion failed.'}}
function Test-RdpIntegration {param($Name,[scriptblock]$Action);try{$null=& $Action;$script:passed++;[Console]::WriteLine('[PASS] '+$Name)}catch{$script:failed++;[Console]::WriteLine('[FAIL] '+$Name+': '+$_.Exception.Message);[Console]::WriteLine($_.ScriptStackTrace)}}
try {
    foreach($directory in @('src','config')){Copy-Item -LiteralPath (Join-Path $sourceRoot $directory) -Destination (Join-Path $sandbox $directory) -Recurse}
    foreach($file in @('src/Core/ScanCoordinator.ps1','src/CLI/Invoke-WinSecCLI.ps1','src/UI/Core/NavigationController.ps1',
        'src/UI/Screens/MainMenu.ps1','src/UI/Screens/Results.ps1','src/CLI/FrameworkWorkflow.ps1',
        'src/UI/Core/TerminalRenderer.ps1','src/UI/Screens/ScanProgress.ps1')){. (Join-Path $sandbox $file)}
    foreach($fixture in @('Rdp','Smb','Firewall')){. (Join-Path $sourceRoot ('tests/Fixtures/'+$fixture+'Memory.ps1'))}
    function Get-WinSecRdpIntegrationCim {
        [CmdletBinding()]param($Namespace,$ClassName,$Property,$Filter,$OperationTimeoutSec)
        if($Namespace -ceq 'root/cimv2' -and $OperationTimeoutSec -eq 5){return Get-WinSecSmbFixtureCim @PSBoundParameters}
        return Get-WinSecFirewallFixtureCim @PSBoundParameters
    }
    function Get-WinSecRdpFixtureHardware {'local:hw1-'+('b'*64)}
    Set-Alias Get-WinSecLocalHardwareDeviceId Get-WinSecRdpFixtureHardware -Scope Script
    Set-Alias Get-CimInstance Get-WinSecRdpIntegrationCim -Scope Script
    Set-Alias Invoke-WinSecFirewallQuery Invoke-WinSecFirewallFixtureQuery -Scope Script
    Set-Alias Invoke-WinSecSmbQuery Invoke-WinSecSmbFixtureQuery -Scope Script
    Set-Alias Read-WinSecSmbRegistryValue Read-WinSecSmbFixtureRegistry -Scope Script
    Set-Alias Invoke-WinSecRdpQuery Invoke-WinSecRdpFixtureQuery -Scope Script
    Set-Alias Read-WinSecRdpRegistryValue Read-WinSecRdpFixtureRegistry -Scope Script
    $production=Get-WinSecCheckRegistry $sandbox
    Test-RdpIntegration 'Production enables RDP after native validation and leaves eight controls disabled' {
        $check=@($production.Checks|Where-Object CheckId -CEQ WSA-NET-003)[0]
        Assert-RdpIntegration ($check.ExecutionEnabled -and $check.ExecutionReady -and $check.ImplementationStatus -ceq 'VALIDATED' -and
            (($production.Checks|Where-Object ExecutionReady|Sort-Object CheckId).CheckId -join '|') -ceq 'WSA-NET-001|WSA-NET-002|WSA-NET-003|WSA-SYS-001|WSA-SYS-002|WSA-SYS-003' -and
            @($production.Checks|Where-Object {-not $_.ExecutionEnabled}).Count -eq 8)
    }
    Initialize-WinSecRdpFixture;Initialize-WinSecSmbFixture;Initialize-WinSecFirewallFixture
    $null=Register-WinSecLocalDevice $sandbox;$target=New-WinSecLocalTarget
    $c=New-WinSecScanCoordinator $sandbox;$c.Registry=[pscustomobject]@{schemaVersion='1.0.0';targets=@($target)}
    $c.AssessmentEnabled=$true;$c.PublicHistoryEnabled=$true;$c.TechnicalReportsEnabled=$true
    $confirmation={
        param($request)
        $ids=if($request.ScopeType -ceq 'SECTION'){'WSA-NET-001|WSA-NET-002|WSA-NET-003'}else{'WSA-NET-003'}
        Assert-RdpIntegration ($request.ReadOnly -and (($request.Checks.CheckId|Sort-Object) -join '|') -ceq $ids)
        $true
    }
    Test-RdpIntegration 'Device confirmation lists exactly six validated controls and cancels without collection' {
        $r=Invoke-WinSecCoordinatedScan $c -DeviceId $target.DeviceId -ScanId cancelled-device -ScopeType DEVICE -ScopeKey ALL -ConfirmAction {
            param($request)
            Assert-RdpIntegration ($request.ReadOnly -and (($request.Checks.CheckId|Sort-Object) -join '|') -ceq
                'WSA-NET-001|WSA-NET-002|WSA-NET-003|WSA-SYS-001|WSA-SYS-002|WSA-SYS-003')
            $false
        }
        Assert-RdpIntegration ($null -eq $r -and $RdpCalls.Count -eq 0 -and $FirewallCalls.Count -eq 0 -and $SmbCalls.Count -eq 0 -and $c.Sessions.Count -eq 0)
    }
    Test-RdpIntegration 'Cancelling confirmation leaves providers history and technical reports untouched' {
        $r=Invoke-WinSecCoordinatedScan $c -DeviceId $target.DeviceId -ScanId cancelled -ScopeType CONTROL -ScopeKey WSA-NET-003 -ConfirmAction {$false}
        Assert-RdpIntegration ($null -eq $r -and $RdpCalls.Count -eq 0 -and $c.Sessions.Count -eq 0 -and -not (Test-Path (Join-Path $sandbox 'reports/exports')))
    }
    Test-RdpIntegration 'Confirmed RDP scan persists one complete technical Markdown and public history without scores' {
        $public=Invoke-WinSecCoordinatedScan $c -DeviceId $target.DeviceId -ScanId rdp-control -ScopeType CONTROL -ScopeKey WSA-NET-003 `
            -AssessmentProfile WSA-W11-23H2-PRO-DEF-BASE -ConfirmAction $confirmation -ProgressCallback {param($event);$script:RdpEvents.Add($event)}
        Assert-RdpIntegration ($public.ExecutionStatus -ceq 'COMPLETED' -and $null -eq $public.ConfigurationAssessment -and $null -eq $public.OverallScore -and
            @($public.ControlResults|Where-Object Status -CNE NOT_SELECTED).Count -eq 1 -and $c.LastTechnicalReports.Status -ceq 'SAVED' -and $c.LastTechnicalReports.Files.Count -eq 1)
        $r=Read-WinSecTechnicalReport $sandbox $target.DeviceId rdp-control WSA-NET-003
        Assert-RdpIntegration ($r.Rows.Count -eq @(Get-WinSecRdpTechnicalDefinitions).Count -and $r.ObservedOSRelease -ceq 'Windows 11 10.0.22631' -and
            (Get-Content $c.LastTechnicalReports.Files[0].Path -Raw) -notmatch 'PRIVATE-|NOT_SCORED|/100' -and
            (Get-WinSecScanAction $c $target.DeviceId CONTROL WSA-NET-003) -ceq 'Rescan' -and
            (Get-WinSecScanAction $c $target.DeviceId SECTION NetworkSecurity) -ceq 'Scan')
    }
    Test-RdpIntegration 'Esc during rescan preserves previous session and files' {
        $script:RdpCalls.Clear();$before=@(Get-ChildItem (Join-Path $sandbox 'reports/exports') -Recurse -File).Count
        $r=Invoke-WinSecCoordinatedScan $c -DeviceId $target.DeviceId -ScanId cancelled-running -ScopeType CONTROL -ScopeKey WSA-NET-003 `
            -ConfirmAction $confirmation -CancellationAction {return ($script:RdpCalls.Count -ge 2)}
        Assert-RdpIntegration ($null -eq $r -and $c.Sessions.Count -eq 1 -and $RdpCalls.Count -eq 2 -and
            @(Get-ChildItem (Join-Path $sandbox 'reports/exports') -Recurse -File).Count -eq $before)
    }
    Test-RdpIntegration 'A confirmed section executes its three production-enabled controls and saves independent Markdown files' {
        $r=Invoke-WinSecCoordinatedScan $c -DeviceId $target.DeviceId -ScanId rdp-section -ScopeType SECTION -ScopeKey NetworkSecurity `
            -AssessmentProfile WSA-W11-23H2-PRO-DEF-BASE -ConfirmAction $confirmation
        Assert-RdpIntegration ($r.ExecutionStatus -ceq 'COMPLETED' -and $c.LastTechnicalReports.Files.Count -eq 3 -and
            (($c.LastTechnicalReports.Files.CheckId|Sort-Object) -join '|') -ceq 'WSA-NET-001|WSA-NET-002|WSA-NET-003' -and
            (Get-WinSecScanAction $c $target.DeviceId SECTION NetworkSecurity) -ceq 'Rescan')
    }
    Test-RdpIntegration 'Restored F selects a framework and P exports that frozen view with no new provider calls' {
        $restored=New-WinSecScanCoordinator $sandbox;$restored.Registry=$c.Registry
        $state=New-WinSecNavigationState;$state.Screen='Section';$state.SelectedDeviceId=$target.DeviceId
        $sections=@(Get-WinSecMainMenuSections);for($i=0;$i -lt $sections.Count;$i++){if($sections[$i].Key -ceq 'NetworkSecurity'){$state.SectionIndex=$i}}
        $state.ControlIndex=2
        $ctx=[pscustomobject]@{ProjectRoot=$sandbox;ScanCoordinator=$restored;Devices=@([pscustomobject]@{DeviceId=$target.DeviceId;Hostname='SYNTHETIC-RDP';DisplayName='SYNTHETIC-RDP'});
            PublicScans=@{};ActiveScanByDevice=@{};ActiveScanByScope=@{};LocalDeviceId=$target.DeviceId;FrameworkWorkflowEnabled=$true;LastExportMessage=''}
        $null=Restore-WinSecPublicHistory -Context $ctx;$calls=$RdpCalls.Count;$fwCalls=$FirewallCalls.Count;$smbCalls=$script:SmbCalls.Count
        function Show-WinSecExportFrameworkSelection {param($Selection,[switch]$ForFindings);[pscustomobject]@{Confirmed=$true;FrameworkId='mitre-attack'}}
        Assert-RdpIntegration (Invoke-WinSecCLIFrameworkFindings $state $ctx)
        $state.Screen='Findings';$state.FindingsScope='Control';$artifact=Export-WinSecCLIFrameworkFindings $state $ctx
        Assert-RdpIntegration ($artifact.Path.EndsWith('.md') -and $ctx.FrameworkFindings.FrameworkId -ceq 'mitre-attack' -and
            $ctx.FrameworkFindings.Rows.Count -eq 8 -and $ctx.FrameworkFindings.Sources[0].Origin -ceq 'RECORDS' -and
            $RdpCalls.Count -eq $calls -and $FirewallCalls.Count -eq $fwCalls -and $script:SmbCalls.Count -eq $smbCalls)
    }
    Test-RdpIntegration 'A scan with the native informational-null pattern persists complete execution and limited coverage' {
        $script:RdpNullFields=@('NetworkAdapterLanaID','DenyAdminPermissionForCustomization','PolicySourceDenyAdminPermissionForCustomization','VideoPlaybackRedir','PolicySourceVideoPlaybackRedir')
        $script:RdpListenerCounts=@{Network=1;Permissions=2;Redirection=1}
        $r=Invoke-WinSecCoordinatedScan $c -DeviceId $target.DeviceId -ScanId rdp-limited -ScopeType CONTROL -ScopeKey WSA-NET-003 `
            -AssessmentProfile WSA-W11-23H2-PRO-DEF-BASE -ConfirmAction $confirmation
        $technical=Read-WinSecTechnicalReport $sandbox $target.DeviceId rdp-limited WSA-NET-003
        $coverage=@($technical.Rows|Where-Object SettingId -CEQ CoverageComplete)[0]
        $unknown=@($technical.Rows|Where-Object SettingId -CEQ InformationalUnknownFieldCount)[0]
        Assert-RdpIntegration ($r.ExecutionStatus -ceq 'COMPLETED' -and $coverage.Value -ceq $false -and $unknown.Value -eq 7 -and
            $c.LastTechnicalReports.Status -ceq 'SAVED' -and (ConvertTo-WinSecTechnicalMarkdown $technical).Contains('Reading coverage: LIMITED'))
    }
    Test-RdpIntegration 'Detailed RDP progress survives small and resized terminals without collection' {
        $script:rendered=New-Object 'Collections.Generic.List[string]'
        function Write-Host {param([object[]]$Object,$ForegroundColor,$BackgroundColor,[switch]$NoNewline);$script:rendered.Add(($Object -join ' '))}
        function Clear-WinSecScreen {$script:rendered.Clear()}
        function Get-WinSecTerminalSize {$script:rdpTerminal}
        $event=@($RdpEvents|Where-Object SchemaVersion -CEQ '2.0.0')[0];$calls=$RdpCalls.Count
        $display=New-WinSecScanProgressState $target.DeviceId 'Remote Desktop' Scan
        foreach($width in @(120,40,80)){
            $script:rdpTerminal=[pscustomobject]@{Width=$width;ContentWidth=($width-1);Height=12}
            Show-WinSecScanProgress $display $event
            Assert-RdpIntegration (@($rendered|Where-Object {$_.Length -gt ($width-1)}).Count -eq 0 -and ($rendered -join '|').Contains('Remote Desktop:'))
        }
        Assert-RdpIntegration ($RdpCalls.Count -eq $calls)
    }
} finally {
    $env:COMPUTERNAME=$oldHostname
    Assert-RdpIntegration ((Get-FileHash (Join-Path $sourceRoot 'config/checks.json')).Hash -ceq $checksHash)
    $absolute=[IO.Path]::GetFullPath($sandbox)
    if([IO.Path]::GetDirectoryName($absolute) -cne $tempParent -or [IO.Path]::GetFileName($absolute) -cnotmatch '\AWinSec-Rdp-[a-f0-9]{32}\z'){throw 'Unsafe RDP fixture cleanup.'}
    Remove-Item -LiteralPath $absolute -Recurse -Force
}
[Console]::WriteLine('RDP integration: '+$passed+' passed; '+$failed+' failed.');if($failed){throw 'RDP integration tests failed.'}
