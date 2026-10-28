# Real production permissions, coordinator and owned temporary storage.
# All providers are synthetic. No production audit or permission changes.
[CmdletBinding()]param()
$ErrorActionPreference='Stop';$sourceRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$tempParent=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\','/')
$sandbox=Join-Path $tempParent ('WinSec-Ports-'+[guid]::NewGuid().ToString('N'));$null=[IO.Directory]::CreateDirectory($sandbox)
$checksHash=(Get-FileHash (Join-Path $sourceRoot 'config/checks.json')).Hash
$oldHostname=$env:COMPUTERNAME;$env:COMPUTERNAME='SYNTHETIC-PORTS';$passed=0;$failed=0
function Assert-PortsIntegration {param([bool]$Value);if(-not $Value){throw 'Open Ports integration assertion failed.'}}
function Test-PortsIntegration {param($Name,[scriptblock]$Action);try{$null=& $Action;$script:passed++;[Console]::WriteLine('[PASS] '+$Name)}catch{$script:failed++;[Console]::WriteLine('[FAIL] '+$Name+': '+$_.Exception.Message);[Console]::WriteLine($_.ScriptStackTrace)}}
try {
    foreach($directory in @('src','config')){Copy-Item -LiteralPath (Join-Path $sourceRoot $directory) -Destination (Join-Path $sandbox $directory) -Recurse}
    foreach($file in @('src/Core/ScanCoordinator.ps1','src/CLI/Invoke-WinSecCLI.ps1','src/UI/Core/NavigationController.ps1',
        'src/UI/Screens/MainMenu.ps1','src/UI/Screens/Results.ps1','src/CLI/FrameworkWorkflow.ps1','src/UI/Core/TerminalRenderer.ps1','src/UI/Screens/ScanProgress.ps1')){. (Join-Path $sandbox $file)}
    foreach($fixture in @('NetworkConfiguration','OpenPorts','Rdp','Smb','Firewall')){. (Join-Path $sourceRoot ('tests/Fixtures/'+$fixture+'Memory.ps1'))}
    function Get-WinSecPortsIntegrationCim {
        [CmdletBinding()]param($Namespace,$ClassName,$Property,$Filter,$OperationTimeoutSec)
        if($Namespace -ceq 'root/cimv2' -and $OperationTimeoutSec -eq 5){return Get-WinSecSmbFixtureCim @PSBoundParameters}
        return Get-WinSecFirewallFixtureCim @PSBoundParameters
    }
    function Get-WinSecPortsFixtureHardware {'local:hw1-'+('b'*64)}
    Set-Alias Get-WinSecLocalHardwareDeviceId Get-WinSecPortsFixtureHardware -Scope Script
    Set-Alias Get-CimInstance Get-WinSecPortsIntegrationCim -Scope Script
    Set-Alias Invoke-WinSecFirewallQuery Invoke-WinSecFirewallFixtureQuery -Scope Script
    Set-Alias Invoke-WinSecSmbQuery Invoke-WinSecSmbFixtureQuery -Scope Script
    Set-Alias Read-WinSecSmbRegistryValue Read-WinSecSmbFixtureRegistry -Scope Script
    Set-Alias Invoke-WinSecRdpQuery Invoke-WinSecRdpFixtureQuery -Scope Script
    Set-Alias Read-WinSecRdpRegistryValue Read-WinSecRdpFixtureRegistry -Scope Script
    Set-Alias Invoke-WinSecOpenPortsQuery Invoke-WinSecOpenPortsFixtureQuery -Scope Script
    Set-Alias Invoke-WinSecNetworkConfigurationQuery Invoke-WinSecNetworkConfigurationFixtureQuery -Scope Script
    $production=Get-WinSecCheckRegistry $sandbox
    Test-PortsIntegration 'Production enables Open Ports after native validation and leaves six controls disabled' {
        $check=Get-WinSecRegisteredCheck $production WSA-NET-004
        Assert-PortsIntegration ($check.ExecutionEnabled -and $check.ExecutionReady -and $check.ImplementationStatus -ceq 'VALIDATED' -and
            (($production.Checks|Where-Object ExecutionReady|Sort-Object CheckId).CheckId -join '|') -ceq 'WSA-NET-001|WSA-NET-002|WSA-NET-003|WSA-NET-004|WSA-NET-005|WSA-SYS-001|WSA-SYS-002|WSA-SYS-003' -and
            @($production.Checks|Where-Object {-not $_.ExecutionEnabled}).Count -eq 6)
    }
    Initialize-WinSecNetworkConfigurationFixture;Initialize-WinSecOpenPortsFixture;Initialize-WinSecRdpFixture;Initialize-WinSecSmbFixture;Initialize-WinSecFirewallFixture
    $null=Register-WinSecLocalDevice $sandbox;$target=New-WinSecLocalTarget
    $c=New-WinSecScanCoordinator $sandbox;$c.Registry=[pscustomobject]@{schemaVersion='1.0.0';targets=@($target)}
    $c.AssessmentEnabled=$true;$c.PublicHistoryEnabled=$true;$c.TechnicalReportsEnabled=$true
    $confirmation={param($preview)
        $ids=if($preview.ScopeType -ceq 'SECTION'){'WSA-NET-001|WSA-NET-002|WSA-NET-003|WSA-NET-004|WSA-NET-005'}else{'WSA-NET-004'}
        Assert-PortsIntegration ($preview.ReadOnly -and (($preview.Checks.CheckId|Sort-Object) -join '|') -ceq $ids)
        $true
    }
    Test-PortsIntegration 'Device confirmation lists exactly eight validated controls and cancels without provider calls' {
        $r=Invoke-WinSecCoordinatedScan $c -DeviceId $target.DeviceId -ScanId cancelled-device -ScopeType DEVICE -ScopeKey ALL -ConfirmAction {
            param($preview)
            Assert-PortsIntegration ($preview.ReadOnly -and (($preview.Checks.CheckId|Sort-Object) -join '|') -ceq
                'WSA-NET-001|WSA-NET-002|WSA-NET-003|WSA-NET-004|WSA-NET-005|WSA-SYS-001|WSA-SYS-002|WSA-SYS-003')
            $false
        }
        Assert-PortsIntegration ($null -eq $r -and $c.Sessions.Count -eq 0 -and $PortsCalls.Count -eq 0 -and $RdpCalls.Count -eq 0 -and $SmbCalls.Count -eq 0 -and $FirewallCalls.Count -eq 0)
    }
    Test-PortsIntegration 'Cancelled confirmation never collects or creates files' {
        $r=Invoke-WinSecCoordinatedScan $c -DeviceId $target.DeviceId -ScanId cancelled -ScopeType CONTROL -ScopeKey WSA-NET-004 -ConfirmAction {$false}
        Assert-PortsIntegration ($null -eq $r -and $PortsCalls.Count -eq 0 -and $c.Sessions.Count -eq 0 -and -not (Test-Path (Join-Path $sandbox 'reports/exports')))
    }
    Test-PortsIntegration 'Confirmed control scan saves independent technical Markdown and safe immutable history without scores' {
        $r=Invoke-WinSecCoordinatedScan $c -DeviceId $target.DeviceId -ScanId ports-control -ScopeType CONTROL -ScopeKey WSA-NET-004 `
            -AssessmentProfile WSA-W11-23H2-PRO-DEF-BASE -ConfirmAction $confirmation -ProgressCallback {param($event);$script:PortsEvents.Add($event)}
        $technical=Read-WinSecTechnicalReport $sandbox $target.DeviceId ports-control WSA-NET-004
        Assert-PortsIntegration ($r.ExecutionStatus -ceq 'COMPLETED' -and $null -eq $r.OverallScore -and $null -eq $r.ConfigurationAssessment -and
            $c.LastTechnicalReports.Status -ceq 'SAVED' -and $c.LastTechnicalReports.Files.Count -eq 1 -and
            (Get-WinSecScanAction $c $target.DeviceId CONTROL WSA-NET-004) -ceq 'Rescan' -and
            (Get-WinSecScanAction $c $target.DeviceId SECTION NetworkSecurity) -ceq 'Scan' -and
            (ConvertTo-WinSecTechnicalMarkdown $technical) -notmatch 'PRIVATE-|192\.0\.2\.9|NOT_SCORED|/100')
    }
    Test-PortsIntegration 'Esc during rescan preserves the previous session and technical file' {
        $script:PortsCalls.Clear();$before=@(Get-ChildItem (Join-Path $sandbox 'reports/exports') -Recurse -File).Count
        $r=Invoke-WinSecCoordinatedScan $c -DeviceId $target.DeviceId -ScanId cancelled-running -ScopeType CONTROL -ScopeKey WSA-NET-004 `
            -ConfirmAction $confirmation -CancellationAction {$PortsCalls.Count -ge 2}
        Assert-PortsIntegration ($null -eq $r -and $c.Sessions.Count -eq 1 -and $PortsCalls.Count -eq 2 -and
            @(Get-ChildItem (Join-Path $sandbox 'reports/exports') -Recurse -File).Count -eq $before)
    }
    Test-PortsIntegration 'Section scan saves five owner-bound technical snapshots for exactly the selected section' {
        $r=Invoke-WinSecCoordinatedScan $c -DeviceId $target.DeviceId -ScanId ports-section -ScopeType SECTION -ScopeKey NetworkSecurity `
            -AssessmentProfile WSA-W11-23H2-PRO-DEF-BASE -ConfirmAction $confirmation
        Assert-PortsIntegration ($r.ExecutionStatus -ceq 'COMPLETED' -and $c.LastTechnicalReports.Files.Count -eq 5 -and $NetworkCalls.Count -eq 11 -and
            (($c.LastTechnicalReports.Files.CheckId|Sort-Object) -join '|') -ceq 'WSA-NET-001|WSA-NET-002|WSA-NET-003|WSA-NET-004|WSA-NET-005' -and
            (Get-WinSecScanAction $c $target.DeviceId SECTION NetworkSecurity) -ceq 'Rescan')
    }
    Test-PortsIntegration 'Restored F chooses a framework and P exports the frozen view without querying Windows again' {
        $restored=New-WinSecScanCoordinator $sandbox;$restored.Registry=$c.Registry
        $state=New-WinSecNavigationState;$state.Screen='Section';$state.SelectedDeviceId=$target.DeviceId
        $sections=@(Get-WinSecMainMenuSections);for($i=0;$i -lt $sections.Count;$i++){if($sections[$i].Key -ceq 'NetworkSecurity'){$state.SectionIndex=$i}}
        $state.ControlIndex=3
        $ctx=[pscustomobject]@{ProjectRoot=$sandbox;ScanCoordinator=$restored;Devices=@([pscustomobject]@{DeviceId=$target.DeviceId;Hostname='SYNTHETIC-PORTS';DisplayName='SYNTHETIC-PORTS'});
            PublicScans=@{};ActiveScanByDevice=@{};ActiveScanByScope=@{};LocalDeviceId=$target.DeviceId;FrameworkWorkflowEnabled=$true;LastExportMessage=''}
        $null=Restore-WinSecPublicHistory $ctx;$calls=$PortsCalls.Count;$networkReads=$NetworkCalls.Count;$rdp=$RdpCalls.Count;$smb=$SmbCalls.Count;$fw=$FirewallCalls.Count
        function Show-WinSecExportFrameworkSelection {param($Selection,[switch]$ForFindings);[pscustomobject]@{Confirmed=$true;FrameworkId='nist-csf'}}
        Assert-PortsIntegration (Invoke-WinSecCLIFrameworkFindings $state $ctx)
        $state.Screen='Findings';$state.FindingsScope='Control';$artifact=Export-WinSecCLIFrameworkFindings $state $ctx
        Assert-PortsIntegration ($artifact.Path.EndsWith('.md') -and $ctx.FrameworkFindings.Rows.Count -eq 2 -and $ctx.FrameworkFindings.Sources[0].Origin -ceq 'RECORDS' -and
            $PortsCalls.Count -eq $calls -and $NetworkCalls.Count -eq $networkReads -and $RdpCalls.Count -eq $rdp -and $SmbCalls.Count -eq $smb -and $FirewallCalls.Count -eq $fw)
    }
    Test-PortsIntegration 'Optional endpoint metadata persists as unknown without converting complete execution into a security verdict' {
        $script:PortsOptionalMissing=$true
        $r=Invoke-WinSecCoordinatedScan $c -DeviceId $target.DeviceId -ScanId ports-limited -ScopeType CONTROL -ScopeKey WSA-NET-004 `
            -AssessmentProfile WSA-W11-23H2-PRO-DEF-BASE -ConfirmAction $confirmation
        $technical=Read-WinSecTechnicalReport $sandbox $target.DeviceId ports-limited WSA-NET-004
        Assert-PortsIntegration ($r.ExecutionStatus -ceq 'COMPLETED' -and @($technical.Rows|Where-Object SettingId -CEQ CoverageComplete)[0].Value -ceq $false -and
            @($technical.Rows|Where-Object SettingId -CEQ UnknownFieldCount)[0].Value -eq 18 -and (ConvertTo-WinSecTechnicalMarkdown $technical).Contains('UNKNOWN'))
        $script:PortsOptionalMissing=$false
    }
    Test-PortsIntegration 'Progress fits small and resized terminals without additional provider calls' {
        $script:lines=New-Object 'Collections.Generic.List[string]'
        function Write-Host {param([object[]]$Object,$ForegroundColor,$BackgroundColor,[switch]$NoNewline);$script:lines.Add(($Object -join ' '))}
        function Clear-WinSecScreen {$script:lines.Clear()}
        function Get-WinSecTerminalSize {$script:portsTerminal}
        $event=@($PortsEvents|Where-Object SchemaVersion -CEQ '2.0.0')[0];$before=$PortsCalls.Count
        $display=New-WinSecScanProgressState $target.DeviceId 'Open Ports' Scan
        foreach($width in @(40,120,80)){
            $script:portsTerminal=[pscustomobject]@{Width=$width;ContentWidth=($width-1);Height=12}
            Show-WinSecScanProgress $display $event
            Assert-PortsIntegration (@($lines|Where-Object {$_.Length -gt ($width-1)}).Count -eq 0 -and ($lines -join '|').Contains('Open Ports:'))
        }
        Assert-PortsIntegration ($before -eq $PortsCalls.Count)
    }
}finally{
    $env:COMPUTERNAME=$oldHostname
    Assert-PortsIntegration ((Get-FileHash (Join-Path $sourceRoot 'config/checks.json')).Hash -ceq $checksHash)
    $absolute=[IO.Path]::GetFullPath($sandbox)
    if([IO.Path]::GetDirectoryName($absolute) -cne $tempParent -or [IO.Path]::GetFileName($absolute) -cnotmatch '\AWinSec-Ports-[a-f0-9]{32}\z'){throw 'Unsafe fixture cleanup.'}
    Remove-Item -LiteralPath $absolute -Recurse -Force
}
[Console]::WriteLine('Open Ports integration: '+$passed+' passed; '+$failed+' failed.');if($failed){throw 'Open Ports integration failed.'}
