# Real coordinator, public history and Markdown in an owned temporary installation.
# Real production permissions; every Windows provider is synthetic.
[CmdletBinding()]param()
$ErrorActionPreference='Stop';$sourceRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$tempParent=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\','/')
$sandbox=[IO.Path]::GetFullPath((Join-Path $tempParent ('WinSec-Smb-'+[guid]::NewGuid().ToString('N'))))
$null=[IO.Directory]::CreateDirectory($sandbox)
$checksHash=(Get-FileHash (Join-Path $sourceRoot 'config/checks.json')).Hash
$oldHostname=$env:COMPUTERNAME;$env:COMPUTERNAME='SYNTHETIC-SMB'
$passed=0;$failed=0
function Assert-SmbIntegration {param([bool]$Value);if(-not $Value){throw 'SMB integration assertion failed.'}}
function Test-SmbIntegration {param($Name,[scriptblock]$Action);try{$null=& $Action;$script:passed++;[Console]::WriteLine('[PASS] '+$Name)}catch{$script:failed++;[Console]::WriteLine('[FAIL] '+$Name+': '+$_.Exception.Message);[Console]::WriteLine($_.ScriptStackTrace)}}
try {
    foreach($directory in @('src','config')){Copy-Item -LiteralPath (Join-Path $sourceRoot $directory) -Destination (Join-Path $sandbox $directory) -Recurse}
    foreach($file in @('src/Core/ScanCoordinator.ps1','src/CLI/Invoke-WinSecCLI.ps1','src/UI/Core/NavigationController.ps1',
        'src/UI/Screens/MainMenu.ps1','src/UI/Screens/Results.ps1','src/CLI/FrameworkWorkflow.ps1',
        'src/UI/Core/TerminalRenderer.ps1','src/UI/Screens/ScanProgress.ps1')){. (Join-Path $sandbox $file)}
    . (Join-Path $sourceRoot 'tests/Fixtures/SmbMemory.ps1')
    . (Join-Path $sourceRoot 'tests/Fixtures/FirewallMemory.ps1')
    . (Join-Path $sourceRoot 'tests/Fixtures/RdpMemory.ps1')
    . (Join-Path $sourceRoot 'tests/Fixtures/OpenPortsMemory.ps1')
    function Get-WinSecNetworkIntegrationCim {
        [CmdletBinding()]param($Namespace,$ClassName,$Property,$Filter,$OperationTimeoutSec)
        if($Namespace -ceq 'root/cimv2' -and $OperationTimeoutSec -eq 5){return Get-WinSecSmbFixtureCim @PSBoundParameters}
        return Get-WinSecFirewallFixtureCim @PSBoundParameters
    }
    function Get-WinSecSmbFixtureHardware {'local:hw1-'+('b'*64)}
    Set-Alias Get-WinSecLocalHardwareDeviceId Get-WinSecSmbFixtureHardware -Scope Script
    Set-Alias Get-CimInstance Get-WinSecNetworkIntegrationCim -Scope Script
    Set-Alias Invoke-WinSecFirewallQuery Invoke-WinSecFirewallFixtureQuery -Scope Script
    Set-Alias Invoke-WinSecSmbQuery Invoke-WinSecSmbFixtureQuery -Scope Script
    Set-Alias Read-WinSecSmbRegistryValue Read-WinSecSmbFixtureRegistry -Scope Script
    Set-Alias Invoke-WinSecRdpQuery Invoke-WinSecRdpFixtureQuery -Scope Script
    Set-Alias Read-WinSecRdpRegistryValue Read-WinSecRdpFixtureRegistry -Scope Script
    Set-Alias Invoke-WinSecOpenPortsQuery Invoke-WinSecOpenPortsFixtureQuery -Scope Script
    $production=Get-WinSecCheckRegistry $sandbox
    Test-SmbIntegration 'Production registry enables SMB after native validation and keeps seven checks disabled' {
        $check=@($production.Checks|Where-Object CheckId -CEQ WSA-NET-002)[0]
        Assert-SmbIntegration ($check.ExecutionEnabled -and $check.ExecutionReady -and $check.ImplementationStatus -ceq 'VALIDATED' -and
            @($production.Checks|Where-Object {-not $_.ExecutionEnabled}).Count -eq 7)
    }
    Initialize-WinSecSmbFixture
    Initialize-WinSecFirewallFixture
    Initialize-WinSecRdpFixture
    Initialize-WinSecOpenPortsFixture
    $null=Register-WinSecLocalDevice $sandbox;$target=New-WinSecLocalTarget
    $c=New-WinSecScanCoordinator $sandbox;$c.Registry=[pscustomobject]@{schemaVersion='1.0.0';targets=@($target)}
    $c.AssessmentEnabled=$true;$c.PublicHistoryEnabled=$true;$c.TechnicalReportsEnabled=$true
    $confirmation={
        param($request)
        $section=($request.ScopeType -ceq 'SECTION')
        $ids=if($section){'WSA-NET-001|WSA-NET-002|WSA-NET-003|WSA-NET-004'}else{'WSA-NET-002'}
        $schema=if($section){'3.0.0'}else{'2.0.0'}
        Assert-SmbIntegration ($request.ReadOnly -and (($request.Checks.CheckId|Sort-Object) -join '|') -ceq $ids -and
            $request.TechnicalReports.SchemaVersion -ceq $schema)
        $true
    }
    Test-SmbIntegration 'Device confirmation lists exactly seven validated controls and cancels without providers' {
        $r=Invoke-WinSecCoordinatedScan $c -DeviceId $target.DeviceId -ScanId cancelled-device -ScopeType DEVICE -ScopeKey ALL -ConfirmAction {
            param($request)
            Assert-SmbIntegration ($request.ReadOnly -and (($request.Checks.CheckId|Sort-Object) -join '|') -ceq
                'WSA-NET-001|WSA-NET-002|WSA-NET-003|WSA-NET-004|WSA-SYS-001|WSA-SYS-002|WSA-SYS-003')
            $false
        }
        Assert-SmbIntegration ($null -eq $r -and $SmbCalls.Count -eq 0 -and $FirewallCalls.Count -eq 0 -and $RdpCalls.Count -eq 0 -and $PortsCalls.Count -eq 0 -and $c.Sessions.Count -eq 0)
    }
    Test-SmbIntegration 'Opening the coordinator and cancelling confirmation performs no collection or writes' {
        Assert-SmbIntegration ((Get-WinSecScanAction $c $target.DeviceId CONTROL WSA-NET-002) -ceq 'Scan')
        $r=Invoke-WinSecCoordinatedScan $c -DeviceId $target.DeviceId -ScanId cancelled -ScopeType CONTROL -ScopeKey WSA-NET-002 -ConfirmAction {$false}
        Assert-SmbIntegration ($null -eq $r -and $SmbCalls.Count -eq 0 -and $c.Sessions.Count -eq 0 -and -not (Test-Path (Join-Path $sandbox 'reports/exports')))
    }
    Test-SmbIntegration 'Confirmed control scan saves all normalized readings and immutable public history' {
        $public=Invoke-WinSecCoordinatedScan $c -DeviceId $target.DeviceId -ScanId smb-control -ScopeType CONTROL -ScopeKey WSA-NET-002 `
            -AssessmentProfile WSA-W11-23H2-PRO-DEF-BASE -ConfirmAction $confirmation -ProgressCallback {param($event);$script:SmbEvents.Add($event)}
        Assert-SmbIntegration ($public.ExecutionStatus -ceq 'COMPLETED' -and $null -eq $public.ConfigurationAssessment -and $null -eq $public.OverallScore -and
            @($public.ControlResults|Where-Object Status -CNE NOT_SELECTED).Count -eq 1 -and $c.LastTechnicalReports.Status -ceq 'SAVED' -and $c.LastTechnicalReports.Files.Count -eq 1)
        $r=Read-WinSecTechnicalReport $sandbox $target.DeviceId smb-control WSA-NET-002
        Assert-SmbIntegration ($r.Rows.Count -eq @(Get-WinSecSmbTechnicalDefinitions).Count -and $r.SectionKey -ceq 'NetworkSecurity' -and
            $r.ObservedOSRelease -ceq 'Windows 11 10.0.22631' -and
            (Get-Content $c.LastTechnicalReports.Files[0].Path -Raw) -notmatch 'PRIVATE-|NOT_SCORED|/100' -and
            (Get-WinSecScanAction $c $target.DeviceId CONTROL WSA-NET-002) -ceq 'Rescan' -and
            (Get-WinSecScanAction $c $target.DeviceId SECTION NetworkSecurity) -ceq 'Scan')
    }
    Test-SmbIntegration 'Cancelling a running rescan preserves the previous session and technical file' {
        $script:SmbCalls.Clear();$before=@(Get-ChildItem (Join-Path $sandbox 'reports/exports') -Recurse -File).Count
        $r=Invoke-WinSecCoordinatedScan $c -DeviceId $target.DeviceId -ScanId cancelled-running -ScopeType CONTROL -ScopeKey WSA-NET-002 `
            -ConfirmAction $confirmation -CancellationAction {return ($script:SmbCalls.Count -ge 2)}
        Assert-SmbIntegration ($null -eq $r -and $c.Sessions.Count -eq 1 -and $SmbCalls.Count -eq 2 -and
            @(Get-ChildItem (Join-Path $sandbox 'reports/exports') -Recurse -File).Count -eq $before)
    }
    Test-SmbIntegration 'Network Security scans four validated controls and saves four independent technical files' {
        $r=Invoke-WinSecCoordinatedScan $c -DeviceId $target.DeviceId -ScanId smb-section -ScopeType SECTION -ScopeKey NetworkSecurity `
            -AssessmentProfile WSA-W11-23H2-PRO-DEF-BASE -ConfirmAction $confirmation
        Assert-SmbIntegration ($r.ExecutionStatus -ceq 'COMPLETED' -and $r.ScopeType -ceq 'SECTION' -and $c.LastTechnicalReports.Files.Count -eq 4 -and
            (($c.LastTechnicalReports.Files.CheckId|Sort-Object) -join '|') -ceq 'WSA-NET-001|WSA-NET-002|WSA-NET-003|WSA-NET-004' -and $FirewallCalls.Count -eq 25 -and $PortsCalls.Count -eq 3 -and
            $RdpCalls.Count -eq (9+@(Get-WinSecRdpRegistryDefinitions).Count) -and
            (Get-WinSecScanAction $c $target.DeviceId SECTION NetworkSecurity) -ceq 'Rescan')
    }
    Test-SmbIntegration 'Restored F chooses a framework and P exports that same view without more Windows reads' {
        $restored=New-WinSecScanCoordinator $sandbox;$restored.Registry=$c.Registry
        $state=New-WinSecNavigationState;$state.Screen='Section';$state.SelectedDeviceId=$target.DeviceId
        $sections=@(Get-WinSecMainMenuSections);for($i=0;$i -lt $sections.Count;$i++){if($sections[$i].Key -ceq 'NetworkSecurity'){$state.SectionIndex=$i}}
        $state.ControlIndex=1
        $ctx=[pscustomobject]@{ProjectRoot=$sandbox;ScanCoordinator=$restored;Devices=@([pscustomobject]@{DeviceId=$target.DeviceId;Hostname='SYNTHETIC-SMB';DisplayName='SYNTHETIC-SMB'});
            PublicScans=@{};ActiveScanByDevice=@{};ActiveScanByScope=@{};LocalDeviceId=$target.DeviceId;FrameworkWorkflowEnabled=$true;LastExportMessage=''}
        $null=Restore-WinSecPublicHistory -Context $ctx;$calls=$SmbCalls.Count;$fwCalls=$FirewallCalls.Count;$rdpReads=$RdpCalls.Count;$portsReads=$PortsCalls.Count
        function Show-WinSecExportFrameworkSelection {param($Selection,[switch]$ForFindings);[pscustomobject]@{Confirmed=$true;FrameworkId='mitre-attack'}}
        Assert-SmbIntegration (Invoke-WinSecCLIFrameworkFindings $state $ctx)
        $state.Screen='Findings';$state.FindingsScope='Control';$artifact=Export-WinSecCLIFrameworkFindings $state $ctx
        Assert-SmbIntegration ($artifact.Path.EndsWith('.md') -and $ctx.FrameworkFindings.FrameworkId -ceq 'mitre-attack' -and
            $ctx.FrameworkFindings.Rows.Count -eq 4 -and $ctx.FrameworkFindings.Sources[0].Origin -ceq 'RECORDS' -and
            $SmbCalls.Count -eq $calls -and $FirewallCalls.Count -eq $fwCalls -and $RdpCalls.Count -eq $rdpReads -and $PortsCalls.Count -eq $portsReads)
    }
    Test-SmbIntegration 'Detailed SMB progress fits a small or resized terminal and never invokes a provider' {
        $script:rendered=New-Object 'Collections.Generic.List[string]'
        function Write-Host {param([object[]]$Object,$ForegroundColor,$BackgroundColor,[switch]$NoNewline);$script:rendered.Add(($Object -join ' '))}
        function Clear-WinSecScreen {$script:rendered.Clear()}
        function Get-WinSecTerminalSize {$script:smbTerminal}
        $event=@($SmbEvents|Where-Object SchemaVersion -CEQ '2.0.0')[0];$calls=$SmbCalls.Count
        $display=New-WinSecScanProgressState $target.DeviceId 'SMBv1' Scan
        foreach($width in @(120,40,80)){
            $script:smbTerminal=[pscustomobject]@{Width=$width;ContentWidth=($width-1);Height=12}
            Show-WinSecScanProgress $display $event
            Assert-SmbIntegration (@($rendered|Where-Object {$_.Length -gt ($width-1)}).Count -eq 0 -and ($rendered -join '|').Contains('SMBv1:'))
        }
        Assert-SmbIntegration ($SmbCalls.Count -eq $calls)
    }
} finally {
    $env:COMPUTERNAME=$oldHostname
    Assert-SmbIntegration ((Get-FileHash (Join-Path $sourceRoot 'config/checks.json')).Hash -ceq $checksHash)
    $absolute=[IO.Path]::GetFullPath($sandbox)
    if([IO.Path]::GetDirectoryName($absolute) -cne $tempParent -or [IO.Path]::GetFileName($absolute) -cnotmatch '\AWinSec-Smb-[a-f0-9]{32}\z'){throw 'Unsafe SMB fixture cleanup.'}
    Remove-Item -LiteralPath $absolute -Recurse -Force
}
[Console]::WriteLine('SMB integration: '+$passed+' passed; '+$failed+' failed.');if($failed){throw 'SMB integration tests failed.'}
