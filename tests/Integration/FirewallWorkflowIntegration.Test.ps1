# Real coordinator, history and Markdown I/O in an owned disposable installation.
# All OS and Firewall providers are synthetic. Production permissions are untouched.
[CmdletBinding()]param()
$ErrorActionPreference='Stop'
$sourceRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$tempParent=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\','/')
$sandbox=[IO.Path]::GetFullPath((Join-Path $tempParent ('WinSec-Firewall-'+[guid]::NewGuid().ToString('N'))))
$null=[IO.Directory]::CreateDirectory($sandbox)
$savedHostname=$env:COMPUTERNAME;$env:COMPUTERNAME='SYNTHETIC-FW'
$checksHash=(Get-FileHash -LiteralPath (Join-Path $sourceRoot 'config/checks.json')).Hash
$script:passed=0;$script:failed=0
function Assert-FWIntegration {param([bool]$Value);if(-not $Value){throw 'Firewall integration assertion failed.'}}
function Test-FWIntegration {param($Name,[scriptblock]$Action);try{$null=& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}catch{$script:failed++;Write-Host ('[FAIL] '+$Name+' : '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}
try {
    foreach($directory in @('src','config')){Copy-Item -LiteralPath (Join-Path $sourceRoot $directory) -Destination (Join-Path $sandbox $directory) -Recurse}
    . (Join-Path $sandbox 'src/Core/ScanCoordinator.ps1')
    . (Join-Path $sandbox 'src/CLI/Invoke-WinSecCLI.ps1')
    . (Join-Path $sandbox 'src/UI/Core/NavigationController.ps1')
    . (Join-Path $sandbox 'src/UI/Screens/MainMenu.ps1')
    . (Join-Path $sandbox 'src/UI/Screens/Results.ps1')
    . (Join-Path $sandbox 'src/CLI/FrameworkWorkflow.ps1')
    . (Join-Path $sourceRoot 'tests/Fixtures/FirewallMemory.ps1')
    function Get-WinSecFirewallFixtureHardware {'local:hw1-'+('b'*64)}
    Set-Alias Get-WinSecLocalHardwareDeviceId Get-WinSecFirewallFixtureHardware -Scope Script
    Set-Alias Get-CimInstance Get-WinSecFirewallFixtureCim -Scope Script
    Set-Alias Invoke-WinSecFirewallQuery Invoke-WinSecFirewallFixtureQuery -Scope Script
    Initialize-WinSecFirewallFixture
    $null=Register-WinSecLocalDevice -ProjectRoot $sandbox
    $c=New-WinSecScanCoordinator $sandbox;$target=New-WinSecLocalTarget
    $c.Registry=[pscustomobject]@{schemaVersion='1.0.0';targets=@($target)}
    $c.AssessmentEnabled=$true;$c.PublicHistoryEnabled=$true;$c.TechnicalReportsEnabled=$true
    Test-FWIntegration 'Production registry enables only the four individually validated controls' {
        $registry=Get-WinSecCheckRegistry $sandbox
        $ready=@(Get-WinSecExecutableChecks -Registry $registry)
        Assert-FWIntegration ((($ready.CheckId|Sort-Object) -join '|') -ceq 'WSA-NET-001|WSA-SYS-001|WSA-SYS-002|WSA-SYS-003' -and
            @($registry.Checks|Where-Object {-not $_.ExecutionEnabled}).Count -eq 10 -and $FirewallCalls.Count -eq 0)
    }
    Test-FWIntegration 'Device confirmation lists all four enabled controls and cancellation makes no queries' {
        $r=Invoke-WinSecCoordinatedScan $c -DeviceId $target.DeviceId -ScanId 'cancelled-device' -ScopeType DEVICE -ScopeKey ALL -ConfirmAction {
            param($request)
            Assert-FWIntegration ($request.ReadOnly -and (($request.Checks.CheckId|Sort-Object) -join '|') -ceq
                'WSA-NET-001|WSA-SYS-001|WSA-SYS-002|WSA-SYS-003')
            $false
        }
        Assert-FWIntegration ($null -eq $r -and $c.Sessions.Count -eq 0 -and $FirewallCalls.Count -eq 0)
    }
    $script:allowScan=$true
    $confirmation={param($request);Assert-FWIntegration ($request.ReadOnly -and $request.Checks.Count -eq 1 -and $request.Checks[0].CheckId -ceq 'WSA-NET-001' -and
        $request.TechnicalReports.SchemaVersion -ceq '3.0.0');return $script:allowScan}
    Test-FWIntegration 'Cancellation at confirmation publishes no session, file or provider query' {
        $script:allowScan=$false
        $r=Invoke-WinSecCoordinatedScan $c -DeviceId $target.DeviceId -ScanId 'cancelled-fw' -ScopeType CONTROL -ScopeKey WSA-NET-001 -ConfirmAction $confirmation
        Assert-FWIntegration ($null -eq $r -and $c.Sessions.Count -eq 0 -and $FirewallCalls.Count -eq 0 -and -not (Test-Path -LiteralPath (Join-Path $sandbox 'reports/exports')))
        $script:allowScan=$true
    }
    Test-FWIntegration 'Confirmed control scan runs only Firewall and saves technical Markdown and public history' {
        $script:FirewallLocalPort='135-139,443'
        $script:public=Invoke-WinSecCoordinatedScan $c -DeviceId $target.DeviceId -ScanId 'firewall-control' -ScopeType CONTROL -ScopeKey WSA-NET-001 `
            -AssessmentProfile WSA-W11-23H2-PRO-DEF-BASE -ConfirmAction $confirmation -ProgressCallback {param($e);$script:FirewallEvents.Add($e)}
        Assert-FWIntegration ($null -ne $public -and $c.Sessions.Count -eq 1 -and $c.LastTechnicalReports.Status -ceq 'SAVED' -and $c.LastTechnicalReports.Files.Count -eq 1)
        Assert-FWIntegration (@($public.ControlResults|Where-Object {$_.Status -cne 'NOT_SELECTED' -and $_.CheckId -cne 'WSA-NET-001'}).Count -eq 0 -and $null -eq $public.ConfigurationAssessment)
        $script:report=Read-WinSecTechnicalReport $sandbox $target.DeviceId 'firewall-control' WSA-NET-001
        Assert-FWIntegration ($report.CheckId -ceq 'WSA-NET-001' -and $report.SectionKey -ceq 'NetworkSecurity' -and $report.ObservedOSRelease -ceq 'Windows 11 10.0.22631')
        $ports=ConvertTo-WinSecFirewallBatch @($report.Rows|Where-Object SettingId -CEQ Inventory.ACTIVE.0001)[0].Value
        Assert-FWIntegration ($ports[0].LocalPort -ceq '135-139,443')
        $raw=Get-Content -LiteralPath $c.LastTechnicalReports.Files[0].Path -Raw -Encoding UTF8
        Assert-FWIntegration ($raw -notmatch 'PRIVATE-|NOT_SCORED|/100' -and @($FirewallEvents|Where-Object SchemaVersion -CEQ '2.0.0').Count -ge 28)
        $script:FirewallLocalPort='Any'
    }
    Test-FWIntegration 'Cancellation during collection preserves the completed control and files' {
        $before=@(Get-ChildItem -LiteralPath (Join-Path $sandbox 'reports/exports') -Recurse -File).Count
        $script:FirewallCalls.Clear()
        $r=Invoke-WinSecCoordinatedScan $c -DeviceId $target.DeviceId -ScanId 'cancel-running' -ScopeType CONTROL -ScopeKey WSA-NET-001 -ConfirmAction $confirmation `
            -CancellationAction {return ($script:FirewallCalls.Count -ge 3)}
        Assert-FWIntegration ($null -eq $r -and $c.Sessions.Count -eq 1 -and $FirewallCalls.Count -lt 25 -and
            @(Get-ChildItem -LiteralPath (Join-Path $sandbox 'reports/exports') -Recurse -File).Count -eq $before)
    }
    Test-FWIntegration 'Section scan saves its own source identity without running SMB, RDP or System Security' {
        $r=Invoke-WinSecCoordinatedScan $c -DeviceId $target.DeviceId -ScanId 'firewall-section' -ScopeType SECTION -ScopeKey NetworkSecurity -ConfirmAction $confirmation
        Assert-FWIntegration ($r.ScopeType -ceq 'SECTION' -and $r.ScopeKey -ceq 'NetworkSecurity' -and $c.LastTechnicalReports.Status -ceq 'SAVED')
        $r=Read-WinSecTechnicalReport $sandbox $target.DeviceId 'firewall-section' WSA-NET-001
        Assert-FWIntegration ($r.ScopeType -ceq 'SECTION' -and $r.ScopeKey -ceq 'NetworkSecurity')
    }
    Test-FWIntegration 'F uses restored public sources and saved technical data; P exports the selected framework without providers' {
        $restored=New-WinSecScanCoordinator $sandbox;$restored.Registry=$c.Registry
        $state=New-WinSecNavigationState;$state.Screen='Section';$state.SelectedDeviceId=$target.DeviceId
        $sections=@(Get-WinSecMainMenuSections);for($i=0;$i -lt $sections.Count;$i++){if($sections[$i].Key -ceq 'NetworkSecurity'){$state.SectionIndex=$i}}
        $ctx=[pscustomobject]@{ProjectRoot=$sandbox;ScanCoordinator=$restored;Devices=@([pscustomobject]@{DeviceId=$target.DeviceId;Hostname='SYNTHETIC-FW';DisplayName='SYNTHETIC-FW'});
            PublicScans=@{};ActiveScanByDevice=@{};ActiveScanByScope=@{};LocalDeviceId=$target.DeviceId;FrameworkWorkflowEnabled=$true;LastExportMessage=''}
        $null=Restore-WinSecPublicHistory -Context $ctx
        $calls=$FirewallCalls.Count
        function Show-WinSecExportFrameworkSelection {param($Selection,[switch]$ForFindings);[pscustomobject]@{Confirmed=$true;FrameworkId='nist-csf'}}
        Assert-FWIntegration (Invoke-WinSecCLIFrameworkFindings $state $ctx)
        $state.Screen='Findings';$state.FindingsScope='Control'
        $artifact=Export-WinSecCLIFrameworkFindings $state $ctx
        Assert-FWIntegration ($artifact.Path.EndsWith('.md') -and $ctx.FrameworkFindings.FrameworkId -ceq 'nist-csf' -and
            $ctx.FrameworkFindings.Rows.Count -eq 5 -and $FirewallCalls.Count -eq $calls -and $ctx.FrameworkFindings.Sources[0].Origin -ceq 'RECORDS')
    }
    Test-FWIntegration 'Large Firewall inventories roundtrip without raising public history limits' {
        . (Join-Path $sandbox 'src/Checks/Firewall/Test-Firewall.ps1')
        Initialize-WinSecFirewallFixture;$script:FirewallRuleCount=600
        $s=New-WinSecFirewallFixtureSession 'large-firewall';$r=New-WinSecTechnicalReport $s WSA-NET-001 SYNTHETIC SYNTHETIC
        $artifact=Write-WinSecTechnicalArtifact $sandbox $r
        Assert-FWIntegration ((Get-Item -LiteralPath $artifact.Path).Length -gt 1048576)
        $loaded=Read-WinSecTechnicalReport $sandbox $s.DeviceId $s.ScanId WSA-NET-001
        Assert-FWIntegration (@($loaded.Rows|Where-Object SettingId -CEQ Inventories.RulesActiveCount)[0].Value -eq 600)
        $caught=$false;try{$null=ConvertFrom-WinSecStoredJson ('{"padding":"'+('x'*1048576)+'"}')}catch{$caught=$true};Assert-FWIntegration $caught
    }
} finally {
    $env:COMPUTERNAME=$savedHostname
    Assert-FWIntegration ((Get-FileHash -LiteralPath (Join-Path $sourceRoot 'config/checks.json')).Hash -ceq $checksHash)
    $absolute=[IO.Path]::GetFullPath($sandbox)
    if([IO.Path]::GetDirectoryName($absolute) -cne $tempParent -or [IO.Path]::GetFileName($absolute) -cnotmatch '\AWinSec-Firewall-[a-f0-9]{32}\z'){throw 'Unsafe Firewall fixture cleanup.'}
    Remove-Item -LiteralPath $absolute -Recurse -Force
}
Write-Host ('Firewall integration: '+$passed+' passed; '+$failed+' failed.');if($failed){throw 'Firewall integration tests failed.'}
