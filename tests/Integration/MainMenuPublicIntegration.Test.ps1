# Core -> CLI -> real MainMenu/layout/table, with simulated terminal output.
# Synthetic sessions only; no startup, scans, Windows queries or persistence.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
foreach($file in @(
    'src/Core/ScoreEngine.ps1','src/Core/ResultModel.ps1','src/Core/ScanCoordinator.ps1','src/CLI/Invoke-WinSecCLI.ps1',
    'src/UI/Core/TerminalRenderer.ps1','src/UI/Components/Banner.ps1','src/UI/Components/Table.ps1',
    'src/UI/Components/KeyboardHelp.ps1','src/UI/Core/LayoutManager.ps1',
    'src/UI/Core/NavigationController.ps1','src/UI/Core/ResizeHandler.ps1','src/UI/Screens/MainMenu.ps1'
)) {. (Join-Path $root $file)}
$script:passed=0; $script:failed=0; $script:scanCalls=0; $script:renderCalls=0
$script:lines=New-Object 'System.Collections.Generic.List[string]'
$script:fragment=New-Object Text.StringBuilder
function Assert-WinSecMenuIntegration {param([bool]$Condition); if(-not $Condition){throw 'MainMenu integration assertion failed.'}}
function Test-WinSecMenuIntegration {
    param([string]$Name,[scriptblock]$Action)
    try {$null=& $Action; $script:passed++; [Console]::WriteLine('[PASS] '+$Name)}
    catch {$script:failed++; [Console]::WriteLine('[FAIL] '+$Name+' : '+$_.Exception.Message)}
}
function Get-WinSecTerminalSize { $script:terminal }
function Clear-WinSecScreen {$script:renderCalls++; $script:lines.Clear(); $null=$script:fragment.Clear()}
function Write-Host {
    param([object[]]$Object,[switch]$NoNewline,$ForegroundColor,$BackgroundColor,[string]$Separator=' ')
    $null=$script:fragment.Append(($Object -join $Separator))
    if(-not $NoNewline){$script:lines.Add($script:fragment.ToString()); $null=$script:fragment.Clear()}
}
function Invoke-WinSecCoordinatedScan {$script:scanCalls++; throw 'Unexpected scan during rendering.'}
function Invoke-WinSecAudit {$script:scanCalls++; throw 'Unexpected collector during rendering.'}
function Set-WinSecMenuTestTerminal {
    param([int]$Width,[int]$Height)
    $script:terminal=[pscustomobject]@{Width=$Width;Height=$Height;ContentWidth=$Width-1}
}

$policy=Get-Content -LiteralPath (Join-Path $root 'config/scoring.json') -Raw | ConvertFrom-Json
if($policy.enabled -cne $false -or $policy.activationStatus -cne 'PENDING_APPROVED_CRITERIA') {
    throw 'Production scoring must remain disabled.'
}
$deviceId='local:MENU-PUBLIC'; $scanId='menu-public-1'
$control=[pscustomobject]@{
    DeviceId=$deviceId;ScanId=$scanId;CheckId='WSA-SYS-001';SectionKey='SystemSecurity'
    Status='INFORMATIONAL';Evidence=@{SyntheticValue='SYNTHETIC-MENU-PRIVATE'}
}
$session=New-WinSecResultSession -DeviceId $deviceId -ScanId $scanId -ControlResults @($control) `
    -ExpectedCheckIds @($control.CheckId) -ScoringPolicy $policy
$public=ConvertTo-WinSecPublicScanResult -Session $session
$key='{0}:{1}{2}:{3}' -f $deviceId.Length,$deviceId,$scanId.Length,$scanId
$state=New-WinSecNavigationState
$state.Screen='MainMenu'; $state.SelectedDeviceId=$deviceId; $state.SelectedDeviceName='Synthetic menu device'; $state.SectionIndex=2
$context=[pscustomobject]@{
    Version='0.9.0';Devices=@();ScanCoordinator=$null
    ActiveScanByDevice=@{$deviceId=$scanId};PublicScans=@{$key=$public}
}
$before=ConvertTo-Json -InputObject @($state,$context,$session) -Depth 25 -Compress

Test-WinSecMenuIntegration 'Real unscored ResultModel sections reach the matching CLI/menu' {
    $assessment=Get-WinSecCLIActiveAssessment -State $state -Context $context
    $rows=@(Get-WinSecMainMenuSections -SectionResults $assessment.SectionResults)
    Assert-WinSecMenuIntegration ($public.SectionResults.Count -eq 5 -and $rows.Count -eq 5 -and
        @($rows|Where-Object{$_.Score -cne 'NOT_SCORED' -or $_.Status -cne 'NOT_SCORED'}).Count -eq 0)
}
foreach($size in @(@{Width=120;Height=45},@{Width=80;Height=26},@{Width=40;Height=20})) {
    Test-WinSecMenuIntegration ('Public results render within simulated width '+$size.Width) {
        Set-WinSecMenuTestTerminal -Width $size.Width -Height $size.Height
        Show-WinSecCLICurrentScreen -State $state -Context $context
        $text=$script:lines -join "`n"
        Assert-WinSecMenuIntegration ($text -match 'SECURITY SCORE: NOT_SCORED' -and
            $text -notmatch '\d+/100|--/100|SYNTHETIC-MENU-PRIVATE' -and
            $script:lines.Count -le $script:terminal.Height -and
            @($script:lines|Where-Object{$_.Length -gt $script:terminal.ContentWidth}).Count -eq 0 -and
            $script:scanCalls -eq 0 -and
            $before -ceq (ConvertTo-Json -InputObject @($state,$context,$session) -Depth 25 -Compress))
    }
}
Test-WinSecMenuIntegration 'Before any scan the dashboard stays pending and explicitly unscored' {
    Set-WinSecMenuTestTerminal -Width 80 -Height 26
    Show-WinSecMainMenu -NavigationState $state
    $text=$script:lines -join '|'
    Assert-WinSecMenuIntegration ($text -match 'SECURITY SCORE: NOT_SCORED' -and
        $text -match 'STATUS: PENDING' -and $text -notmatch '\d+/100|--/100' -and $script:scanCalls -eq 0)
}
Test-WinSecMenuIntegration 'An enabled scan shortcut only renders and does not execute' {
    Set-WinSecMenuTestTerminal -Width 80 -Height 26
    Show-WinSecMainMenu -NavigationState $state -SectionResults $public.SectionResults `
        -OverallStatus NOT_SCORED -EnableRescan
    Assert-WinSecMenuIntegration (($script:lines -join '|') -match '\[R\] Scan Local Device' -and
        $script:lines.Count -le $script:terminal.Height -and $script:scanCalls -eq 0 -and
        $before -ceq (ConvertTo-Json -InputObject @($state,$context,$session) -Depth 25 -Compress))
}
Test-WinSecMenuIntegration 'Too-small terminal shows resize guidance without scans or data mutation' {
    Set-WinSecMenuTestTerminal -Width 38 -Height 15
    Show-WinSecCLICurrentScreen -State $state -Context $context
    Assert-WinSecMenuIntegration (($script:lines -join '|') -match 'Terminal window is too small' -and
        ($script:lines -join '|') -notmatch 'SECURITY SCORE|SYNTHETIC-MENU-PRIVATE' -and $script:scanCalls -eq 0 -and
        $before -ceq (ConvertTo-Json -InputObject @($state,$context,$session) -Depth 25 -Compress))
}
Test-WinSecMenuIntegration 'Resize redraws once and preserves device session and selection' {
    Set-WinSecMenuTestTerminal -Width 40 -Height 20
    $resize=New-WinSecResizeState
    Set-WinSecMenuTestTerminal -Width 80 -Height 26
    $renders=$script:renderCalls
    $render={param($State); Show-WinSecCLICurrentScreen -State $State -Context $context}
    $first=Invoke-WinSecResizeHandler -ResizeState $resize -NavigationState $state -RenderAction $render
    $second=Invoke-WinSecResizeHandler -ResizeState $resize -NavigationState $state -RenderAction $render
    Assert-WinSecMenuIntegration ($first -and -not $second -and $script:renderCalls -eq ($renders+1) -and
        $script:scanCalls -eq 0 -and $before -ceq (ConvertTo-Json -InputObject @($state,$context,$session) -Depth 25 -Compress))
}
Test-WinSecMenuIntegration 'Section navigation and back preserve the public assessment' {
    $null=Invoke-WinSecNavigationAction -State $state -Action Open -SectionCount 5
    Assert-WinSecMenuIntegration ($state.Screen -ceq 'Section' -and $state.SectionIndex -eq 2)
    $null=Invoke-WinSecNavigationAction -State $state -Action Back
    Assert-WinSecMenuIntegration ($state.Screen -ceq 'MainMenu' -and $state.SectionIndex -eq 2 -and
        $context.ActiveScanByDevice[$deviceId] -ceq $scanId -and $script:scanCalls -eq 0)
}
Test-WinSecMenuIntegration 'Invalid direct input is rejected before any screen output' {
    $renders=$script:renderCalls; $script:lines.Clear()
    $caught=$null
    try {Show-WinSecMainMenu -NavigationState $state -OverallScore 100 -OverallStatus PASS} catch {$caught=$_}
    Assert-WinSecMenuIntegration ($null -ne $caught -and $script:lines.Count -eq 0 -and $script:renderCalls -eq $renders)
}
Test-WinSecMenuIntegration 'CLI renders Scan or Rescan from coordinator scope history without a duplicate shortcut' {
    $originalEligibility=(Get-Command Test-WinSecCLIRescanEligibility).ScriptBlock
    $oldCoordinator=$context.ScanCoordinator
    try {
        function Test-WinSecCLIRescanEligibility {$true}
        $coordinator=[pscustomobject]@{Component='ScanCoordinator';SchemaVersion='1.0.0';ProjectRoot=$root;
            Registry=[pscustomobject]@{schemaVersion='1.0.0';targets=@()};Sessions=@{};
            ParallelExecution=$false;RemoteExecution=$false;AutomaticEvidencePersistence=$false;ScoringEnabled=$false}
        $context.ScanCoordinator=$coordinator
        Set-WinSecMenuTestTerminal -Width 80 -Height 26
        Show-WinSecCLICurrentScreen -State $state -Context $context
        Assert-WinSecMenuIntegration (($script:lines -join '|') -match '\[R\] Scan Local Device' -and
            ($script:lines -join '|') -notmatch '\[R\] Rescan')
        $scoped=New-WinSecResultSession -DeviceId $deviceId -ScanId $scanId -ControlResults $session.ControlResults `
            -ExpectedCheckIds $session.ExpectedCheckIds -ScopeType DEVICE -ScopeKey ALL -ExecutionStatus COMPLETED `
            -StartedAtUTC '2026-10-20T00:00:00Z' -CompletedAtUTC '2026-10-20T00:01:00Z'
        $coordinator.Sessions[(Get-WinSecScanSessionKey $deviceId $scanId)]=[pscustomobject]@{
            DeviceId=$deviceId;ScanId=$scanId;Session=$scoped;EvidenceStorage=[pscustomobject]@{
                DeviceId=$deviceId;ScanId=$scanId;Status='NOT_REQUESTED';StoredCount=0;FailedCount=0;SkippedCount=0}}
        Show-WinSecCLICurrentScreen -State $state -Context $context
        Assert-WinSecMenuIntegration (($script:lines -join '|') -match '\[R\] Rescan Local Device' -and
            @($script:lines|Where-Object{$_ -match '\[R\]'}).Count -eq 1 -and $script:scanCalls -eq 0)
        $scoped.ScopeKey='CHANGED'
        Show-WinSecCLICurrentScreen -State $state -Context $context
        Assert-WinSecMenuIntegration (($script:lines -join '|') -match '\[R\] Scan \(unavailable\)' -and $script:scanCalls -eq 0)
    }
    finally {
        $context.ScanCoordinator=$oldCoordinator
        Set-Item -Path Function:Test-WinSecCLIRescanEligibility -Value $originalEligibility
    }
}
[Console]::WriteLine('Passed: '+$script:passed)
[Console]::WriteLine('Failed: '+$script:failed)
if($script:failed -gt 0){throw "$script:failed MainMenu integration test(s) failed."}
