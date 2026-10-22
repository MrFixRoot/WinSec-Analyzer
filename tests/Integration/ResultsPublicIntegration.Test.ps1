# Core -> CLI -> Results/layout/table, with synthetic data and terminal output.
# No startup, scans, Windows queries, configuration changes or persistence.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
foreach($file in @(
    'src/Core/ResultModel.ps1','src/CLI/Invoke-WinSecCLI.ps1',
    'src/UI/Core/TerminalRenderer.ps1','src/UI/Components/Banner.ps1','src/UI/Components/Table.ps1',
    'src/UI/Components/KeyboardHelp.ps1','src/UI/Core/LayoutManager.ps1',
    'src/UI/Core/KeyboardController.ps1','src/UI/Core/NavigationController.ps1',
    'src/UI/Core/ResizeHandler.ps1','src/UI/Screens/MainMenu.ps1','src/UI/Screens/Results.ps1'
)) {. (Join-Path $root $file)}
$script:passed=0;$script:failed=0;$script:scanCalls=0;$script:renderCalls=0
$script:lines=New-Object 'System.Collections.Generic.List[string]'
$script:fragment=New-Object Text.StringBuilder
function Assert-WinSecResultsIntegration {param([bool]$Condition);if(-not $Condition){throw 'Results integration assertion failed.'}}
function Test-WinSecResultsIntegration {
    param([string]$Name,[scriptblock]$Action)
    try {$null=& $Action;$script:passed++;[Console]::WriteLine('[PASS] '+$Name)}
    catch {$script:failed++;[Console]::WriteLine('[FAIL] '+$Name+' : '+$_.Exception.Message)}
}
function Get-WinSecTerminalSize {$script:terminal}
function Clear-WinSecScreen {$script:renderCalls++;$script:lines.Clear();$null=$script:fragment.Clear()}
function Write-Host {
    param([object[]]$Object,[switch]$NoNewline,$ForegroundColor,$BackgroundColor,[string]$Separator=' ')
    $null=$script:fragment.Append(($Object -join $Separator))
    if(-not $NoNewline){$script:lines.Add($script:fragment.ToString());$null=$script:fragment.Clear()}
}
function Invoke-WinSecCoordinatedScan {$script:scanCalls++;throw 'Unexpected scan during rendering.'}
function Invoke-WinSecAudit {$script:scanCalls++;throw 'Unexpected collector during rendering.'}
function Set-WinSecResultsTestTerminal {
    param([int]$Width,[int]$Height)
    $script:terminal=[pscustomobject]@{Width=$Width;Height=$Height;ContentWidth=$Width-1}
}
$catalog=Get-Content -LiteralPath (Join-Path $root 'config/checks.json') -Raw|ConvertFrom-Json
$enabled=@($catalog.checks|Where-Object {$_.execution.enabled -eq $true})
if($enabled.Count -ne 1 -or $enabled[0].checkId -cne 'WSA-SYS-001' -or $enabled[0].implementationStatus -cne 'VALIDATED'){throw 'Only validated Defender may be enabled in production.'}
$deviceId='local:RESULTS-PUBLIC';$scanId='results-public-1'
$collectors=@(foreach($check in $catalog.checks){
    $status=switch($check.checkId){'WSA-SYS-001'{'INFORMATIONAL'};'WSA-SYS-002'{'ERROR'};default{'NOT_SELECTED'}}
    [pscustomobject]@{
        DeviceId=$deviceId;ScanId=$scanId;CheckId=$check.checkId;SectionKey=$check.sectionKey
        Status=$status;ObservedStatus=$status;Evidence=@{SyntheticValue='SYNTHETIC-RESULTS-PRIVATE'}
    }
})
$session=New-WinSecResultSession -DeviceId $deviceId -ScanId $scanId -ControlResults $collectors `
    -ExpectedCheckIds @('WSA-SYS-001','WSA-SYS-002') -ExecutionStatus COMPLETED_WITH_ERRORS `
    -StartedAtUTC '2026-01-01T00:00:00Z' -CompletedAtUTC '2026-01-01T00:01:00Z'
$public=ConvertTo-WinSecPublicScanResult -Session $session
$key='{0}:{1}{2}:{3}' -f $deviceId.Length,$deviceId,$scanId.Length,$scanId
$state=New-WinSecNavigationState
$state.Screen='Section';$state.SelectedDeviceId=$deviceId;$state.SelectedDeviceName='Synthetic results device';$state.ControlIndex=1
$context=[pscustomobject]@{Version='0.9.0';ActiveScanByDevice=@{$deviceId=$scanId};PublicScans=@{$key=$public}}
$before=ConvertTo-Json -InputObject @($state,$context,$session) -Depth 25 -Compress

Test-WinSecResultsIntegration 'CheckId-only Core records preserve collected error and unselected states' {
    $assessment=Get-WinSecCLIActiveAssessment -State $state -Context $context
    $rows=@(Get-WinSecSectionControls -SectionKey SystemSecurity -ControlResults $assessment.ControlResults)
    Assert-WinSecResultsIntegration ($rows.Count -eq 3 -and $rows[0].Status -ceq 'INFORMATIONAL' -and
        $rows[1].Status -ceq 'ERROR' -and $rows[2].Status -ceq 'NOT_SELECTED' -and
        $rows[1].ObservedStatus -ceq 'ERROR' -and @($rows|Where-Object{$_.Score -cne 'NOT_SCORED'}).Count -eq 0)
}
Test-WinSecResultsIntegration 'All five sections retain catalog counts and public identities' {
    $assessment=Get-WinSecCLIActiveAssessment -State $state -Context $context
    foreach($section in $catalog.sections){
        $rows=@(Get-WinSecSectionControls -SectionKey $section.key -ControlResults $assessment.ControlResults)
        $expected=@($catalog.checks|Where-Object{$_.sectionKey -ceq $section.key -and $_.visible})
        Assert-WinSecResultsIntegration ($rows.Count -eq $expected.Count -and
            @($rows|Where-Object{$_.SectionKey -cne $section.key -or [string]::IsNullOrWhiteSpace($_.CheckId)}).Count -eq 0)
    }
}
foreach($size in @(@{Width=120;Height=45},@{Width=80;Height=26},@{Width=40;Height=20})) {
    Test-WinSecResultsIntegration ('Results render safely within simulated size '+$size.Width+'x'+$size.Height) {
        Set-WinSecResultsTestTerminal -Width $size.Width -Height $size.Height
        Show-WinSecCLICurrentScreen -State $state -Context $context
        $text=$script:lines -join "`n"
        Assert-WinSecResultsIntegration ($text -match 'SECTION SCORE: NOT_SCORED' -and
            $text -notmatch '\d+/100|--/100|SYNTHETIC-RESULTS-PRIVATE' -and
            $script:lines.Count -le $script:terminal.Height -and
            @($script:lines|Where-Object{$_.Length -gt $script:terminal.ContentWidth}).Count -eq 0 -and
            $script:scanCalls -eq 0 -and $before -ceq (ConvertTo-Json -InputObject @($state,$context,$session) -Depth 25 -Compress))
    }
}
Test-WinSecResultsIntegration 'Too-small terminal shows guidance without altering the assessment' {
    Set-WinSecResultsTestTerminal -Width 38 -Height 18
    Show-WinSecCLICurrentScreen -State $state -Context $context
    Assert-WinSecResultsIntegration (($script:lines -join '|') -match 'Terminal window is too small' -and
        ($script:lines -join '|') -notmatch 'SECTION SCORE|SYNTHETIC-RESULTS-PRIVATE' -and $script:scanCalls -eq 0 -and
        $before -ceq (ConvertTo-Json -InputObject @($state,$context,$session) -Depth 25 -Compress))
}
Test-WinSecResultsIntegration 'Resize redraws once while preserving device scan and selected control' {
    Set-WinSecResultsTestTerminal -Width 40 -Height 20
    $resize=New-WinSecResizeState
    Set-WinSecResultsTestTerminal -Width 80 -Height 26
    $renders=$script:renderCalls
    $render={param($State);Show-WinSecCLICurrentScreen -State $State -Context $context}
    $first=Invoke-WinSecResizeHandler -ResizeState $resize -NavigationState $state -RenderAction $render
    $second=Invoke-WinSecResizeHandler -ResizeState $resize -NavigationState $state -RenderAction $render
    Assert-WinSecResultsIntegration ($first -and -not $second -and $script:renderCalls -eq ($renders+1) -and
        $before -ceq (ConvertTo-Json -InputObject @($state,$context,$session) -Depth 25 -Compress) -and $script:scanCalls -eq 0)
}
Test-WinSecResultsIntegration 'Findings navigation and Escape retain the selected control and session' {
    $counts=Get-WinSecCLINavigationCounts -State $state -Context $context
    $keyInfo=[pscustomobject]@{VirtualKeyCode=70;Character=[char]'F';ControlKeyState=0;KeyDown=$true}
    $action=ConvertTo-WinSecKeyboardAction -KeyInfo $keyInfo -Screen Section
    $null=Invoke-WinSecNavigationAction -State $state -Action $action -ControlCount $counts.ControlCount
    Assert-WinSecResultsIntegration ($state.Screen -ceq 'Findings' -and $state.ControlIndex -eq 1)
    $null=Invoke-WinSecNavigationAction -State $state -Action Back
    Assert-WinSecResultsIntegration ($state.Screen -ceq 'Section' -and $state.ControlIndex -eq 1 -and
        $context.ActiveScanByDevice[$deviceId] -ceq $scanId -and $script:scanCalls -eq 0)
}
Test-WinSecResultsIntegration 'Ambiguous direct input rejects before clearing or publishing screen content' {
    $renders=$script:renderCalls;$script:lines.Clear();$caught=$null
    try {Show-WinSecResults -NavigationState $state -ControlResults @(@{CheckId='WSA-SYS-001';Key='BitLocker'})}
    catch {$caught=$_}
    Assert-WinSecResultsIntegration ($null -ne $caught -and $script:renderCalls -eq $renders -and $script:lines.Count -eq 0)
}
[Console]::WriteLine('Passed: '+$script:passed)
[Console]::WriteLine('Failed: '+$script:failed)
if($script:failed -gt 0){throw "$script:failed Results integration test(s) failed."}
