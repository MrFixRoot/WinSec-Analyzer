# Evaluation/Findings/ResultModel -> CLI -> real Findings/layout/table/details.
# Collectors and terminal data are synthetic. No scans, startup or persistence.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
foreach($file in @('src/Core/EvaluationEngine.ps1','src/Core/FindingsEngine.ps1','src/Core/ResultModel.ps1',
    'src/CLI/Invoke-WinSecCLI.ps1','src/UI/Core/TerminalRenderer.ps1','src/UI/Components/Banner.ps1',
    'src/UI/Components/Table.ps1','src/UI/Components/KeyboardHelp.ps1','src/UI/Core/LayoutManager.ps1',
    'src/UI/Core/KeyboardController.ps1','src/UI/Core/NavigationController.ps1','src/UI/Core/ResizeHandler.ps1',
    'src/UI/Screens/MainMenu.ps1','src/UI/Screens/Results.ps1','src/UI/Screens/Findings.ps1')) {. (Join-Path $root $file)}
$script:passed=0;$script:failed=0;$script:scanCalls=0;$script:renderCalls=0
$script:lines=New-Object 'System.Collections.Generic.List[string]'
$script:fragment=New-Object Text.StringBuilder
function Assert-WinSecFindingIntegration {param([bool]$Condition);if(-not $Condition){throw 'Public Findings integration assertion failed.'}}
function Test-WinSecFindingIntegration {
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
function Set-WinSecFindingTestTerminal {
    param([int]$Width,[int]$Height)
    $script:terminal=[pscustomobject]@{Width=$Width;Height=$Height;ContentWidth=$Width-1}
}
$device='local:FINDINGS-PUBLIC';$scan='findings-public-1'
$collectors=@(foreach($id in @('WSA-SYS-001','WSA-SYS-002','WSA-SYS-003','WSA-NET-001')){
    [pscustomobject]@{DeviceId=$device;ScanId=$scan;CheckId=$id;
        SectionKey=if($id -like 'WSA-SYS-*'){'SystemSecurity'}else{'NetworkSecurity'};
        Status='INFORMATIONAL';ObservedStatus='INFORMATIONAL';
        Evidence=@{SyntheticValue='SYNTHETIC-FINDINGS-RAW';CollectionSuccessful=$true}}
})
$evaluations=@();$findings=@()
foreach($collector in $collectors){
    $evaluation=Invoke-WinSecControlEvaluation -ControlResult $collector
    $generated=ConvertTo-WinSecFindings -EvaluationResult $evaluation -ControlResult $collector
    $evaluations+=@($evaluation);$findings+=@($generated.Findings)
}
$session=New-WinSecResultSession -DeviceId $device -ScanId $scan -ControlResults $collectors `
    -EvaluationResults $evaluations -Findings $findings -ExpectedCheckIds @($collectors.CheckId) `
    -ExecutionStatus COMPLETED -StartedAtUTC '2026-01-01T00:00:00Z' -CompletedAtUTC '2026-01-01T00:01:00Z'
$public=ConvertTo-WinSecPublicScanResult -Session $session
$key='{0}:{1}{2}:{3}' -f $device.Length,$device,$scan.Length,$scan
$state=New-WinSecNavigationState
$state.Screen='Findings';$state.SelectedDeviceId=$device;$state.SelectedDeviceName='Synthetic findings device';$state.FindingsOffset=1
$context=[pscustomobject]@{Version='0.9.0';ActiveScanByDevice=@{$device=$scan};PublicScans=@{$key=$public}}
$before=ConvertTo-Json -InputObject @($state,$context,$session) -Depth 25 -Compress

Test-WinSecFindingIntegration 'Real pending evaluations reach the public view with original identities and UNASSIGNED' {
    $assessment=Get-WinSecCLIActiveAssessment -State $state -Context $context
    $view=Get-WinSecSelectedFindings -NavigationState $state -ControlResults $assessment.ControlResults -Findings $assessment.Findings -ScanId $scan
    Assert-WinSecFindingIntegration ($public.Findings.Count -eq 4 -and $view.Findings.Count -eq 3 -and
        @($view.Findings|Where-Object{$_.Priority -cne 'UNASSIGNED' -or $_.Severity -cne 'UNASSIGNED' -or $_.Kind -cne 'EVALUATION_PENDING'}).Count -eq 0 -and
        @($view.Findings|Where-Object{$_.FindingId -cnotin $public.Findings.FindingId}).Count -eq 0 -and $view.Score -ceq 'NOT_SCORED')
}
Test-WinSecFindingIntegration 'CLI counts use the same CheckId routing as section and control views' {
    $counts=Get-WinSecCLINavigationCounts -State $state -Context $context
    Assert-WinSecFindingIntegration ($counts.FindingCount -eq 3)
    $controlState=Copy-WinSecResultData -Value $state;$controlState.FindingsScope='Control';$controlState.ControlIndex=1
    $controlCounts=Get-WinSecCLINavigationCounts -State $controlState -Context $context
    Assert-WinSecFindingIntegration ($controlCounts.FindingCount -eq 1)
}
foreach($size in @(@{Width=120;Height=55},@{Width=80;Height=26},@{Width=40;Height=20})) {
    Test-WinSecFindingIntegration ('Findings render within simulated size '+$size.Width+'x'+$size.Height) {
        Set-WinSecFindingTestTerminal -Width $size.Width -Height $size.Height
        Show-WinSecCLICurrentScreen -State $state -Context $context
        $text=$script:lines -join "`n"
        Assert-WinSecFindingIntegration ($text -match 'SCORE: NOT_SCORED' -and $text -match 'FINDINGS / DIAGNOSTICS: 3' -and
            $text -notmatch '\d+/100|--/100|SYNTHETIC-FINDINGS-RAW|PRIORITY: P[1-5]' -and
            $script:lines.Count -le $script:terminal.Height -and
            @($script:lines|Where-Object{$_.Length -gt $script:terminal.ContentWidth}).Count -eq 0 -and
            $before -ceq (ConvertTo-Json -InputObject @($state,$context,$session) -Depth 25 -Compress) -and $script:scanCalls -eq 0)
        if($size.Height -ge 55){
            Assert-WinSecFindingIntegration ($text -match 'Evidence: Not included in public results.' -and
                $text -match 'UNASSIGNED')
            $assessment=Get-WinSecCLIActiveAssessment -State $state -Context $context
            $view=Get-WinSecSelectedFindings -NavigationState $state -ControlResults $assessment.ControlResults -Findings $assessment.Findings -ScanId $scan
            if($view.Findings[$state.FindingsOffset].FrameworkReferences.Count -eq 0){
                Assert-WinSecFindingIntegration ($text -match 'No configured framework references.' -and
                    $text -notmatch 'FRAMEWORK REFERENCES \(context only\): [1-9]')
            }
            else {Assert-WinSecFindingIntegration ($text -match 'FRAMEWORK REFERENCES \(context only\)')}
        }
    }
}
Test-WinSecFindingIntegration 'Resize redraws once without changing finding selection or stored data' {
    Set-WinSecFindingTestTerminal -Width 40 -Height 20;$resize=New-WinSecResizeState
    Set-WinSecFindingTestTerminal -Width 80 -Height 26;$renders=$script:renderCalls
    $render={param($State);Show-WinSecCLICurrentScreen -State $State -Context $context}
    $first=Invoke-WinSecResizeHandler -ResizeState $resize -NavigationState $state -RenderAction $render
    $second=Invoke-WinSecResizeHandler -ResizeState $resize -NavigationState $state -RenderAction $render
    Assert-WinSecFindingIntegration ($first -and -not $second -and $script:renderCalls -eq ($renders+1) -and
        $before -ceq (ConvertTo-Json -InputObject @($state,$context,$session) -Depth 25 -Compress) -and $script:scanCalls -eq 0)
}
Test-WinSecFindingIntegration 'Down arrow reaches the next visible diagnostic using CLI boundaries' {
    $counts=Get-WinSecCLINavigationCounts -State $state -Context $context
    $moving=Copy-WinSecResultData -Value $state
    $keyInfo=[pscustomobject]@{VirtualKeyCode=40;Character=[char]0;ControlKeyState=0;KeyDown=$true}
    $action=ConvertTo-WinSecKeyboardAction -KeyInfo $keyInfo -Screen Findings
    $null=Invoke-WinSecNavigationAction -State $moving -Action $action -FindingCount $counts.FindingCount
    Assert-WinSecFindingIntegration ($moving.FindingsOffset -eq 2 -and $moving.SelectedDeviceId -ceq $device -and $script:scanCalls -eq 0)
}
Test-WinSecFindingIntegration 'Control findings and Escape preserve the selected control and scan' {
    $moving=Copy-WinSecResultData -Value $state;$moving.Screen='Section';$moving.ControlIndex=1
    $null=Invoke-WinSecNavigationAction -State $moving -Action ShowFindings -ControlCount 3
    $counts=Get-WinSecCLINavigationCounts -State $moving -Context $context
    Assert-WinSecFindingIntegration ($moving.Screen -ceq 'Findings' -and $moving.FindingsScope -ceq 'Control' -and $counts.FindingCount -eq 1)
    $null=Invoke-WinSecNavigationAction -State $moving -Action Back
    Assert-WinSecFindingIntegration ($moving.Screen -ceq 'Section' -and $moving.ControlIndex -eq 1 -and $context.ActiveScanByDevice[$device] -ceq $scan)
}
Test-WinSecFindingIntegration 'Too-small terminal shows guidance without data disclosure or scans' {
    Set-WinSecFindingTestTerminal -Width 38 -Height 18
    Show-WinSecCLICurrentScreen -State $state -Context $context
    Assert-WinSecFindingIntegration (($script:lines -join '|') -match 'Terminal window is too small' -and
        ($script:lines -join '|') -notmatch 'SYNTHETIC-FINDINGS-RAW|FINDINGS / DIAGNOSTICS' -and $script:scanCalls -eq 0)
}
Test-WinSecFindingIntegration 'A nested private field prevents both counting and rendering before screen output' {
    $forged=Copy-WinSecResultData -Value $context
    $forged.PublicScans[$key].Findings[0]|Add-Member -NotePropertyName Metadata -NotePropertyValue @{OriginalResult='SYNTHETIC-FINDINGS-RAW'}
    $renders=$script:renderCalls;$script:lines.Clear();$caught=0
    try {$null=Get-WinSecCLINavigationCounts -State $state -Context $forged}catch{$caught++}
    try {Show-WinSecCLICurrentScreen -State $state -Context $forged}catch{$caught++}
    Assert-WinSecFindingIntegration ($caught -eq 2 -and $script:lines.Count -eq 0 -and $script:renderCalls -eq $renders -and
        $before -ceq (ConvertTo-Json -InputObject @($state,$context,$session) -Depth 25 -Compress))
}
# Exportación conectada al informe real; el único escritor se sustituye en memoria.
foreach($file in @('src/Core/TargetRegistry.ps1','src/Core/DeviceInventory.ps1',
    'src/Services/DeviceManagementService.ps1','src/Services/ReportService.ps1','src/Services/ExportService.ps1')) { . (Join-Path $root $file) }
$script:exportWrites=0;$script:exportFailure=$false;$script:exportedReport=$null
function Write-WinSecMarkdownArtifact {
    param($ProjectRoot,$Report)
    if($script:exportFailure){throw 'SYNTHETIC-FINDINGS-RAW'}
    $script:exportWrites++;$script:exportedReport=Copy-WinSecResultData -Value $Report
    [pscustomobject]@{FileName='synthetic.md';RelativePath='reports/exports/synthetic/synthetic.md'}
}
function New-WinSecExportContext {
    $copy=Copy-WinSecResultData -Value $context
    $copy | Add-Member -NotePropertyName ProjectRoot -NotePropertyValue $root
    $copy.PublicScans[$key] | Add-Member -NotePropertyName ScopeType -NotePropertyValue DEVICE
    $copy.PublicScans[$key] | Add-Member -NotePropertyName ScopeKey -NotePropertyValue ALL
    return $copy
}
$tokens=$null;$errors=$null
$cliAst=[System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'src/CLI/Invoke-WinSecCLI.ps1'),[ref]$tokens,[ref]$errors)
$exportBranches=@($cliAst.FindAll({param($node)
    $node -is [System.Management.Automation.Language.IfStatementAst] -and
    $node.Clauses[0].Item1.Extent.Text -ceq '$navigationState.PendingCommand -eq ''ExportMD'''
},$true))
if($errors.Count -or $exportBranches.Count -ne 1){throw 'Expected one parsed CLI export handler.'}
$script:exportHandler=[scriptblock]::Create($exportBranches[0].Extent.Text)
function Invoke-WinSecTestExportCommand {
    param($State,$Context)
    $navigationState=$State;$context=$Context
    & $script:exportHandler
}
Test-WinSecFindingIntegration 'P exports only the visible control findings with source scope and no raw values' {
    $moving=Copy-WinSecResultData -Value $state;$moving.FindingsScope='Control';$moving.ControlIndex=1
    $exportContext=New-WinSecExportContext
    $snapshot=ConvertTo-Json $exportContext.PublicScans -Depth 25 -Compress
    $enabled=Test-WinSecCLIFindingsExportEligibility $moving $exportContext
    $keyInfo=[pscustomobject]@{VirtualKeyCode=80;Character='P';ControlKeyState=0;KeyDown=$true}
    $action=ConvertTo-WinSecKeyboardAction -KeyInfo $keyInfo -Screen Findings -EnableExport:$enabled
    $null=Invoke-WinSecNavigationAction -State $moving -Action $action -FindingCount 1
    Assert-WinSecFindingIntegration ($action -ceq 'ExportMD' -and $moving.PendingCommand -ceq 'ExportMD')
    $writes=$script:exportWrites
    Invoke-WinSecTestExportCommand -State $moving -Context $exportContext
    Assert-WinSecFindingIntegration ($script:exportWrites -eq ($writes+1) -and $script:scanCalls -eq 0 -and
        $script:exportedReport.Markdown.Contains('Source scope: DEVICE / ALL') -and
        $script:exportedReport.Markdown.Contains('Exported selection: CONTROL / WSA\-SYS\-002') -and
        $script:exportedReport.Markdown -notmatch 'WSA\\-NET|WSA\\-SYS\\-001|SYNTHETIC-FINDINGS-RAW|"Evidence"|\d+/100' -and
        $script:exportedReport.Markdown.Contains('PENDING_APPROVED_CRITERIA') -and
        $snapshot -ceq (ConvertTo-Json $exportContext.PublicScans -Depth 25 -Compress) -and $null -eq $moving.PendingCommand)
    Invoke-WinSecTestExportCommand -State $moving -Context $exportContext
    Assert-WinSecFindingIntegration ($script:exportWrites -eq ($writes+1))
}
Test-WinSecFindingIntegration 'Section export includes matching findings and excludes another section' {
    $exportContext=New-WinSecExportContext
    $null=Invoke-WinSecCLIFindingsExport -State $state -Context $exportContext
    Assert-WinSecFindingIntegration (@([regex]::Matches($script:exportedReport.Markdown,'(?m)^## ')).Count -eq 4 -and
        $script:exportedReport.Markdown.Contains('Exported selection: SECTION / SystemSecurity') -and
        $script:exportedReport.Markdown.Contains('WSA\-SYS\-001') -and $script:exportedReport.Markdown.Contains('WSA\-SYS\-003') -and
        -not $script:exportedReport.Markdown.Contains('WSA\-NET\-001'))
}
foreach($fault in @('LegacyScope','ForeignIdentity','RawEvidence','Empty','WrongScreen')) {
    Test-WinSecFindingIntegration ('Export rejects before write: '+$fault) {
        $moving=Copy-WinSecResultData -Value $state;$exportContext=New-WinSecExportContext
        switch($fault) {
            LegacyScope {$exportContext.PublicScans[$key].PSObject.Properties.Remove('ScopeType')}
            ForeignIdentity {$exportContext.PublicScans[$key].Findings[0].DeviceId='local:OTHER'}
            RawEvidence {$exportContext.PublicScans[$key].Findings[0] | Add-Member -NotePropertyName Evidence -NotePropertyValue 'SYNTHETIC-FINDINGS-RAW'}
            Empty {$exportContext.PublicScans[$key].Findings=@()}
            WrongScreen {$moving.Screen='Section'}
        }
        $writes=$script:exportWrites;$caught=$false
        Assert-WinSecFindingIntegration (-not (Test-WinSecCLIFindingsExportEligibility $moving $exportContext))
        try{$null=Invoke-WinSecCLIFindingsExport $moving $exportContext}catch{$caught=$true}
        Assert-WinSecFindingIntegration ($caught -and $writes -eq $script:exportWrites -and $script:scanCalls -eq 0)
    }
}
Test-WinSecFindingIntegration 'Writer failure never reports export success or mutates sessions' {
    $exportContext=New-WinSecExportContext;$snapshot=ConvertTo-Json $exportContext.PublicScans -Depth 25 -Compress
    $moving=Copy-WinSecResultData -Value $state;$moving.PendingCommand='ExportMD';$moving.PendingScope='Section'
    $script:exportFailure=$true
    try{Invoke-WinSecTestExportCommand $moving $exportContext}finally{$script:exportFailure=$false}
    Assert-WinSecFindingIntegration ($exportContext.LastExportMessage -ceq 'Export failed or was rejected.' -and
        $null -eq $moving.PendingCommand -and $null -eq $moving.PendingScope -and
        $snapshot -ceq (ConvertTo-Json $exportContext.PublicScans -Depth 25 -Compress) -and $script:scanCalls -eq 0)
}
Test-WinSecFindingIntegration 'Export shortcut and status fit a small terminal without triggering another write' {
    $exportContext=New-WinSecExportContext
    $exportContext | Add-Member -NotePropertyName LastExportMessage -NotePropertyValue 'Exported: reports/exports/synthetic/synthetic.md'
    Set-WinSecFindingTestTerminal -Width 40 -Height 20
    $writes=$script:exportWrites
    Show-WinSecCLICurrentScreen -State $state -Context $exportContext
    Assert-WinSecFindingIntegration (($script:lines -join '|') -match '\[P\] Export MD' -and
        ($script:lines -join '|') -notmatch '\[R\]' -and $script:lines.Count -le 20 -and
        @($script:lines|Where-Object{$_.Length -gt 39}).Count -eq 0 -and $writes -eq $script:exportWrites -and $script:scanCalls -eq 0)
}
[Console]::WriteLine('Passed: '+$script:passed)
[Console]::WriteLine('Failed: '+$script:failed)
if($script:failed -gt 0){throw "$script:failed public Findings integration test(s) failed."}
