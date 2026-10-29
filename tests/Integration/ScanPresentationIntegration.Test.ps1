# Production catalogue/collectors and paired storage, exclusively synthetic Windows providers.
[CmdletBinding()]param()
$ErrorActionPreference='Stop';$sourceRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$tempParent=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\');$root=Join-Path $tempParent ('wsp-'+[guid]::NewGuid().ToString('N').Substring(0,12))
$null=New-Item -ItemType Directory -Path $root;$oldName=$env:COMPUTERNAME;$env:COMPUTERNAME='SYNTHETIC-PRESENTATION';$passed=0;$failed=0
function Assert-WinSecUpdateCoordinator {param([bool]$Value);if(-not $Value){throw 'Synthetic provider contract failed.'}}
function Assert-Presentation {param([bool]$Value);if(-not $Value){throw 'Scan presentation assertion failed.'}}
function Test-Presentation {param($Name,[scriptblock]$Action);try{& $Action;$script:passed++;[Console]::WriteLine('[PASS] '+$Name)}catch{$script:failed++;[Console]::WriteLine('[FAIL] '+$Name+': '+$_.Exception.Message);[Console]::WriteLine($_.ScriptStackTrace)}}
try {
    foreach($dir in @('src','config')){Copy-Item -LiteralPath (Join-Path $sourceRoot $dir) -Destination (Join-Path $root $dir) -Recurse}
    foreach($file in @('src/Core/ScanCoordinator.ps1','src/CLI/Invoke-WinSecCLI.ps1','src/CLI/FrameworkWorkflow.ps1',
        'src/UI/Core/NavigationController.ps1','src/UI/Core/TerminalRenderer.ps1','src/UI/Core/LayoutManager.ps1','src/UI/Core/ResizeHandler.ps1',
        'src/UI/Screens/MainMenu.ps1','src/UI/Screens/Results.ps1','src/UI/Screens/ScanConfirmation.ps1','src/UI/Screens/ScanProgress.ps1',
        'src/UI/Screens/FrameworkFindings.ps1','src/UI/Screens/ExportFrameworkSelection.ps1')){. (Join-Path $root $file)}
    foreach($file in @('WindowsUpdateMemory','FirewallMemory','SmbMemory','RdpMemory','OpenPortsMemory','NetworkConfigurationMemory','IdentityAccessMemory')){. (Join-Path $sourceRoot ('tests/Fixtures/'+$file+'.ps1'))}
    $script:auditReader=(Get-Command Invoke-WinSecAudit).ScriptBlock;$script:wuCimReader=(Get-Command Get-CimInstance).ScriptBlock
    # Reuse only the reviewed synthetic provider functions, never that suite's mocked stores or tests.
    $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $sourceRoot 'tests/Integration/WindowsUpdateCoordinatorIntegration.Test.ps1'),[ref]$tokens,[ref]$errors)
    foreach($name in @('Get-CimInstance','Invoke-CimMethod','Get-MpComputerStatus','Get-MpPreference','Invoke-WinSecAudit',
        'Invoke-WinSecUpdateRdpFixtureQuery','Invoke-WinSecUpdatePortsFixtureQuery','Invoke-WinSecUpdateNetworkFixtureQuery','Invoke-WinSecUpdateIdentityFixtureQuery')){
        $definition=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true)
        if($null -eq $definition){throw 'Synthetic provider definition missing.'};. ([scriptblock]::Create($definition.Extent.Text))
    }
    foreach($name in @('Get-WinSecLocalHardwareDeviceId','Open-WinSecWindowsUpdatePolicyKey','Open-WinSecWindowsUpdateVersionKey','Get-WinSecWindowsUpdateRebootRequired','Read-WinSecWindowsUpdateNamedPolicy')){
        $fake='Stage4_'+$name;Set-Item ('Function:'+$fake) (Get-Command $name).ScriptBlock;Set-Alias $name $fake -Scope Script
    }
    foreach($pair in @(@('Invoke-WinSecFirewallQuery','Invoke-WinSecFirewallFixtureQuery'),@('Invoke-WinSecSmbQuery','Invoke-WinSecSmbFixtureQuery'),
        @('Read-WinSecSmbRegistryValue','Read-WinSecSmbFixtureRegistry'),@('Invoke-WinSecRdpQuery','Invoke-WinSecUpdateRdpFixtureQuery'),
        @('Read-WinSecRdpRegistryValue','Read-WinSecRdpFixtureRegistry'),@('Invoke-WinSecOpenPortsQuery','Invoke-WinSecUpdatePortsFixtureQuery'),
        @('Invoke-WinSecNetworkConfigurationQuery','Invoke-WinSecUpdateNetworkFixtureQuery'),@('Invoke-WinSecIdentityAccessQuery','Invoke-WinSecUpdateIdentityFixtureQuery'))){Set-Alias $pair[0] $pair[1] -Scope Script}
    Reset-WinSecWindowsUpdateFixture;Initialize-WinSecFirewallFixture;Initialize-WinSecSmbFixture;Initialize-WinSecRdpFixture
    Initialize-WinSecOpenPortsFixture;Initialize-WinSecNetworkConfigurationFixture;Initialize-WinSecIdentityFixture
    $script:sequence=0;$script:osReads=0;$script:volumeReads=0;$script:volumeMethods=0;$script:defenderReads=0
    $script:terminal=[pscustomobject]@{Width=120;ContentWidth=119;Height=65}
    $script:keys=New-Object 'Collections.Generic.Queue[object]';$script:scanEvents=New-Object 'Collections.Generic.List[object]'
    $script:reviewEvents=New-Object 'Collections.Generic.List[object]';$script:sourcePreference='PREFER_COMPLETE';$script:cancelAfter=0;$script:pendingEsc=$false
    function Get-WinSecTerminalSize {$script:terminal}
    function Clear-WinSecScreen {}
    function Write-Host {param($Object,[switch]$NoNewline,$ForegroundColor,$BackgroundColor,$Separator)}
    function Write-WinSecText {param($Text,$Color,$Align)}
    function Read-WinSecResizeAwareKey {param($ResizeState,$RenderAction);if(-not $script:keys.Count){throw 'No synthetic confirmation key.'};$script:keys.Dequeue()}
    function Read-WinSecPendingKey {if($script:pendingEsc){$script:pendingEsc=$false;return [pscustomobject]@{VirtualKeyCode=27;KeyDown=$true;ControlKeyState=0}}}
    $progressRenderer=(Get-Command Show-WinSecScanProgress).ScriptBlock
    function Show-WinSecScanProgress {param($State,$Progress);$script:scanEvents.Add((Copy-WinSecResultData $Progress));& $progressRenderer @PSBoundParameters
        if($script:cancelAfter -gt 0 -and $Progress.Phase -ceq 'CHECK_COMPLETED' -and $Progress.CompletedChecks -ge $script:cancelAfter){$script:pendingEsc=$true}}
    function Show-WinSecFrameworkProgress {param($Progress);$script:reviewEvents.Add((Copy-WinSecResultData $Progress))}
    function Show-WinSecAssessmentProfileSelection {param($Request,$Profiles,$CurrentSystemLabel)
        $p=@($Profiles|Where-Object {$_.Profile -ceq 'WSA-W11-24H2-PRO-DEF-BASE'})
        if($p.Count -ne 1){throw 'Expected synthetic profile not offered.'};[pscustomobject]@{Confirmed=$true;Selection=$p[0]}}
    function Show-WinSecFindingsSourceSelection {param($Selection);if($script:sourcePreference -ceq 'CANCEL'){return [pscustomobject]@{Confirmed=$false;SourcePreference=$null}};[pscustomobject]@{Confirmed=$true;SourcePreference=$script:sourcePreference}}
    function Show-WinSecExportFrameworkSelection {param($Selection,[switch]$ForFindings);[pscustomobject]@{Confirmed=$true;FrameworkId='nist-csf'}}
    $null=Register-WinSecLocalDevice $root;$target=New-WinSecLocalTarget;$coordinator=New-WinSecScanCoordinator $root
    $coordinator.Registry=[pscustomobject]@{schemaVersion='1.0.0';targets=@($target)}
    $coordinator.AssessmentEnabled=$true;$coordinator.PublicHistoryEnabled=$true;$coordinator.TechnicalReportsEnabled=$true;$coordinator.NewTechnicalStorageEnabled=$true
    $context=[pscustomobject]@{ProjectRoot=$root;ScanCoordinator=$coordinator;Devices=@($target);LocalDeviceId=$target.DeviceId;FrameworkWorkflowEnabled=$true;
        PublicScans=@{};ActiveScanByDevice=@{};ActiveScanByScope=@{};LastScanMessage='';Version='0.9.0'}
    $state=New-WinSecNavigationState;$state.SelectedDeviceId=$target.DeviceId;$state.SelectedDeviceName=$target.Hostname
    $sections=@(Get-WinSecMainMenuSections);$catalog=Get-WinSecCheckRegistry $root;$enabled=@(Get-WinSecExecutableChecks $catalog)
    function Select-PresentationControl {param($Id)
        $control=Get-WinSecTechnicalControl $Id
        $state.Screen='Section';$state.SectionIndex=[array]::IndexOf(@($sections.Key),$control.SectionKey)
        $controls=@(Get-WinSecSectionControls $control.SectionKey);$state.ControlIndex=[array]::IndexOf(@($controls.CheckId),$Id)}
    function Invoke-PresentationScan {param([int]$Key=13)
        $script:keys.Enqueue([pscustomobject]@{VirtualKeyCode=$Key;KeyDown=$true;ControlKeyState=0;Character=''})
        Invoke-WinSecCLILocalRescan -State $state -Context $context -ShowProgress}
    Test-Presentation 'Unmodified production catalogue contains eleven ready and three disabled checks' {
        Assert-Presentation ($enabled.Count -eq 11 -and @($catalog.Checks|Where-Object {-not $_.ExecutionEnabled}).Count -eq 3)
    }
    Test-Presentation 'A pending control cannot query providers or publish a session' {
        $state.Screen='Section';$state.SectionIndex=[array]::IndexOf(@($sections.Key),'LoggingAuditing');$state.ControlIndex=0;$before=$sequence;$rejected=$false
        try{$null=Invoke-WinSecCLILocalRescan -State $state -Context $context}catch{$rejected=$true}
        Assert-Presentation ($rejected -and $sequence -eq $before -and $coordinator.Sessions.Count -eq 0)
    }
    Test-Presentation 'A historical device cannot authorize a local scan' {
        $foreign=Copy-WinSecResultData $target;$foreign.DeviceId='local:hw1-'+('b'*64);$context.Devices=@($target,$foreign)
        $coordinator.Registry.targets=@($target,$foreign);$state.Screen='Devices';$state.DeviceIndex=1;$rejected=$false;$before=$sequence
        try{try{$null=Invoke-WinSecCLILocalRescan -State $state -Context $context}catch{$rejected=$true}}
        finally{$context.Devices=@($target);$coordinator.Registry.targets=@($target);$state.DeviceIndex=0}
        Assert-Presentation ($rejected -and $sequence -eq $before -and $coordinator.Sessions.Count -eq 0)
    }
    foreach($check in $enabled){Test-Presentation ('CONTROL scan persists and presents only '+$check.CheckId) {
        Select-PresentationControl $check.CheckId;$script:scanEvents.Clear();$r=Invoke-PresentationScan
        Assert-Presentation ($r.ExecutionStatus -ceq 'COMPLETED' -and $r.ScopeKey -ceq $check.CheckId -and $coordinator.LastTechnicalReports.Files.Count -eq 1 -and
            $coordinator.LastTechnicalReports.Files[0].CheckId -ceq $check.CheckId -and $scanEvents[-1].CompletedChecks -eq 1 -and $scanEvents[-1].Phase -ceq 'COMPLETED')
        $view=@(Get-WinSecWorkflowControlRows $state $context|Where-Object CheckId -CEQ $check.CheckId)
        Assert-Presentation ($view.Count -eq 1 -and $view[0].Status -ceq 'COMPLETE' -and $view[0].Mode -ceq 'LIVE' -and (Get-WinSecCLIScanPresentation $state $context).ScanAction -ceq 'Rescan')
    }}
    foreach($section in @('SystemSecurity','NetworkSecurity','IdentityAccess')){Test-Presentation ('SECTION scan retains exact original scope and enabled members: '+$section) {
        $state.Screen='MainMenu';$state.SectionIndex=[array]::IndexOf(@($sections.Key),$section);$r=Invoke-PresentationScan
        $expected=@($enabled|Where-Object SectionKey -CEQ $section)
        Assert-Presentation ($r.ScopeType -ceq 'SECTION' -and $r.ScopeKey -ceq $section -and $coordinator.LastTechnicalReports.Files.Count -eq $expected.Count -and $r.ExecutionStatus -ceq 'COMPLETED')
    }}
    Test-Presentation 'DEVICE scan persists eleven sources, keeps other scopes and reports real completion' {
        $state.Screen='Devices';$state.DeviceIndex=0;$r=Invoke-PresentationScan
        Assert-Presentation ($r.ScopeType -ceq 'DEVICE' -and $r.ScopeKey -ceq 'ALL' -and $r.ExecutionStatus -ceq 'COMPLETED' -and $coordinator.LastTechnicalReports.Files.Count -eq 11 -and $scanEvents[-1].CompletedChecks -eq 11)
        Assert-Presentation ((Get-WinSecCLIScanPresentation $state $context).ScanAction -ceq 'Rescan')
    }
    Test-Presentation 'Esc confirmation preserves prior sessions and performs no collection' {
        Select-PresentationControl WSA-IAM-002;$before=$sequence;$count=$coordinator.Sessions.Count;$r=Invoke-PresentationScan 27
        Assert-Presentation ($null -eq $r -and $sequence -eq $before -and $coordinator.Sessions.Count -eq $count)
    }
    Test-Presentation 'Esc during collection publishes no new session and retains the old selection' {
        $state.Screen='MainMenu';$state.SectionIndex=[array]::IndexOf(@($sections.Key),'IdentityAccess')
        $before=Get-WinSecPublicHistoryJson $context.ActiveScanByScope;$count=$coordinator.Sessions.Count;$script:cancelAfter=1
        try{$r=Invoke-PresentationScan}finally{$script:cancelAfter=0}
        Assert-Presentation ($null -eq $r -and $coordinator.Sessions.Count -eq $count -and (Get-WinSecPublicHistoryJson $context.ActiveScanByScope) -ceq $before)
    }
    Test-Presentation 'A partial rescan is saved and selectable alongside its older complete source' {
        Select-PresentationControl WSA-IAM-002;$script:IdentityFailure='Guest'
        try{$script:partial=Invoke-PresentationScan}finally{$script:IdentityFailure=''}
        Assert-Presentation ($partial.ExecutionStatus -ceq 'COMPLETED_WITH_ERRORS')
        $latest=Get-WinSecCLIActiveAssessment $state $context;$complete=Get-WinSecCLIActiveAssessment $state $context -SourcePreference PREFER_COMPLETE
        Assert-Presentation ($latest.ScanId -ceq $partial.ScanId -and $complete.ScanId -cne $partial.ScanId -and (Get-WinSecWorkflowControlRows $state $context)[1].Status -ceq 'PARTIAL')
    }
    foreach($scopeType in @('SECTION','DEVICE')){Test-Presentation ('Partial '+$scopeType+' keeps valid siblings and complete predecessors visible') {
        if($scopeType -ceq 'SECTION'){$state.Screen='MainMenu';$state.SectionIndex=[array]::IndexOf(@($sections.Key),'IdentityAccess')}else{$state.Screen='Devices';$state.DeviceIndex=0}
        $script:IdentityFailure='Guest'
        try{$script:partial=Invoke-PresentationScan}finally{$script:IdentityFailure=''}
        Assert-Presentation ($partial.ExecutionStatus -ceq 'COMPLETED_WITH_ERRORS' -and $partial.ScopeType -ceq $scopeType)
        Select-PresentationControl WSA-IAM-002;$rows=@(Get-WinSecWorkflowControlRows $state $context)
        $guest=Get-WinSecCLIActiveAssessment $state $context
        $complete=Get-WinSecCLIActiveAssessment $state $context -SourcePreference PREFER_COMPLETE
        Assert-Presentation ($guest.ScanId -ceq $partial.ScanId -and $guest.SourceScopeType -ceq $scopeType -and $complete.ScanId -cne $partial.ScanId -and
            $rows[0].Status -ceq 'COMPLETE' -and $rows[1].Status -ceq 'PARTIAL' -and $rows[2].Status -ceq 'COMPLETE')
    }}
    function Stop-PresentationProvider {throw 'F/P must never query a Windows provider.'}
    foreach($name in @('Get-CimInstance','Invoke-CimMethod','Get-MpComputerStatus','Get-MpPreference','Invoke-WinSecFirewallQuery','Invoke-WinSecSmbQuery',
        'Read-WinSecSmbRegistryValue','Invoke-WinSecRdpQuery','Read-WinSecRdpRegistryValue','Invoke-WinSecOpenPortsQuery','Invoke-WinSecNetworkConfigurationQuery',
        'Invoke-WinSecIdentityAccessQuery','Get-WinSecLocalHardwareDeviceId')){Set-Alias $name Stop-PresentationProvider -Scope Script}
    foreach($preference in @('PREFER_COMPLETE','LATEST_ATTEMPT')){Test-Presentation ('F/P preserve the selected saved source without collection: '+$preference) {
        Select-PresentationControl WSA-IAM-002;$script:sourcePreference=$preference;$before=$sequence
        Assert-Presentation (Invoke-WinSecCLIFrameworkFindings $state $context -ShowProgress)
        Assert-Presentation (-not (Get-WinSecCLIValue $context LastExportMessage))
        $analysis=$context.FrameworkFindings;$state.Screen='Findings';$state.FindingsScope='Control';$export=Export-WinSecCLIFrameworkFindings $state $context
        Assert-Presentation ([IO.File]::Exists($export.Path) -and $sequence -eq $before -and $context.FrameworkFindings.AnalysisId -ceq $analysis.AnalysisId -and $context.FrameworkSourcePreference -ceq $preference)
        if($preference -ceq 'LATEST_ATTEMPT'){Assert-Presentation ($analysis.Sources[0].ScanId -ceq $partial.ScanId)}else{Assert-Presentation ($analysis.Sources[0].ScanId -cne $partial.ScanId)}
    }}
    Test-Presentation 'Esc while loading Findings preserves the frozen previous analysis' {
        Select-PresentationControl WSA-IAM-002;$before=Get-WinSecPublicHistoryJson $context.FrameworkFindings;$script:pendingEsc=$true
        Assert-Presentation (-not (Invoke-WinSecCLIFrameworkFindings $state $context -ShowProgress) -and (Get-WinSecPublicHistoryJson $context.FrameworkFindings) -ceq $before)
    }
    Test-Presentation 'Cancelling the explicit source choice preserves the previous analysis' {
        Select-PresentationControl WSA-IAM-002;$before=Get-WinSecPublicHistoryJson $context.FrameworkFindings;$script:sourcePreference='CANCEL'
        try{Assert-Presentation (-not (Invoke-WinSecCLIFrameworkFindings $state $context) -and (Get-WinSecPublicHistoryJson $context.FrameworkFindings) -ceq $before)}finally{$script:sourcePreference='LATEST_ATTEMPT'}
    }
    Test-Presentation 'Restart preserves partial/complete choices and changes all restored sources to RECORDS' {
        $restored=New-WinSecScanCoordinator $root;$restored.NewTechnicalStorageEnabled=$true
        $reloaded=[pscustomobject]@{ProjectRoot=$root;ScanCoordinator=$restored;Devices=@($target);LocalDeviceId=$target.DeviceId;PublicScans=@{};ActiveScanByDevice=@{};ActiveScanByScope=@{}}
        Restore-WinSecPublicHistory $reloaded;Select-PresentationControl WSA-IAM-002
        $latest=@(Get-WinSecWorkflowSources $state $reloaded);$previous=@(Get-WinSecWorkflowSources $state $reloaded -SourcePreference PREFER_COMPLETE)
        Assert-Presentation ($latest[0].ScanId -ceq $partial.ScanId -and $previous[0].ScanId -cne $partial.ScanId -and $latest[0].Origin -ceq 'RECORDS' -and $restored.Sessions.Count -eq $coordinator.Sessions.Count)
    }
}finally{
    $env:COMPUTERNAME=$oldName;$full=[IO.Path]::GetFullPath($root)
    if([IO.Path]::GetDirectoryName($full) -cne $tempParent -or [IO.Path]::GetFileName($full) -cnotmatch '\Awsp-[a-f0-9]{12}\z'){throw 'Unsafe presentation fixture cleanup.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
[Console]::WriteLine("Scan presentation integration: $passed passed; $failed failed.");if($failed){exit 1}
