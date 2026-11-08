# Synthetic recovery scenarios. No live Windows sources or repository evidence.
$ErrorActionPreference='Stop'
$tempBase=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')+'\'
$testRoot=[IO.Path]::GetFullPath((Join-Path $tempBase ('winsec-recovery-test-'+[guid]::NewGuid().ToString('N'))))
$previousName=$env:COMPUTERNAME
try {
    $env:COMPUTERNAME='SYNTHETIC_RECOVERY'
    Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'WinSecAnalyzer.psm1') -Force -DisableNameChecking
    & (Get-Module WinSecAnalyzer) {
        param($testRoot)
        $script:assertions=0; $script:queries=0; $script:calls=@{}
        function Assert-Test {
            param([bool]$Condition,[string]$Message)
            if (-not $Condition) {throw ('FAIL: '+$Message)}
            $script:assertions++
        }
        function Assert-Throws {
            param([scriptblock]$Action,[string]$Message)
            $failed=$false
            try {& $Action} catch {$failed=$true}
            Assert-Test $failed $Message
        }
        function Assert-WinSecWindows11 {
            $script:queries++
            [pscustomobject]@{Edition='SYNTHETIC';Build=22000;Caption='SYNTHETIC';Arch='SYNTHETIC'}
        }
        function Test-WinSecElevated {return $false}
        function Get-WinSecLocalDevice {
            [pscustomobject]@{id=(Get-WinSecDeviceId $env:COMPUTERNAME);host=$env:COMPUTERNAME;hardware=$null;warnings=@();os=@{family='Windows11';build=22000;productType=1}}
        }
        function New-SyntheticEvidence {
            param([string]$Id)
            $script:calls[$Id]=1+$(if ($script:calls.ContainsKey($Id)) {$script:calls[$Id]} else {0})
            New-WinSecPayload -Data @{synthetic=$true;attempt=$script:calls[$Id]} -Sources @('SYNTHETIC')
        }
        function Get-WinSecWindowsDefenderEvidence {param([switch]$Deep) New-SyntheticEvidence WindowsDefender}
        function Get-WinSecSMBEvidence {param([switch]$Deep) New-SyntheticEvidence SMB}
        function Get-WinSecRDPEvidence {param([switch]$Deep) New-SyntheticEvidence RDP}
        function Get-WinSecWinRMEvidence {param([switch]$Deep) New-SyntheticEvidence WinRM}
        function Get-WinSecTCPListenersEvidence {param([switch]$Deep) New-SyntheticEvidence TCPListeners}
        function Get-WinSecNetworkAdaptersEvidence {param([switch]$Deep) New-SyntheticEvidence NetworkAdapters}
        function Get-WinSecDNSAndProxyEvidence {param([switch]$Deep) New-SyntheticEvidence DNSAndProxy}
        function Clear-Host {}
        function Show-WinSecBanner {}
        $script:answers=New-Object System.Collections.Queue
        function Add-Answer {
            param([string]$Text)
            $script:answers.Enqueue([pscustomobject]@{Text=$Text;Cancelled=($Text -eq 'ESC');HelpRequested=($Text -eq 'F1');Action=''})
        }
        function Read-WinSecInput {
            param($Hints,$Shortcuts)
            if ($script:answers.Count -eq 0) {throw 'Unexpected recovery input read.'}
            return $script:answers.Dequeue()
        }
        function New-TestSession {
            param([string]$Root)
            $value=New-WinSecSession -OutputRoot $Root
            $value.DeviceId=Get-WinSecDeviceId $env:COMPUTERNAME
            $value.DeviceName=$env:COMPUTERNAME
            return $value
        }
        function New-AnalysisCommand {
            param($Session,[string]$Target='windowsDefender',[switch]$Cis)
            $p=@{Analyze=$Target;Session=$Session;NoBanner=$true}
            if ($Cis) {$p.Cis=$true} else {$p.Nist=$true}
            return $p
        }

        $root=Join-Path $testRoot 'device'
        $session=New-TestSession $root
        foreach ($answer in @('n','','ESC')) {
            Add-Answer $answer
            $p=New-AnalysisCommand $session
            Assert-Test ((Confirm-WinSecAnalysisEvidence $session $p 6>$null) -eq 'Cancelled') 'No, Enter and Esc must cancel recovery.'
        }
        Assert-Test ($script:queries -eq 0 -and -not (Test-Path $root)) 'Declining recovery must not query Windows or write files.'
        $invalid=@{Analyze='windowsDefender';Nist=$true;Cis=$true}
        Assert-Throws {Confirm-WinSecAnalysisEvidence $session $invalid} 'Invalid framework combinations must be rejected before recovery.'
        $invalid=@{Analyze='windowsDefender';Nist=$true;Collector='SMB'}
        Assert-Throws {Confirm-WinSecAnalysisEvidence $session $invalid} 'Conflicting analysis targets must be rejected before recovery.'
        $invalid=@{Analyze='windowsDefender';Nist=$true;OutputRoot=(Join-Path $testRoot 'different-output')}
        Assert-Throws {Confirm-WinSecAnalysisEvidence $session $invalid} 'An incompatible OutputRoot must not trigger recovery in a different directory.'
        Assert-Test ($script:answers.Count -eq 0 -and $script:queries -eq 0) 'Invalid analysis must not prompt or scan.'
        Add-Answer 'F1';Add-Answer 'y'
        $p=New-AnalysisCommand $session
        Assert-Test ((Confirm-WinSecAnalysisEvidence $session $p 6>$null) -eq 'Ready') 'Help followed by Yes must scan the requested target and make analysis ready.'
        $first=Get-WinSecSnapshotManifest $session.Snapshot
        $firstEvidence=Join-Path $first.Base 'SystemSecurity/WindowsDefender.json'
        Assert-Test (@($first.Manifest.collectors).Count -eq 1 -and $script:calls.WindowsDefender -eq 1) 'Control recovery must scan only the requested collector.'
        $before=$script:queries
        winsec @p 6>$null
        $nist=Get-Content (Join-Path $first.Base 'export/nistcsf/windowsDefender.json') -Raw | ConvertFrom-Json
        Assert-Test ($nist.sourceRunId -eq $first.Manifest.runId -and $script:queries -eq $before) 'Analysis must use the recovered run without another Windows query.'
        $cisParams=New-AnalysisCommand $session -Cis
        Assert-Test ((Confirm-WinSecAnalysisEvidence $session $cisParams 6>$null) -eq 'Ready' -and $script:answers.Count -eq 0) 'Existing valid evidence must not request a rescan.'
        winsec @cisParams 6>$null
        Assert-Test ((Get-Content (Join-Path $first.Base 'export/cisf/windowsDefender.json') -Raw | ConvertFrom-Json).status -eq 'NOT_CONFIGURED') 'CIS must remain NOT_CONFIGURED without a verified benchmark pack.'

        # An older valid run must not hide a missing file in the latest attempt.
        $olderRun=Join-Path (Split-Path -Parent $first.Base) '20260101T000000Z_SYNTHETIC_HISTORY'
        $olderEvidence=Join-Path $olderRun 'SystemSecurity/WindowsDefender.json'
        $olderTime=[DateTime]::UtcNow.AddDays(-2).ToString('o')
        [void](Save-WinSecJson $olderEvidence @{schemaVersion='1';runId='SYNTHETIC_HISTORY';collector='WindowsDefender';status='COMPLETED';data=@{synthetic=$true}})
        $olderManifest=Join-Path $olderRun 'manifest.json'
        [void](Save-WinSecJson $olderManifest @{schemaVersion='1';runId='SYNTHETIC_HISTORY';host=$env:COMPUTERNAME;startedAtUtc=$olderTime;status='COMPLETED';collectors=@(@{id='WindowsDefender';domain='SystemSecurity';status='COMPLETED';path='SystemSecurity/WindowsDefender.json';sha256=(Get-WinSecHash $olderEvidence);collectedAtUtc=$olderTime});os=@{family='Windows11';build=22000;productType=1}})
        $olderHash=Get-WinSecHash $olderManifest
        Remove-Item -LiteralPath $firstEvidence
        $before=$script:queries
        Add-Answer 'n'
        $p=New-AnalysisCommand $session
        Assert-Test ((Confirm-WinSecAnalysisEvidence $session $p 6>$null) -eq 'Cancelled') 'A missing latest evidence file must prompt instead of falling back to history.'
        Assert-Test ($script:queries -eq $before -and $script:calls.WindowsDefender -eq 1) 'Rejecting a rescan must preserve existing captures without recollection.'
        Add-Answer 's'
        $p=New-AnalysisCommand $session
        Assert-Test ((Confirm-WinSecAnalysisEvidence $session $p 6>$null) -eq 'Ready') 'Spanish S must also confirm a fresh rescan.'
        $fresh=Get-WinSecSnapshotManifest $session.Snapshot
        Assert-Test ($fresh.Manifest.runId -ne $first.Manifest.runId -and $script:calls.WindowsDefender -eq 2) 'Confirmed recovery must create a new run even when other snapshots still exist.'
        Assert-Test ((Get-WinSecHash $olderManifest) -eq $olderHash -and (Test-Path $first.Path)) 'Older history must remain intact after recovery.'
        winsec @p 6>$null
        Assert-Test ((Get-Content (Join-Path $fresh.Base 'export/nistcsf/windowsDefender.json') -Raw | ConvertFrom-Json).sourceRunId -eq $fresh.Manifest.runId) 'NIST must export under the new run after recovery.'

        # A stale UI context and a newer filesystem mtime must not override collection UTC.
        [IO.File]::SetLastWriteTimeUtc($olderManifest,[DateTime]::UtcNow.AddDays(1))
        $stale=New-TestSession $root
        $stale.Snapshot=$olderManifest; $stale.Context=Get-WinSecSnapshotManifest $olderManifest
        Assert-Test ((Get-WinSecSessionSnapshot -Session $stale -Collector WindowsDefender -Domain SystemSecurity) -eq $fresh.Path) 'Automatic analysis must select the latest collected control, regardless of the displayed context or manifest mtime.'
        $before=$script:queries
        winsec -a windowsDefender -c -OutputRoot $root -NoBanner 6>$null
        $cis=Get-Content (Join-Path $fresh.Base 'export/cisf/windowsDefender.json') -Raw | ConvertFrom-Json
        Assert-Test ($cis.sourceRunId -eq $fresh.Manifest.runId -and $script:queries -eq $before) 'CLI analysis must also use the latest collected target without querying Windows.'

        # Removing the active manifest must not break recovery or quitting.
        Remove-Item -LiteralPath $fresh.Path
        Add-Answer 'n'
        $p=New-AnalysisCommand $session
        Assert-Test ((Confirm-WinSecAnalysisEvidence $session $p 6>$null) -eq 'Cancelled') 'A deleted active snapshot must be detected even when older snapshots remain.'
        $deletedView=New-TestSession $root
        $deletedView.Snapshot=$fresh.Path; $deletedView.Context=$fresh; $deletedView.RunId=$fresh.Manifest.runId
        Close-WinSecSession $deletedView
        Assert-Test ($deletedView.Closed -and -not (Test-Path $fresh.Path)) 'Quitting after a snapshot was deleted must not fail or recreate it.'
        Add-Answer 'y'
        $p=New-AnalysisCommand $session
        Assert-Test ((Confirm-WinSecAnalysisEvidence $session $p 6>$null) -eq 'Ready') 'A deleted active manifest must allow a new run after confirmation.'
        Assert-Test ($session.Snapshot -ne $fresh.Path -and -not (Test-Path $fresh.Path)) 'Recovery must not recreate or reuse the deleted historical manifest.'
        Close-WinSecSession $session

        # A recorded failed attempt is still the newest attempt, not a reason to use older success.
        $failureRun=Join-Path (Split-Path -Parent $first.Base) '20261107T000000Z_SYNTHETIC_FAILURE'
        $failureFile=Join-Path $failureRun 'SystemSecurity/WindowsDefender.json'
        $failureTime=[DateTime]::UtcNow.AddMinutes(1).ToString('o')
        [void](Save-WinSecJson $failureFile @{schemaVersion='1';runId='SYNTHETIC_FAILURE';collector='WindowsDefender';status='ERROR';data=@{}})
        $failureManifest=Join-Path $failureRun 'manifest.json'
        [void](Save-WinSecJson $failureManifest @{schemaVersion='1';runId='SYNTHETIC_FAILURE';host=$env:COMPUTERNAME;startedAtUtc=$failureTime;status='PARTIAL';collectors=@(@{id='WindowsDefender';domain='SystemSecurity';status='ERROR';path='SystemSecurity/WindowsDefender.json';sha256=(Get-WinSecHash $failureFile);collectedAtUtc=$failureTime});os=@{family='Windows11';build=22000;productType=1}})
        $p=New-AnalysisCommand $session
        $before=$script:queries
        Assert-Test ((Confirm-WinSecAnalysisEvidence $session $p 6>$null) -eq 'Ready' -and $p.Snapshot -eq $failureManifest -and $script:queries -eq $before) 'The latest saved failed attempt must remain selected without silently substituting older success.'

        $networkRoot=Join-Path $testRoot 'network'
        $network=New-TestSession $networkRoot
        Add-Answer 'y'
        $p=New-AnalysisCommand $network -Target network
        $p.Deep=$true
        Assert-Test ((Confirm-WinSecAnalysisEvidence $network $p 6>$null) -eq 'Ready') 'Section recovery must be supported.'
        $networkContext=Get-WinSecSnapshotManifest $network.Snapshot
        Assert-Test (@($networkContext.Manifest.collectors).Count -eq 6) 'Section recovery must scan all six Network Security collectors.'
        Assert-Test ($networkContext.Manifest.mode -eq 'DEEP') 'Recovery must retain an explicitly requested scan mode.'
        winsec @p 6>$null
        Assert-Test ((Get-Content (Join-Path $networkContext.Base 'export/nistcsf/networkSecurity.json') -Raw | ConvertFrom-Json).sourceRunId -eq $networkContext.Manifest.runId) 'Section analysis must use one recovered snapshot.'
        Close-WinSecSession $network

        $foreign=New-TestSession (Join-Path $testRoot 'foreign')
        $foreign.DeviceId='SYNTHETIC_OTHER'
        $before=$script:queries
        Assert-Throws {Confirm-WinSecAnalysisEvidence $foreign (New-AnalysisCommand $foreign)} 'A saved foreign device must never be rescanned remotely.'
        Assert-Test ($script:queries -eq $before -and $script:answers.Count -eq 0) 'A foreign-device recovery failure must not prompt or query Windows.'

        # Verify the actual menu cancels directly, without a result-wait Enter.
        $menuRoot=Join-Path $testRoot 'menu'
        foreach ($text in @('','winsec -a windowsDefender -n','n','q')) {Add-Answer $text}
        $before=$script:queries
        Invoke-WinSecMenu -OutputRoot $menuRoot 6>$null
        Assert-Test ($script:queries -eq $before -and $script:answers.Count -eq 0) 'Menu cancellation must not scan or request another Enter.'
        foreach ($text in @('','winsec -a windowsDefender -n','y','','q')) {Add-Answer $text}
        Invoke-WinSecMenu -OutputRoot $menuRoot 6>$null
        Assert-Test (@(Get-ChildItem $menuRoot -Filter manifest.json -File -Recurse).Count -eq 1 -and $script:answers.Count -eq 0) 'The menu must rescan, analyze and return through only the analysis result wait.'
        Write-Output ('PASS: '+$script:assertions+' analysis recovery assertions')
    } $testRoot
} finally {
    $env:COMPUTERNAME=$previousName
    $full=[IO.Path]::GetFullPath($testRoot)
    if (-not $full.StartsWith($tempBase,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($full) -notlike 'winsec-recovery-test-*') {throw 'Unsafe recovery cleanup path.'}
    if (Test-Path -LiteralPath $full) {Remove-Item -LiteralPath $full -Recurse -Force}
    Remove-Module WinSecAnalyzer -ErrorAction SilentlyContinue
}
