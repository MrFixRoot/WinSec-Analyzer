# Synthetic regression tests. No Windows queries and no repository snapshots.
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$WarningPreference='Continue'
$root=Split-Path -Parent $PSScriptRoot
$tempRoot=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')+'\'
$testRoot=[IO.Path]::GetFullPath((Join-Path $tempRoot ('winsec-ui-test-'+[guid]::NewGuid().ToString('N'))))
if (-not $testRoot.StartsWith($tempRoot,[StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe test directory.' }
$previousComputerName=$env:COMPUTERNAME
try {
    $env:COMPUTERNAME='SYNTHETIC_TEST_HOST'
    Import-Module (Join-Path $root 'WinSecAnalyzer.psm1') -Force
    $module=Get-Module WinSecAnalyzer
    & $module {
        param($testRoot)
        $script:assertions=0
        function Assert-Test {
            param([bool]$Condition,[string]$Message)
            if (-not $Condition) { throw ('FAIL: '+$Message) }
            $script:assertions++
        }
        function Assert-Throws {
            param([scriptblock]$Action,[string]$Message)
            $threw=$false
            try { & $Action } catch { $threw=$true }
            Assert-Test $threw $Message
        }
        $script:osQueries=0; $script:collectorCalls=@{WindowsDefender=0;SMB=0}
        function Assert-WinSecWindows11 {
            $script:osQueries++
            [pscustomobject]@{Edition='SYNTHETIC';Build=22000;Caption='SYNTHETIC';Arch='SYNTHETIC'}
        }
        function Test-WinSecElevated { return $false }
        function Get-WinSecWindowsDefenderEvidence {
            [CmdletBinding()]param([switch]$Deep)
            $script:collectorCalls.WindowsDefender++
            New-WinSecPayload -Data ([ordered]@{computerStatus=[ordered]@{RealTimeProtectionEnabled=$true}}) -Sources @('SYNTHETIC')
        }
        function Get-WinSecSMBEvidence {
            [CmdletBinding()]param([switch]$Deep)
            $script:collectorCalls.SMB++
            New-WinSecPayload -Data ([ordered]@{server=[ordered]@{EnableSMB1Protocol=$false}}) -Sources @('SYNTHETIC')
        }
        $session=New-WinSecSession -OutputRoot $testRoot
        Assert-Test (-not (Test-Path -LiteralPath $testRoot)) 'Opening a session must not create an empty snapshot.'
        winsec -s system -Collector WindowsDefender -Session $session -NoBanner 6>$null
        $first=$session.Snapshot
        $context=Get-WinSecSnapshotManifest -Snapshot $first
        $firstHash=$context.Manifest.collectors[0].sha256
        winsec -s network -Collector SMB -Session $session -NoBanner 6>$null
        winsec -s system -Collector WindowsDefender -Session $session -NoBanner 6>$null
        $context=Get-WinSecSnapshotManifest -Snapshot $session.Snapshot
        Assert-Test ($session.Snapshot -eq $first) 'Sections must share one snapshot.'
        Assert-Test (@($context.Manifest.collectors).Count -eq 2) 'Collectors must not have duplicate manifest entries.'
        Assert-Test ($script:collectorCalls.WindowsDefender -eq 1 -and $script:collectorCalls.SMB -eq 1) 'Repeated scans must reuse evidence.'
        Assert-Test (@(Get-ChildItem -LiteralPath $testRoot -Filter manifest.json -File -Recurse).Count -eq 1) 'Only one UTC run is created per interactive session.'
        $entry=@($context.Manifest.collectors | Where-Object {$_.id -eq 'WindowsDefender'})[0]
        Assert-Test ($entry.sha256 -eq $firstHash) 'Adding a section must preserve earlier evidence hashes.'
        $file=Get-WinSecEvidenceFile -Context $context -CollectorId WindowsDefender
        Assert-Test ($file.runId -eq $context.Manifest.runId) 'Evidence must carry the shared run identifier.'
        $queriesBefore=$script:osQueries
        winsec -a WindowsDefender -c -Session $session -NoBanner 6>$null
        winsec -a WindowsDefender -n -Session $session -NoBanner 6>$null
        $cis=Get-ChildItem (Join-Path $context.Base 'analysis/cis') -Filter '*.json' | Select-Object -First 1
        $nist=Get-ChildItem (Join-Path $context.Base 'analysis/nist') -Filter '*.json' | Select-Object -First 1
        Assert-Test ((Get-Content $cis.FullName -Raw | ConvertFrom-Json).status -eq 'NOT_CONFIGURED') 'CIS without a pack must stay NOT_CONFIGURED.'
        Assert-Test ((Get-Content $nist.FullName -Raw | ConvertFrom-Json).status -eq 'EVIDENCE_MAPPING_ONLY') 'NIST must remain evidence mapping.'
        Assert-Test ($script:osQueries -eq $queriesBefore) 'Analysis must never call the live OS guard.'
        Assert-Throws {winsec -a WindowsDefender -n -c -Session $session} 'Combined framework switches must be rejected.'
        Assert-Throws {winsec -a 'cis,nist' -n -Session $session} 'Combined framework values must be rejected.'
        Assert-Throws {winsec -a 'nistcis' -c -Session $session} 'Combined framework names must be rejected.'
        Assert-Throws {winsec -a WindowsDefender -Session $session} 'Analysis requires one explicit framework.'
        Assert-Test ($script:osQueries -eq $queriesBefore) 'Invalid analysis commands must not query Windows.'
        $savedPath=Join-Path $context.Base ($entry.path -replace '/', [IO.Path]::DirectorySeparatorChar)
        [IO.File]::AppendAllText($savedPath,' ')
        $tamperedHash=Get-WinSecHash $savedPath
        Assert-Throws {winsec -s system -Collector WindowsDefender -Session $session -NoBanner 6>$null} 'Corrupt cached evidence must be rejected.'
        Assert-Test ((Get-WinSecHash $savedPath) -eq $tamperedHash) 'Corrupt evidence must never be overwritten.'
        Assert-Test ($script:collectorCalls.WindowsDefender -eq 1) 'Corrupt evidence must not silently trigger recollection.'
        Close-WinSecSession $session
        $closed=Get-WinSecSnapshotManifest -Snapshot $first
        Assert-Test ($closed.Manifest.sessionState -eq 'CLOSED' -and $closed.Manifest.finishedAtUtc) 'Quit must close the session with a UTC timestamp.'
        Assert-Throws {winsec -s network -Collector SMB -Session $session -NoBanner 6>$null} 'A closed session cannot be resumed.'
        $historical=New-WinSecSession -OutputRoot $testRoot -Snapshot $first
        $historical.Context=Get-WinSecSnapshotManifest -Snapshot $first
        $closedHash=Get-WinSecHash $first
        Close-WinSecSession $historical
        Assert-Test ((Get-WinSecHash $first) -eq $closedHash) 'Viewing a historical snapshot must not modify it.'
        $fresh=New-WinSecSession -OutputRoot $testRoot -Snapshot $first
        $fresh.Context=Get-WinSecSnapshotManifest -Snapshot $first
        winsec -s network -Collector SMB -Session $fresh -NoBanner 6>$null
        Assert-Test ($fresh.Snapshot -ne $first -and $fresh.RunId -ne $session.RunId) 'A new session must create its own run, never append to history.'
        Close-WinSecSession $fresh

        $atomicPath=Join-Path $testRoot 'atomic.json'
        $null=Save-WinSecJson -Path $atomicPath -Value @{synthetic='original'}
        $atomicHash=Get-WinSecHash $atomicPath
        $lock=[IO.File]::Open($atomicPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
        try { Assert-Throws {Save-WinSecJson -Path $atomicPath -Value @{synthetic='replacement'}} 'A locked destination must reject replacement.' }
        finally { $lock.Dispose() }
        Assert-Test ((Get-WinSecHash $atomicPath) -eq $atomicHash) 'Failed replacement must preserve the previous JSON.'
        Assert-Test (@(Get-ChildItem -LiteralPath $testRoot -Filter '*.tmp' -File -Force).Count -eq 0) 'Failed replacement must clean up its temporary JSON.'

        $correlationData=[ordered]@{
            service=@{Status='SYNTHETIC'};server=@{EnableSMB1Protocol=$false};tcp=@();services=@()
            members=@();users=@();exitCode=0
            'HKLM:_ScriptBlockLogging'=@{values=@{EnableScriptBlockLogging=1}}
            terminal=@{values=@{fDenyTSConnections=1}};rdpTcp=@{values=@{UserAuthentication=1}}
            rules=@();computerStatus=@{RealTimeProtectionEnabled=$true};logs=@()
        }
        $correlationRoot=Join-Path $testRoot 'SYNTHETIC_CORRELATION'
        $correlationContext=[pscustomobject]@{Base=$correlationRoot;Manifest=[pscustomobject]@{collectors=@()}}
        $rules=Get-Content (Join-Path $script:WinSecRoot 'config/correlation-rules/cross-domain.json') -Raw | ConvertFrom-Json
        foreach ($id in @($rules.correlations.required | Sort-Object -Unique)) {
            $path=Join-Path $correlationRoot ($id+'.json')
            $null=Save-WinSecJson -Path $path -Value @{schemaVersion='1';collector=$id;status='COMPLETED';data=$correlationData}
            $correlationContext.Manifest.collectors+= [pscustomobject]@{id=$id;status='COMPLETED';path=($id+'.json');sha256=(Get-WinSecHash $path)}
        }
        $correlated=Invoke-WinSecCorrelation -Context $correlationContext -Id 5
        Assert-Test (@($correlated.correlations).Count -eq 4) 'PLUS must execute all four correlations.'
        Assert-Test (@($correlated.correlations | Where-Object {$_.status -ne 'REVIEW_REQUIRED'}).Count -eq 0) 'Optional display properties must not break complete correlations.'
        $counts=@($correlated.correlations[0].facts | Where-Object {$_.label -eq 'TCP listening endpoints'})
        Assert-Test ($counts[0].available -and $counts[0].value -eq 0) 'Successfully collected empty arrays must remain available with count zero.'
        $correlationData.service=$null
        $missingPath=Join-Path $correlationRoot 'WinRM.json'
        $null=Save-WinSecJson -Path $missingPath -Value @{schemaVersion='1';collector='WinRM';status='PARTIAL';data=$correlationData}
        ($correlationContext.Manifest.collectors | Where-Object {$_.id -eq 'WinRM'}).sha256=Get-WinSecHash $missingPath
        $correlated=Invoke-WinSecCorrelation -Context $correlationContext -Id 1
        Assert-Test ($correlated.correlations[0].status -eq 'INSUFFICIENT_EVIDENCE') 'Missing required fact values must mean insufficient evidence.'
        Assert-Test (@($correlated.correlations[0].missing | Where-Object {$_ -eq 'WinRM:data.service.Status'}).Count -eq 1) 'Missing facts must identify the collector and property.'

        $parsed=ConvertFrom-WinSecInputCommand "winsec -a WindowsDefender -n -Snapshot 'C:\Synthetic path\manifest.json'"
        Assert-Test ($parsed.Analyze -eq 'WindowsDefender' -and $parsed.Nist -and $parsed.Snapshot -eq 'C:\Synthetic path\manifest.json') 'Literal commands and quoted paths must parse.'
        Assert-Test ((ConvertFrom-WinSecInputCommand 'winsec -Correlation 2').Correlation -eq 2) 'The correlation command must parse numeric arguments.'
        foreach ($unsafe in @('winsec -s; Get-Service','winsec -s | Out-Host','winsec -s > output.txt','winsec -a $(Get-Service) -n','& winsec -s','winsec -a $env:USERNAME -c','winsec -s -s')) {
            Assert-Throws {ConvertFrom-WinSecInputCommand $unsafe} ('Reject unsafe or ambiguous input: '+$unsafe)
        }
        function Get-WinSecCursor { return $null }
        function Move-WinSecCursor { param($Position) }
        function Read-WinSecKey {
            if ($script:testKeys.Count -eq 0) { throw 'Unexpected extra key read.' }
            return $script:testKeys.Dequeue()
        }
        $script:testKeys=New-Object System.Collections.Queue
        foreach ($ch in 'winsec -s syX'.ToCharArray()) {$script:testKeys.Enqueue([pscustomobject]@{VirtualKeyCode=0;Character=$ch})}
        $script:testKeys.Enqueue([pscustomobject]@{VirtualKeyCode=8;Character=[char]8})
        foreach ($ch in 'stem'.ToCharArray()) {$script:testKeys.Enqueue([pscustomobject]@{VirtualKeyCode=0;Character=$ch})}
        $script:testKeys.Enqueue([pscustomobject]@{VirtualKeyCode=13;Character=[char]13})
        $answer=Read-WinSecInput 6>$null
        Assert-Test ($answer.Text -eq 'winsec -s system' -and -not $answer.Cancelled) 'Typed commands must support Backspace and Enter.'
        $script:testKeys.Enqueue([pscustomobject]@{VirtualKeyCode=0;Character=[char]'w'})
        $script:testKeys.Enqueue([pscustomobject]@{VirtualKeyCode=27;Character=[char]27})
        $answer=Read-WinSecInput 6>$null
        Assert-Test ($answer.Cancelled -and $answer.Text -eq '') 'Esc must discard unfinished commands.'
        foreach ($ch in @('q','Q','c','N')) {
            $script:testKeys.Enqueue([pscustomobject]@{VirtualKeyCode=0;Character=[char]$ch})
            $answer=Read-WinSecInput -Shortcuts 'qcn' 6>$null
            Assert-Test ($answer.Text -eq $ch -and $script:testKeys.Count -eq 0) 'Keyboard shortcuts must work without Enter in either case.'
        }

        $empty=New-WinSecSession -OutputRoot $testRoot
        Assert-Test ((Get-WinSecCollectorState $empty WindowsDefender).Text -eq 'Not yet') 'Uncollected controls must show Not yet.'
        $empty.Context=[pscustomobject]@{Manifest=[pscustomobject]@{collectors=@([pscustomobject]@{id='WindowsDefender';status='COMPLETED'})}}
        Assert-Test ((Get-WinSecCollectorState $empty WindowsDefender).Color -eq 'Green') 'Completed collection must show green.'
        $empty.Context.Manifest.collectors[0].status='PARTIAL'
        Assert-Test ((Get-WinSecCollectorState $empty WindowsDefender).Color -eq 'Yellow') 'Partial collection must not show green.'
        function Clear-Host {}
        function Show-WinSecBanner {}
        $catalog=@(Get-WinSecCatalog)
        $screen=@(Show-WinSecMenuPage -View main -Session (New-WinSecSession -OutputRoot $testRoot) -Domain all -Catalog $catalog 6>&1)
        $screenText=($screen | ForEach-Object {$_.ToString()}) -join [Environment]::NewLine
        foreach($number in 1..6) {Assert-Test ($screenText.Contains('['+$number+']')) 'Every domain must appear in the main menu.'}
        Assert-Test ($screenText -match 'PLUS' -and $screenText -match '\[7\]' -and $screenText -notmatch '\[8\]|\[9\]|\[0\]|Select an option') 'Main menu must keep extras outside the six sections.'

        $script:views=New-Object 'System.Collections.Generic.List[string]'
        function Show-WinSecMenuPage {param($View,$Session,$Domain,$Agent,$Catalog) $script:views.Add($View)}
        $script:answers=New-Object System.Collections.Queue
        foreach ($text in @('1','help','ESC','1','a','ESC','ESC','ESC','7','ESC','Q')) {
            $script:answers.Enqueue([pscustomobject]@{Cancelled=($text -eq 'ESC');Text=$text})
        }
        function Read-WinSecInput {
            param($Hints,$Shortcuts)
            if ($script:answers.Count -eq 0) {throw 'Unexpected extra menu read.'}
            return $script:answers.Dequeue()
        }
        Invoke-WinSecMenu -OutputRoot $testRoot
        Assert-Test (($script:views -join ',') -eq 'main,section,help,section,control,framework,control,section,main,correlations,main') 'Esc and Q must navigate every menu level.'
        Assert-Test ($script:answers.Count -eq 0) 'Q must exit without an extra confirmation.'

        function Show-WinSecMenuPage {
            param($View,$Session,$Domain,$Agent,$Catalog)
            $script:observedSession=$Session
        }
        foreach ($text in @('winsec -s system -Collector WindowsDefender','ESC','winsec -s network -Collector SMB','ESC','1','1','a','c','ESC','q')) {
            $script:answers.Enqueue([pscustomobject]@{Cancelled=($text -eq 'ESC');Text=$text})
        }
        Invoke-WinSecMenu -OutputRoot $testRoot 6>$null
        $uiContext=Get-WinSecSnapshotManifest -Snapshot $script:observedSession.Snapshot
        Assert-Test (@($uiContext.Manifest.collectors).Count -eq 2 -and $uiContext.Manifest.sessionState -eq 'CLOSED') 'Typed section scans and control analysis must share one closed UI session.'
        Assert-Test ($uiContext.Manifest.runId -ne $session.RunId) 'Opening the UI again must not reuse a previous run.'
        Assert-Test ((Get-WinSecCollectorState $script:observedSession WindowsDefender).Text -eq 'Scanned') 'UI scans must update the displayed collector state.'

        function Invoke-WinSecCollection {
            param($Domain,$Collector,$OutputRoot,$Deep,$Session)
            $script:aliasRoute=[pscustomobject]@{Domain=$Domain;Collector=$Collector}
            return 'SYNTHETIC_PATH'
        }
        function Invoke-WinSecNamedAnalysis {
            param($Framework,$Correlation,$Snapshot,$OutputRoot,$CollectorFilter,$DomainFilter)
            $script:aliasAnalysis=[pscustomobject]@{Framework=$Framework;Collector=$CollectorFilter;Domain=$DomainFilter}
        }
        foreach ($pair in @(
            @('win-defender','WindowsDefender'),@('win-firewall','WindowsFirewall'),
            @('win-bitlocker','BitLocker'),@('win-update','WindowsUpdate'),
            @('win-network','NetworkSecurity'),@('win-identity','IdentityAccess'),
            @('win-logging','LoggingAuditing'),@('win-services','ServicesHardening')
        )) {
            & $pair[0] -s -OutputRoot $testRoot
            Assert-Test ($script:aliasRoute.Collector -eq $pair[1] -or $script:aliasRoute.Domain -eq $pair[1]) 'Short scan commands must retain their intended target.'
            & $pair[0] -a -n -Snapshot 'SYNTHETIC_PATH'
            Assert-Test ($script:aliasAnalysis.Framework -eq 'nist' -and ($script:aliasAnalysis.Collector -eq $pair[1] -or $script:aliasAnalysis.Domain -eq $pair[1])) 'Short analysis commands must use exactly the selected framework and target.'
        }
        Write-Output ('PASS: '+$script:assertions+' UI/session assertions')
    } $testRoot
} finally {
    $env:COMPUTERNAME=$previousComputerName
    $resolved=[IO.Path]::GetFullPath($testRoot)
    if (-not $resolved.StartsWith($tempRoot,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($resolved) -notlike 'winsec-ui-test-*') { throw 'Unsafe test cleanup path.' }
    if (Test-Path -LiteralPath $resolved) { Remove-Item -LiteralPath $resolved -Recurse -Force }
    Remove-Module WinSecAnalyzer -ErrorAction SilentlyContinue
}
