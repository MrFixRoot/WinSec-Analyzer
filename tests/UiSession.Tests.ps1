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
        $script:nativeProgressCalls=0
        function Write-Progress {param($Activity,$Status,$PercentComplete,[switch]$Completed) $script:nativeProgressCalls++}
        function Assert-WinSecWindows11 {
            $script:osQueries++
            [pscustomobject]@{Edition='SYNTHETIC';Build=22000;Caption='SYNTHETIC';Arch='SYNTHETIC'}
        }
        function Test-WinSecElevated { return $false }
        function Get-WinSecLocalDevice {
            [pscustomobject]@{
                id=(Get-WinSecDeviceId $env:COMPUTERNAME);host=$env:COMPUTERNAME
                hardware=[pscustomobject]@{manufacturer='SYNTHETIC';model='SYNTHETIC';memoryBytes=8GB;processors=@('SYNTHETIC')}
                os=[pscustomobject]@{family='Windows11';edition='SYNTHETIC';build=22000;arch='SYNTHETIC';productType=1}
                warnings=@()
            }
        }
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
        winsec -s windowsDefender -Session $session -NoBanner 6>$null
        $first=$session.Snapshot
        $context=Get-WinSecSnapshotManifest -Snapshot $first
        $firstHash=$context.Manifest.collectors[0].sha256
        winsec -s smb -Session $session -NoBanner 6>$null
        winsec -s windowsDefender -Session $session -NoBanner 6>$null
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
        $manifestHash=Get-WinSecHash $first
        winsec -a windowsDefender -c -Session $session -NoBanner 6>$null
        winsec -a windowsDefender -n -Session $session -NoBanner 6>$null
        $cis=Join-Path $context.Base 'export/cisf/windowsDefender.json'
        $nist=Join-Path $context.Base 'export/nistcsf/windowsDefender.json'
        Assert-Test ((Get-Content $cis -Raw | ConvertFrom-Json).status -eq 'NOT_CONFIGURED') 'CIS without a pack must stay NOT_CONFIGURED.'
        Assert-Test ((Get-Content $nist -Raw | ConvertFrom-Json).status -eq 'EVIDENCE_MAPPING_ONLY') 'NIST must remain evidence mapping.'
        $cisHash=Get-WinSecHash $cis
        winsec -a windowsDefender -n -Session $session -NoBanner 6>$null
        Assert-Test ((Get-WinSecHash $cis) -eq $cisHash) 'Updating a NIST export must preserve the CIS result.'
        foreach ($framework in @('c','n')) {
            $flags=@{$framework=$true}
            winsec -a network @flags -Session $session -NoBanner 6>$null
            winsec -a networkSecurity @flags -Session $session -NoBanner 6>$null
        }
        foreach ($folder in @('cisf','nistcsf')) {
            $exportRoot=Join-Path $context.Base ('export/'+$folder)
            Assert-Test (@(Get-ChildItem $exportRoot -Filter '*.json').Count -eq 2) 'Repeated analysis and section aliases must reuse the same export names.'
            $controlExport=Get-Content (Join-Path $exportRoot 'windowsDefender.json') -Raw | ConvertFrom-Json
            $sectionExport=Get-Content (Join-Path $exportRoot 'networkSecurity.json') -Raw | ConvertFrom-Json
            Assert-Test ($controlExport.scope.type -eq 'control' -and $controlExport.scope.id -eq 'WindowsDefender') 'Control exports must identify the selected collector.'
            Assert-Test ($sectionExport.scope.type -eq 'section' -and $sectionExport.scope.id -eq 'NetworkSecurity') 'Section exports must use the canonical section name.'
            Assert-Test ($sectionExport.schemaVersion -eq '1' -and $sectionExport.sourceRunId -eq $context.Manifest.runId -and $sectionExport.generatedAtUtc -match 'Z$') 'Exports must identify their schema, source snapshot and generation time in UTC.'
        }
        Assert-Test (-not (Test-Path (Join-Path $context.Base 'analysis'))) 'Framework analysis must not create the old analysis directory.'
        Assert-Test ((Get-WinSecHash $first) -eq $manifestHash -and (Get-WinSecHash (Join-Path $context.Base $entry.path)) -eq $firstHash) 'Exports must preserve the source manifest and evidence.'
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
        $correlationContext=[pscustomobject]@{
            Base=$correlationRoot
            Manifest=[pscustomobject]@{
                schemaVersion='1';runId='SYNTHETIC_CORRELATION';host='SYNTHETIC';status='COMPLETED'
                os=[pscustomobject]@{family='Windows11';edition='SYNTHETIC';build=22000;productType=1}
                collectors=@()
            }
        }
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
        $correlationManifest=Join-Path $correlationRoot 'manifest.json'
        $null=Save-WinSecJson -Path $correlationManifest -Value $correlationContext.Manifest
        $queriesBefore=$script:osQueries
        $manifestHash=Get-WinSecHash $correlationManifest
        winsec -r -Snapshot $correlationManifest -NoBanner 6>$null
        $correlationDirectory=Join-Path $correlationRoot 'correlations'
        $correlationNames=@{
            1='networkSecurity+servicesHardening.json'
            2='identityAccess+loggingAuditing.json'
            3='networkSecurity+identityAccess.json'
            4='systemSecurity+loggingAuditing.json'
        }
        Assert-Test (@(Get-ChildItem $correlationDirectory -Filter '*.json').Count -eq 4) 'Bare -r must save four separate section-pair files, without an aggregate copy.'
        foreach ($id in 1..4) {
            $pair=Get-Content (Join-Path $correlationDirectory $correlationNames[$id]) -Raw | ConvertFrom-Json
            Assert-Test (@($pair.correlations).Count -eq 1 -and $pair.correlations[0].id -eq $id) 'Each correlation file must contain only its own section pair.'
            Assert-Test ($pair.scope.type -eq 'correlation' -and $pair.scope.id -eq $id -and @($pair.scope.domains).Count -eq 2 -and $pair.sourceRunId -eq $correlationContext.Manifest.runId) 'Correlation exports must identify the pair and source snapshot.'
        }
        foreach ($id in 1..4) { winsec -r $id -Snapshot $correlationManifest -NoBanner 6>$null }
        Assert-Test (@(Get-ChildItem $correlationDirectory -Filter '*.json').Count -eq 4) 'Repeating individual correlations must update the existing pair files.'
        Assert-Test (-not (Test-Path (Join-Path $correlationRoot 'analysis'))) 'Correlations must not create the old analysis directory.'
        Assert-Test ((Get-WinSecHash $correlationManifest) -eq $manifestHash) 'Correlation exports must preserve the source manifest.'
        $pairHashes=@{}
        foreach ($id in 2..4) { $pairHashes[$id]=Get-WinSecHash (Join-Path $correlationDirectory $correlationNames[$id]) }
        winsec -a network -n -Snapshot $correlationManifest -NoBanner 6>$null
        $reportPath=Invoke-WinSecReport -Context $correlationContext 6>$null
        $report=Get-Content $reportPath -Raw | ConvertFrom-Json
        Assert-Test (@($report.analyses).Count -eq 5) 'The report must index framework exports and all four correlation files.'
        Assert-Test (@($report.analyses | Where-Object {$_.path -eq 'export/nistcsf/networkSecurity.json'}).Count -eq 1) 'The report must retain an unambiguous relative export path.'
        foreach ($result in $report.analyses) {
            Assert-Test ($result.sha256 -eq (Get-WinSecHash (Join-Path $correlationRoot $result.path))) 'Report entries must include the current result hashes.'
        }
        foreach ($invalid in @('0','5','network')) {
            Assert-Throws {winsec -r $invalid -Snapshot $correlationManifest -NoBanner} '-r only accepts 1 through 4, or no number for all.'
        }
        Assert-Throws {winsec -r -s -Snapshot $correlationManifest -NoBanner} 'Correlation cannot trigger collection.'
        Assert-Test ($script:osQueries -eq $queriesBefore) 'Correlation shortcuts must use saved JSON without querying Windows.'
        $correlationData.service=$null
        $missingPath=Join-Path $correlationRoot 'WinRM.json'
        $null=Save-WinSecJson -Path $missingPath -Value @{schemaVersion='1';collector='WinRM';status='PARTIAL';data=$correlationData}
        ($correlationContext.Manifest.collectors | Where-Object {$_.id -eq 'WinRM'}).sha256=Get-WinSecHash $missingPath
        $correlated=Invoke-WinSecCorrelation -Context $correlationContext -Id 1
        Assert-Test ($correlated.correlations[0].status -eq 'INSUFFICIENT_EVIDENCE') 'Missing required fact values must mean insufficient evidence.'
        Assert-Test (@($correlated.correlations[0].missing | Where-Object {$_ -eq 'WinRM:data.service.Status'}).Count -eq 1) 'Missing facts must identify the collector and property.'
        $null=Save-WinSecJson -Path $correlationManifest -Value $correlationContext.Manifest
        winsec -r 1 -Snapshot $correlationManifest -NoBanner 6>$null
        $updated=Get-Content (Join-Path $correlationDirectory $correlationNames[1]) -Raw | ConvertFrom-Json
        Assert-Test ($updated.correlations[0].status -eq 'INSUFFICIENT_EVIDENCE') 'A repeated correlation must replace its previous result at the same path.'
        foreach ($id in 2..4) {
            Assert-Test ((Get-WinSecHash (Join-Path $correlationDirectory $correlationNames[$id])) -eq $pairHashes[$id]) 'An individual correlation must preserve other pair files.'
        }

        $parsed=ConvertFrom-WinSecInputCommand "winsec -a WindowsDefender -n -Snapshot 'C:\Synthetic path\manifest.json'"
        Assert-Test ($parsed.Analyze -eq 'WindowsDefender' -and $parsed.Nist -and $parsed.Snapshot -eq 'C:\Synthetic path\manifest.json') 'Literal commands and quoted paths must parse.'
        Assert-Test ((ConvertFrom-WinSecInputCommand 'winsec -Correlation 2').Correlation -eq 2) 'The correlation command must parse numeric arguments.'
        $parsed=ConvertFrom-WinSecInputCommand 'winsec -r 2'
        Assert-Test ($parsed.Correlate -and $parsed.Domain -eq 2) 'The interactive parser must support the optional -r number.'
        Assert-Test ((ConvertFrom-WinSecInputCommand 'winsec -r').Correlate) 'The interactive parser must support bare -r.'
        Assert-Test ((Resolve-WinSecTarget 'login').Domain -eq 'LoggingAuditing') 'login must select Logging & Auditing.'
        $serviceControl=Resolve-WinSecTarget 'services'
        $serviceSection=Resolve-WinSecTarget 'servicesHardening'
        Assert-Test ($serviceControl.Collector -eq 'Services' -and -not $serviceSection.Collector -and $serviceSection.Domain -eq 'ServicesHardening') 'The services control and Services & Hardening section must have distinct example targets.'
        foreach ($pair in @(@('WindowsDefender','windowsDefender'),@('TPM','tpm'),@('UAC','uac'),@('TCPListeners','tcpListeners'),@('DNSAndProxy','dnsAndProxy'))) {
            Assert-Test ((ConvertTo-WinSecControlName $pair[0]) -ceq $pair[1]) 'User-facing control names must use camelCase and lowercase initialisms.'
        }
        $hintSession=New-WinSecSession -OutputRoot $testRoot
        foreach ($scope in @('section','control','correlations')) {
            $hintSession.HintIndex=0
            for ($i=0; $i -lt 3; $i++) {
                $control=if ($scope -eq 'control') {'WindowsFirewall'} else {''}
                $hint=@(Get-WinSecHint -Session $hintSession -Domain NetworkSecurity -Collector $control -View $scope)
                $command=$hint[-1]
                $pattern=switch ($scope) {
                    'control' {'^winsec -(s|a) windowsFirewall( -[cn])?$'}
                    'correlations' {'^winsec -r( [1-4])?$'}
                    default {''}
                }
                if ($scope -eq 'section') {
                    $parsedHint=ConvertFrom-WinSecInputCommand $command
                    $hintTarget=if ($parsedHint.ContainsKey('Analyze')) {$parsedHint.Analyze} else {$parsedHint.Domain}
                    $selection=Resolve-WinSecTarget $hintTarget
                    Assert-Test ($selection.Domain -eq 'NetworkSecurity' -and ($parsedHint.ContainsKey('Scan') -or $selection.Collector)) 'A control-list hint must scan its section or analyze one of its controls.'
                } else {
                    Assert-Test ($command -cmatch $pattern) 'Examples must be specific to the current control or correlation view.'
                }
            }
        }
        foreach ($section in @(Get-WinSecSections)) {
            $sectionTarget=Resolve-WinSecTarget $section.Command
            Assert-Test (-not $sectionTarget.Collector -and $sectionTarget.Domain -eq $section.Domain) 'Every section command must select the whole section rather than a same-named control.'
            $agents=@(Get-WinSecCatalog | Where-Object {$_.domain -eq $section.Domain})
            $renderedHelp=@(Show-WinSecHelp -Domain $section.Domain 6>&1)
            $renderedText=($renderedHelp | ForEach-Object {$_.ToString()}) -join [Environment]::NewLine
            $hintSession.HintIndex=0
            $examples=@(for ($i=0; $i -lt (1+2*$agents.Count); $i++) {
                $lines=@(Get-WinSecHint -Session $hintSession -Domain $section.Domain -View section)
                $lines[-1]
            })
            foreach ($agent in $agents) {
                $name=ConvertTo-WinSecControlName $agent.id
                foreach ($flag in @('n','c')) {
                    $example='winsec -a '+$name+' -'+$flag
                    Assert-Test ($renderedText.Contains($example)) 'Every registered control must have its own NIST and CIS help examples.'
                    Assert-Test ($examples -ccontains $example) 'Control-list hints must cover every control in the section.'
                }
            }
        }
        $controlHelp=@(Show-WinSecHelp -Domain SystemSecurity -Collector WindowsFirewall 6>&1)
        $helpText=($controlHelp | ForEach-Object {$_.ToString()}) -join [Environment]::NewLine
        Assert-Test ($helpText -cmatch 'winsec -s windowsFirewall' -and $helpText -cmatch 'winsec -a windowsFirewall -c') 'Control help must use the selected control rather than the first collector.'
        foreach ($agent in @(Get-WinSecCatalog | Where-Object {$_.domain -eq 'SystemSecurity'})) {
            $name=ConvertTo-WinSecControlName $agent.id
            foreach ($flag in @('n','c')) {
                $example='winsec -a '+$name+' -'+$flag
                Assert-Test ([regex]::Matches($helpText,[regex]::Escape($example)).Count -eq 1) 'Selecting a control must not replace or duplicate another control analysis example.'
            }
        }
        Assert-Test ($helpText -notmatch 'Selecciona el numero|Esc:|Q / q|sesion interactiva|winsec -a all') 'Control help must remain compact.'
        foreach ($unsafe in @('winsec -s; Get-Service','winsec -s | Out-Host','winsec -s > output.txt','winsec -a $(Get-Service) -n','& winsec -s','winsec -a $env:USERNAME -c','winsec -s -s','help','?','winsec -Help')) {
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
        foreach ($ch in 'winsec -s '.ToCharArray()) {$script:testKeys.Enqueue([pscustomobject]@{VirtualKeyCode=0;Character=$ch})}
        $script:testKeys.Enqueue([pscustomobject]@{VirtualKeyCode=112;Character=[char]0})
        $answer=Read-WinSecInput 6>$null
        Assert-Test ($answer.HelpRequested -and -not $answer.Cancelled -and $answer.Text -eq '' -and $script:testKeys.Count -eq 0) 'F1 must request help immediately without submitting a partially typed command.'
        foreach ($ch in @('q','Q','c','N')) {
            $script:testKeys.Enqueue([pscustomobject]@{VirtualKeyCode=0;Character=[char]$ch})
            $answer=Read-WinSecInput -Shortcuts 'qcn' 6>$null
            Assert-Test ($answer.Text -eq $ch -and $script:testKeys.Count -eq 0) 'Keyboard shortcuts must work without Enter in either case.'
        }
        foreach ($key in @(@(113,'Rename'),@(46,'Delete'),@(38,'Up'),@(40,'Down'))) {
            $script:testKeys.Enqueue([pscustomobject]@{VirtualKeyCode=$key[0];Character=[char]0})
            $answer=Read-WinSecInput -Actions @('Rename','Delete','Up','Down') 6>$null
            Assert-Test ($answer.Action -eq $key[1] -and $answer.Text -eq '' -and $script:testKeys.Count -eq 0) 'Inventory keys must return explicit actions without Enter.'
        }
        $script:testKeys.Enqueue([pscustomobject]@{VirtualKeyCode=46;Character=[char]0})
        $script:testKeys.Enqueue([pscustomobject]@{VirtualKeyCode=13;Character=[char]13})
        $answer=Read-WinSecInput 6>$null
        Assert-Test ($answer.Action -eq '') 'Delete must have no inventory action outside the inventory view.'

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
        Assert-Test ($screenText -match 'PLUS' -and $screenText -match '\[\+\]' -and $screenText -notmatch '\[7\]|\[8\]|\[9\]|\[0\]|Select an option') 'Main menu must keep extras outside the six sections.'
        $displaySession=New-WinSecSession -OutputRoot $testRoot -Snapshot $first
        $displaySession.Context=$context
        $displaySession.RunId=$context.Manifest.runId
        $shortPath='../SYNTHETIC_TEST_HOST\'+(Split-Path -Leaf $context.Base)+'\manifest.json'
        $snapshotScreen=@(Show-WinSecMenuPage -View section -Session $displaySession -Domain SystemSecurity -Catalog $catalog 6>&1)
        $snapshotText=($snapshotScreen | ForEach-Object {$_.ToString()}) -join [Environment]::NewLine
        Assert-Test ($snapshotText.Contains('Snapshot saved: '+$shortPath) -and -not $snapshotText.Contains($context.Base)) 'Scan confirmation must show only the host, run folder and manifest, without the absolute path.'
        Assert-Test ((Format-WinSecSnapshotPath $context.Base) -eq $shortPath) 'Snapshot directory inputs must use the same compact manifest path.'

        $script:views=New-Object 'System.Collections.Generic.List[string]'
        function Show-WinSecMenuPage {param($View,$Session,$Domain,$Agent,$Catalog) $script:views.Add($View)}
        $script:answers=New-Object System.Collections.Queue
        foreach ($text in @('','1','F1','ESC','1','a','ESC','ESC','ESC','+','ESC','Q')) {
            $script:answers.Enqueue([pscustomobject]@{Cancelled=($text -eq 'ESC');HelpRequested=($text -eq 'F1');Text=$text})
        }
        function Read-WinSecInput {
            param($Hints,$Shortcuts)
            if ($Hints -contains 'Press Enter to return.') { $script:resultWaits++ }
            if ($script:answers.Count -eq 0) {throw 'Unexpected extra menu read.'}
            return $script:answers.Dequeue()
        }
        $script:resultWaits=0
        Invoke-WinSecMenu -OutputRoot $testRoot
        Assert-Test (($script:views -join ',') -eq 'main,section,help,section,control,framework,control,section,main,correlations,main') 'F1 must open context help and Esc must return to the previous view.'
        Assert-Test ($script:answers.Count -eq 0) 'Q must exit without an extra confirmation.'
        $queriesBefore=$script:osQueries
        $script:answers.Enqueue([pscustomobject]@{Cancelled=$false;HelpRequested=$true;Text=''})
        $script:answers.Enqueue([pscustomobject]@{Cancelled=$true;HelpRequested=$false;Text=''})
        $quitAfterHelp=Wait-WinSecResult -Domain SystemSecurity -Collector WindowsFirewall 6>$null
        Assert-Test (-not $quitAfterHelp -and $script:answers.Count -eq 0 -and $script:osQueries -eq $queriesBefore) 'F1 must open result help and Esc must return without collecting evidence or quitting.'

        function Show-WinSecMenuPage {
            param($View,$Session,$Domain,$Agent,$Catalog)
            $script:observedSession=$Session
            $script:views.Add($View+':'+$Domain)
        }
        $waitsBefore=$script:resultWaits
        $viewsBefore=$script:views.Count
        foreach ($text in @('','winsec -s system -Collector WindowsDefender','winsec -s windowsDefender','winsec -s network -Collector SMB','ESC','1','1','a','c','ESC','q')) {
            $script:answers.Enqueue([pscustomobject]@{Cancelled=($text -eq 'ESC');HelpRequested=$false;Text=$text})
        }
        Invoke-WinSecMenu -OutputRoot $testRoot 6>$null
        $uiContext=Get-WinSecSnapshotManifest -Snapshot $script:observedSession.Snapshot
        Assert-Test (@($uiContext.Manifest.collectors).Count -eq 2 -and $uiContext.Manifest.sessionState -eq 'CLOSED') 'Typed section scans and control analysis must share one closed UI session.'
        Assert-Test ($uiContext.Manifest.runId -ne $session.RunId) 'Opening the UI again must not reuse a previous run.'
        Assert-Test ((Get-WinSecCollectorState $script:observedSession WindowsDefender).Text -eq 'Scanned') 'UI scans must update the displayed collector state.'
        Assert-Test ($script:resultWaits -eq $waitsBefore+1) 'New and cached scans must return automatically; only the framework result may pause.'
        Assert-Test ($script:nativeProgressCalls -eq 0) 'Interactive scans must keep progress below the logo instead of using the native progress overlay.'
        Assert-Test ($script:views[$viewsBefore+1] -eq 'section:SystemSecurity' -and $script:views[$viewsBefore+3] -eq 'section:NetworkSecurity') 'Scan commands must reopen the selected section controls automatically.'

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
            if ($pair[0] -eq 'win-services') {
                Assert-Test (-not $script:aliasRoute.Collector) 'win-services must scan the whole Services & Hardening section.'
            }
            & $pair[0] -a -n -Snapshot 'SYNTHETIC_PATH'
            Assert-Test ($script:aliasAnalysis.Framework -eq 'nist' -and ($script:aliasAnalysis.Collector -eq $pair[1] -or $script:aliasAnalysis.Domain -eq $pair[1])) 'Short analysis commands must use exactly the selected framework and target.'
            if ($pair[0] -eq 'win-services') {
                Assert-Test (-not $script:aliasAnalysis.Collector) 'win-services analysis must cover the whole Services & Hardening section.'
            }
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
