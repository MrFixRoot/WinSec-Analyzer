[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Services/TechnicalFrameworkAnalysis.ps1')
. (Join-Path $root 'tests/Fixtures/TechnicalFrameworkMemory.ps1')
function Get-CimInstance {throw 'Native query forbidden.'}
function Get-SmbServerConfiguration {throw 'Native query forbidden.'}
function Get-Service {throw 'Native query forbidden.'}
function Invoke-WebRequest {throw 'Online analysis forbidden.'}
$passed=0;$failed=0
function Assert-TFA {param([bool]$Condition);if(-not $Condition){throw 'Technical framework assertion failed.'}}
function Reject-TFA {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-TFA $caught}
function Test-TFA {param($CaseName,[scriptblock]$Action);try{& $Action;$script:passed++;Write-Host ('[PASS] '+$CaseName)}catch{$script:failed++;Write-Host ('[FAIL] '+$CaseName+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}
function Analyze-TFA {param($Fixture,[string]$Framework='nist-csf',[switch]$Section)
    New-WinSecTechnicalFrameworkView -Selection (New-WinSecTechnicalFrameworkSelection $Fixture -Section:$Section) -FrameworkId $Framework -Sources @((New-WinSecTechnicalFrameworkSource $Fixture))
}
foreach($framework in @('nist-csf','cis-controls','mitre-attack')){
    Test-TFA ('Enabled Guest has a sourced contextual warning: '+$framework) {
        $f=New-WinSecTechnicalFrameworkFixture Guest;$v=Analyze-TFA $f $framework
        Assert-TFA ($v.Findings.Count -eq 1 -and $v.Findings[0].RuleId -ceq 'TF-GUEST-001' -and $v.Findings[0].Relation.FrameworkId -ceq $framework -and $v.Findings[0].Evidence[0].Value -ceq $false)
    }
    Test-TFA ('Disabled Guest is evaluated without a finding: '+$framework) {
        $f=New-WinSecTechnicalFrameworkFixture Guest;$f.Sources[1].Data[0].Disabled=$true;$v=Analyze-TFA $f $framework
        Assert-TFA ($v.Findings.Count -eq 0 -and $v.RuleOutcomes[0].State -ceq 'EVALUATED' -and $v.Coverage.Treatments.EVALUATED -eq 1)
    }
    Test-TFA ('Unknown Guest is not a warning: '+$framework) {
        $f=New-WinSecTechnicalFrameworkFixture Guest;$f.Sources[1].Data[0].Disabled=$null;$v=Analyze-TFA $f $framework
        Assert-TFA ($v.Findings.Count -eq 0 -and $v.Coverage.Treatments.UNKNOWN -ge 1 -and $v.RuleOutcomes[0].State -ceq 'UNRESOLVED_READING')
    }
    Test-TFA ('Every SMB reading has exactly one treatment: '+$framework) {
        $f=New-WinSecTechnicalFrameworkFixture;$source=New-WinSecTechnicalFrameworkSource $f
        $v=New-WinSecTechnicalFrameworkView (New-WinSecTechnicalFrameworkSelection $f) $framework @($source)
        $sum=0;foreach($p in $v.Coverage.Treatments.PSObject.Properties){$sum+=$p.Value}
        Assert-TFA ($sum -eq $v.Coverage.ReadingCount -and $sum -eq @($source.Snapshot.Batches|ForEach-Object Records|ForEach-Object Readings).Count -and $v.Findings[0].RuleId -ceq 'TF-SMB-001')
    }
}
Test-TFA 'MITRE selects an extra verified predicate instead of changing only headings' {
    $f=New-WinSecTechnicalFrameworkFixture;$nist=Analyze-TFA $f;$cis=Analyze-TFA $f cis-controls;$mitre=Analyze-TFA $f mitre-attack
    Assert-TFA ($nist.Findings.Count -eq 1 -and $cis.Findings.Count -eq 1 -and $mitre.Findings.Count -eq 2 -and $mitre.Findings[1].RuleId -ceq 'TF-SMB-002' -and $nist.Coverage.Treatments.EVALUATED -eq 1 -and $mitre.Coverage.Treatments.EVALUATED -eq 4)
}
foreach($field in @('RequireSecuritySignature','EncryptData')){
    Test-TFA ('Compensating setting suppresses the signing review: '+$field) {
        $f=New-WinSecTechnicalFrameworkFixture;$f.Sources[1].Data.$field=$true;$v=Analyze-TFA $f mitre-attack
        Assert-TFA ($v.Findings.Count -eq 1 -and $v.RuleOutcomes[1].State -ceq 'EVALUATED')
    }
    Test-TFA ('Unknown prerequisite blocks signing review: '+$field) {
        $f=New-WinSecTechnicalFrameworkFixture;$f.Sources[1].Data.$field=$null;$v=Analyze-TFA $f mitre-attack
        Assert-TFA ($v.Findings.Count -eq 1 -and $v.RuleOutcomes[1].State -ceq 'UNRESOLVED_READING' -and $v.Coverage.Treatments.UNRESOLVED_RULE -ge 1)
    }
}
Test-TFA 'Disabled modern SMB is not a signing weakness finding' {
    $f=New-WinSecTechnicalFrameworkFixture;$f.Sources[1].Data.EnableSMB2Protocol=$false;$v=Analyze-TFA $f mitre-attack
    Assert-TFA ($v.Findings.Count -eq 1)
}
foreach($state in @('ERROR','NOT_COLLECTED')){
    Test-TFA ('Unavailable inventory remains a separate coverage limitation: '+$state) {
        $f=New-WinSecTechnicalFrameworkFixture Guest;$f.Sources[1].State=$state;$f.Sources[1].Data=$null;$v=Analyze-TFA $f
        Assert-TFA ($v.Findings.Count -eq 0 -and $v.RuleOutcomes[0].State -ceq 'NO_DATA' -and $null -eq $v.Sources[0].Inventories[1].ReportedRecords -and $v.Sources[0].Collection.Status -ceq 'PARTIAL')
    }
}
Test-TFA 'Absent physical registry configuration is not a failure' {
    $f=New-WinSecTechnicalFrameworkFixture;$f.Sources[5].Data.GuestPolicy=[pscustomobject]@{State='NOT_CONFIGURED';Kind=$null;Value=$null};$v=Analyze-TFA $f
    Assert-TFA ($v.Coverage.Treatments.NOT_CONFIGURED -eq 1 -and $v.Findings.Count -eq 1)
}
Test-TFA 'A service being Running or Disabled creates no unsupported rule' {
    $f=New-WinSecTechnicalFrameworkFixture Services;$v=Analyze-TFA $f
    Assert-TFA ($v.Findings.Count -eq 0 -and $v.RuleOutcomes.Count -eq 0 -and $v.Coverage.Treatments.INFORMATIVE_NO_RULE -gt 0 -and $v.Coverage.Treatments.NOT_COLLECTED -eq 5)
}
Test-TFA 'Section analysis preserves original control scope and lists missing controls' {
    $f=New-WinSecTechnicalFrameworkFixture Guest;$v=Analyze-TFA $f -Section
    Assert-TFA ($v.Selection.ScopeType -ceq 'SECTION' -and $v.Sources[0].Identity.ScopeType -ceq 'CONTROL' -and $v.Sources[0].Identity.ScanId -ceq $f.Identity.ScanId -and $v.Coverage.MissingCheckIds.Count -eq 2)
}
Test-TFA 'No source means explicit missing coverage and no findings' {
    $f=New-WinSecTechnicalFrameworkFixture Guest;$v=New-WinSecTechnicalFrameworkView (New-WinSecTechnicalFrameworkSelection $f) nist-csf
    Assert-TFA ($v.Findings.Count -eq 0 -and $v.Coverage.ReadingCount -eq 0 -and $v.Coverage.MissingCheckIds.Count -eq 1)
}
Test-TFA 'Analysis identity is independent and source identity remains unchanged' {
    $f=New-WinSecTechnicalFrameworkFixture Guest;$v=Analyze-TFA $f
    Assert-TFA ($v.AnalysisId -cne $f.Identity.ScanId -and $v.AnalysisId -cne $f.Identity.SnapshotId -and $v.Sources[0].Identity.ScanId -ceq $v.Findings[0].ScanId -and $v.Sources[0].SnapshotSha256 -cmatch '^[A-F0-9]{64}$')
}
Test-TFA 'No identifiable account values enter the summarized view' {
    $f=New-WinSecTechnicalFrameworkFixture Guest;$v=Analyze-TFA $f;$json=ConvertTo-Json $v -Depth 16
    Assert-TFA ($json -notmatch 'Guest - Synthetic|S-1-5-21-11-22-33|SYNTHETIC-PC' -and $v.Findings[0].Evidence[0].Value -is [bool])
}
Test-TFA 'Progress counts real readings without repeating providers' {
    $f=New-WinSecTechnicalFrameworkFixture Guest;$events=New-Object 'Collections.Generic.List[object]'
    $v=New-WinSecTechnicalFrameworkView (New-WinSecTechnicalFrameworkSelection $f) nist-csf @((New-WinSecTechnicalFrameworkSource $f)) -ProgressCallback {param($e);$events.Add($e)}
    Assert-TFA ($events.Count -eq $v.Coverage.ReadingCount -and $events[$events.Count-1].Completed -eq $v.Coverage.ReadingCount -and $events[0].Completed -eq 1)
}
Test-TFA 'Cancellation before analysis preserves the previous view reference' {
    $f=New-WinSecTechnicalFrameworkFixture Guest;$old=Analyze-TFA $f;$result=Update-WinSecTechnicalFrameworkCache $old (New-WinSecTechnicalFrameworkSelection $f) mitre-attack @((New-WinSecTechnicalFrameworkSource $f)) -CancellationAction {$true}
    Assert-TFA ($result.Status -ceq 'CANCELLED' -and [object]::ReferenceEquals($old,$result.View))
}
Test-TFA 'Cancellation while processing readings cannot replace a valid view' {
    $f=New-WinSecTechnicalFrameworkFixture Guest;$old=Analyze-TFA $f;$cancelFixture=@{Cancel=$false}
    $result=Update-WinSecTechnicalFrameworkCache $old (New-WinSecTechnicalFrameworkSelection $f) nist-csf @((New-WinSecTechnicalFrameworkSource $f)) -CancellationAction {$cancelFixture.Cancel}.GetNewClosure() -ProgressCallback {param($e);$cancelFixture.Cancel=$true}.GetNewClosure()
    Assert-TFA ($result.Status -ceq 'CANCELLED' -and [object]::ReferenceEquals($old,$result.View))
}
foreach($change in @('Device','Scope','Catalog','Snapshot','Duplicate','Origin')){
    Test-TFA ('Foreign or unreviewed input rejects: '+$change) {
        $f=New-WinSecTechnicalFrameworkFixture Guest;$s=New-WinSecTechnicalFrameworkSource $f;$selection=New-WinSecTechnicalFrameworkSelection $f;$sources=@($s)
        switch($change){Device {$selection.DeviceId='local:hw1-'+('c'*64)};Scope {$selection.ScopeKey='WSA-IAM-001'};Catalog {$s.Catalog.CatalogVersion='9.0.0'};Snapshot {$s.Snapshot.CollectorVersion='9.0.0'};Duplicate {$sources=@($s,$s)};Origin {$s.Origin='REMOTE'}}
        Reject-TFA {New-WinSecTechnicalFrameworkView $selection nist-csf $sources}
    }
}
Test-TFA 'A source getter is rejected without execution' {
    $f=New-WinSecTechnicalFrameworkFixture Guest;$s=New-WinSecTechnicalFrameworkSource $f;$s.Snapshot.PSObject.Properties.Remove('Batches');$state=@{Called=$false}
    $s.Snapshot|Add-Member ScriptProperty Batches {$state.Called=$true;throw 'Getter executed'}
    Reject-TFA {New-WinSecTechnicalFrameworkView (New-WinSecTechnicalFrameworkSelection $f) nist-csf @($s)};Assert-TFA (-not $state.Called)
}
Test-TFA 'A frozen view is reusable without analysis or providers' {
    $f=New-WinSecTechnicalFrameworkFixture Guest;$v=Analyze-TFA $f;$again=Assert-WinSecTechnicalFrameworkView $v (New-WinSecTechnicalFrameworkSelection $f)
    Assert-TFA ($again.AnalysisId -ceq $v.AnalysisId -and $again.ContentSha256 -ceq $v.ContentSha256 -and -not [object]::ReferenceEquals($v,$again))
}
foreach($change in @('Digest','Scope','Counter','Relation','Evidence','Getter','Engine')){
    Test-TFA ('Frozen view tampering rejects: '+$change) {
        $f=New-WinSecTechnicalFrameworkFixture Guest;$v=Analyze-TFA $f;$selection=New-WinSecTechnicalFrameworkSelection $f
        switch($change){Digest {$v.Findings[0].Title='Changed'};Scope {$selection.ScopeKey='WSA-IAM-001'};Counter {$v.Coverage.Treatments.EVALUATED=99};Relation {$v.Findings[0].Relation.FrameworkId='mitre-attack'};Evidence {$v.Findings[0].Evidence[0].Value=$true};Getter {$v.Coverage|Add-Member ScriptProperty Secret {throw 'Never execute'}};Engine {$v.EngineVersion='9.0.0'}}
        if($change -cnotin @('Digest','Scope','Getter')){$v.ContentSha256='';$v.ContentSha256=Get-WinSecTechnicalAnalysisHash $v}
        Reject-TFA {Assert-WinSecTechnicalFrameworkView $v $selection}
    }
}
Test-TFA 'Missing observed platform cannot be replaced by the selected profile' {
    $f=New-WinSecTechnicalFrameworkFixture Guest;$f.Sources[0].State='ERROR';$f.Sources[0].Data=$null;$v=Analyze-TFA $f
    Assert-TFA ($v.Findings.Count -eq 0 -and $v.RuleOutcomes[0].State -ceq 'UNKNOWN_PLATFORM' -and $v.Coverage.Treatments.UNRESOLVED_RULE -eq 1)
}
Test-TFA 'Dropping a reading cannot manufacture complete coverage even with a fresh digest' {
    $f=New-WinSecTechnicalFrameworkFixture Guest;$v=Analyze-TFA $f;$v.Readings=@($v.Readings|Select-Object -Skip 1)
    $v.ContentSha256='';$v.ContentSha256=Get-WinSecTechnicalAnalysisHash $v
    Reject-TFA {Assert-WinSecTechnicalFrameworkView $v (New-WinSecTechnicalFrameworkSelection $f)}
}
Test-TFA 'Unreviewed data in a frozen source manifest is rejected' {
    $f=New-WinSecTechnicalFrameworkFixture Guest;$v=Analyze-TFA $f;$v.Sources[0].Platform|Add-Member NoteProperty RawCredential 'SYNTHETIC-SECRET'
    $v.ContentSha256='';$v.ContentSha256=Get-WinSecTechnicalAnalysisHash $v
    Reject-TFA {Assert-WinSecTechnicalFrameworkView $v (New-WinSecTechnicalFrameworkSelection $f)}
}
Test-TFA 'Invalid cancellation responses are rejected rather than treated as consent or cancellation' {
    $f=New-WinSecTechnicalFrameworkFixture Guest
    Reject-TFA {New-WinSecTechnicalFrameworkView (New-WinSecTechnicalFrameworkSelection $f) nist-csf @((New-WinSecTechnicalFrameworkSource $f)) -CancellationAction {'yes'}}
}
Test-TFA 'Data copying rejects resource overflow without returning a truncated view' {
    Reject-TFA {Copy-WinSecTechnicalAnalysisData ('x'*16777217)}
}
foreach($id in @('WSA-SYS-001','WSA-SYS-002','WSA-SYS-003','WSA-NET-001','WSA-NET-002','WSA-NET-003','WSA-NET-004','WSA-NET-005','WSA-IAM-001','WSA-IAM-002','WSA-IAM-003','WSA-LOG-001','WSA-LOG-002','WSA-HRD-001')){
    Test-TFA ('Fixed adapter resolves a reviewed catalog without a provider: '+$id) {
        $a=Get-WinSecTechnicalAnalysisAdapter $id;. $a.Path;$cat=& $a.Catalog
        Assert-WinSecSnapshotCatalog $cat;Assert-TFA ($cat.CheckId -ceq $id -and $null -ne (Get-Command $a.Validate) -and $null -ne (Get-Command $a.Read))
    }
}
Write-Host ('Technical framework analysis: '+$passed+' passed; '+$failed+' failed.');if($failed){exit 1}
