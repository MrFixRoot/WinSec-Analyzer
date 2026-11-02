[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
. (Join-Path $root 'src/Checks/Accounts/IdentityAccessCollector.ps1')
. (Join-Path $root 'tests/Fixtures/IdentityAccessMemory.ps1')
. (Join-Path $root 'tests/Fixtures/FrameworkWorkflowMemory.ps1')
. (Join-Path $root 'src/Checks/Network/Test-SMBv1.ps1')
. (Join-Path $root 'tests/Fixtures/SmbMemory.ps1')
foreach($file in @('src/Checks/Network/Test-RDP.ps1','src/Checks/Network/Test-OpenPorts.ps1','src/Checks/Network/Test-NetworkConfiguration.ps1','src/Checks/Firewall/Test-Firewall.ps1',
    'tests/Fixtures/RdpMemory.ps1','tests/Fixtures/OpenPortsMemory.ps1','tests/Fixtures/NetworkConfigurationMemory.ps1','tests/Fixtures/FirewallMemory.ps1')){. (Join-Path $root $file)}
function Get-CimInstance {throw 'Native query prohibited.'}
Set-Alias Invoke-WinSecIdentityAccessQuery Invoke-WinSecIdentityFixtureQuery -Scope Script
$passed=0;$failed=0
function Assert-PR {param([bool]$Value);if(-not $Value){throw 'Projected framework assertion failed.'}}
function Reject-PR {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-PR $caught}
function New-PR {
    param([string[]]$Ids=@('WSA-IAM-002'),[string]$Framework='nist-csf',[scriptblock]$CancellationAction,[scriptblock]$ProgressCallback)
    Initialize-WinSecIdentityFixture;$session=New-WinSecIdentityFixtureSession $Ids
    $reports=@($Ids|ForEach-Object {New-WinSecTechnicalReport $session $_ SYNTHETIC SYNTHETIC})
    $snapshots=@($reports|ForEach-Object {(New-WinSecProjectionSnapshot $_).Snapshot})
    $sources=@($Ids|ForEach-Object {New-WinSecIdentityFixtureSource $session $_})
    $result=New-WinSecProjectionFrameworkAnalysis -ProjectRoot $root -DeviceId $session.DeviceId -DeviceName SYNTHETIC -ScopeType $session.ScopeType -ScopeKey $session.ScopeKey -FrameworkId $Framework `
        -Sources $sources -Reports $reports -Snapshots $snapshots -CancellationAction $CancellationAction -ProgressCallback $ProgressCallback
    [pscustomobject]@{Result=$result;Session=$session;Reports=$reports;Snapshots=$snapshots;Sources=$sources}
}
function Test-PR {param($CaseName,[scriptblock]$Action);try{& $Action;$script:passed++;Write-Host ('[PASS] '+$CaseName)}catch{$script:failed++;Write-Host ('[FAIL] '+$CaseName+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}
foreach($framework in @('nist-csf','cis-controls','mitre-attack')){
    Test-PR ('A real 2.1 transport retains its identity and selected framework: '+$framework) {
        $f=New-PR -Framework $framework;$a=$f.Result.Analysis
        Assert-PR ($a.SchemaVersion -ceq '1.1.0' -and $a.FrameworkId -ceq $framework -and $a.Rows.Count -eq 1 -and $a.ReadingReview.Sources[0].Identity.SnapshotId -ceq $f.Snapshots[0].Identity.SnapshotId -and $a.AnalysisId -cne $f.Snapshots[0].Identity.SnapshotId)
        Assert-PR (@($a.Rows|Where-Object {$_.References.Count -eq 0}).Count -eq 0 -and $a.ReadingReview.Sources[0].SnapshotSchemaVersion -ceq '2.1.0')
    }
}
Test-PR 'Every scalar reading and every member property has a separate treatment without values' {
    $f=New-PR @('WSA-IAM-001');$a=$f.Result.Analysis;$ledger=$f.Result.Ledger;$sum=0
    foreach($p in $a.ReadingReview.Treatments.PSObject.Properties){$sum+=$p.Value}
    $members=@($ledger|Where-Object {$_.SettingId -ceq 'Administrators.Members' -and $_.RecordId -clike 'Item*'})
    Assert-PR ($sum -eq $ledger.Count -and $members.Count -eq 4 -and @($members|Where-Object Field -CEQ PrincipalId).Count -eq 2 -and
        (ConvertTo-Json $ledger -Depth 8) -notmatch 'PrincipalId":\s*"sha256:|S-1-5-|PRIVATE')
}
Test-PR 'Section review preserves three snapshot IDs and one original section ScanId' {
    $f=New-PR @('WSA-IAM-001','WSA-IAM-002','WSA-IAM-003');$a=$f.Result.Analysis
    Assert-PR ($a.ScopeType -ceq 'SECTION' -and $a.ReadingReview.Sources.Count -eq 3 -and @($a.ReadingReview.Sources.ScanId|Sort-Object -Unique).Count -eq 1 -and @($a.ReadingReview.Sources.Identity.SnapshotId|Sort-Object -Unique).Count -eq 3 -and $a.Rows.Count -ge 3)
}
Test-PR 'Frozen export preserves summary, identity and original Findings exactly' {
    $f=New-PR;$a=$f.Result.Analysis;$before=Get-WinSecFrameworkAnalysisDigest $a;$md=New-WinSecFrameworkMarkdown $a
    Assert-PR ($md.Contains($a.AnalysisId) -and $md.Contains($a.ReadingReview.Sources[0].Identity.SnapshotId) -and $md.Contains('Saved reading coverage') -and $md.Contains($a.Rows[0].Title) -and (Get-WinSecFrameworkAnalysisDigest $a) -ceq $before)
}
Test-PR 'Markdown artifact roundtrip preserves canonical dates and coverage order' {
    $f=New-PR;$a=$f.Result.Analysis;$body=New-WinSecFrameworkMarkdown $a
    $meta=@{SchemaVersion='1.0.0';DeviceId=$a.DeviceId;AnalysisId=$a.AnalysisId;FrameworkId=$a.FrameworkId;ContentSha256=(Get-WinSecReportTextHash $body)}
    $text="<!-- WinSec framework findings`n"+(ConvertTo-Json $meta -Compress)+"`n-->`n"+$body
    $read=ConvertFrom-WinSecFrameworkMarkdownArtifact $text $a.DeviceId
    Assert-PR ($read.AnalysisId -ceq $a.AnalysisId -and $read.ContentSha256 -ceq $meta.ContentSha256)
}
Test-PR 'A legacy projection remains explicitly legacy without an invented SnapshotId' {
    $f=New-PR;$a=New-WinSecProjectionFrameworkAnalysis $root $f.Session.DeviceId SYNTHETIC CONTROL WSA-IAM-002 nist-csf $f.Sources $f.Reports
    Assert-PR ($a.Analysis.ReadingReview.Sources[0].SnapshotSchemaVersion -ceq 'LEGACY' -and $null -eq $a.Analysis.ReadingReview.Sources[0].Identity -and $a.Analysis.Rows.Count -eq 1)
}
Test-PR 'Missing technical detail produces explicit limits rather than historical fallback findings' {
    $f=New-WinSecFrameworkWorkflowFixture
    $review=New-WinSecProjectionFrameworkAnalysis $root $f.Session.DeviceId SYNTHETIC CONTROL WSA-SYS-002 nist-csf @($f.Source)
    $md=New-WinSecFrameworkMarkdown $review.Analysis
    Assert-PR ($review.Analysis.Rows.Count -eq 0 -and $review.Analysis.MissingTechnicalCheckIds.Count -eq 1 -and $review.Analysis.ReadingReview.ReadingCount -eq 0 -and $md.Contains('No new warnings were evaluated'))
}
Test-PR 'Existing BitLocker warnings retain version-independent semantics without invented platform data' {
    $f=New-WinSecFrameworkWorkflowFixture;$p=New-WinSecProjectionSnapshot $f.Report
    $a=New-WinSecProjectionFrameworkAnalysis $root $f.Session.DeviceId SYNTHETIC CONTROL WSA-SYS-002 nist-csf @($f.Source) @($f.Report) @($p.Snapshot)
    Assert-PR ($a.Analysis.Rows.Count -gt 0 -and $null -eq $a.Analysis.ReadingReview.Sources[0].Platform.BuildNumber -and $a.Analysis.ReadingReview.Sources[0].ApplicabilityBasis -ceq 'REVIEWED_VALUE_SEMANTICS')
}
Test-PR 'An unavailable required IAM platform context remains unresolved' {
    Initialize-WinSecIdentityFixture;$script:IdentityFailure='Platform'
    try{$s=New-WinSecIdentityFixtureSession @('WSA-IAM-002')}finally{$script:IdentityFailure=''}
    $r=New-WinSecTechnicalReport $s WSA-IAM-002 SYNTHETIC SYNTHETIC;$p=New-WinSecProjectionSnapshot $r;$source=New-WinSecIdentityFixtureSource $s WSA-IAM-002
    $review=New-WinSecProjectionFrameworkAnalysis $root $s.DeviceId SYNTHETIC CONTROL WSA-IAM-002 nist-csf @($source) @($r) @($p.Snapshot)
    Assert-PR ($review.Analysis.Rows.Count -eq 0 -and $review.Analysis.ReadingReview.Treatments.UNRESOLVED_RULE -gt 0 -and $review.Analysis.ReadingReview.Sources[0].ApplicabilityBasis -ceq 'UNRESOLVED_CONTEXT')
}
Test-PR 'System Security preserves Defender and BitLocker warnings despite legacy platform omissions' {
    $fixtures=@(foreach($id in @('WSA-SYS-001','WSA-SYS-002','WSA-SYS-003')){New-WinSecFrameworkWorkflowFixture $id ('projected-'+$id)})
    $snapshots=@($fixtures.Report|ForEach-Object {(New-WinSecProjectionSnapshot $_).Snapshot})
    $review=New-WinSecProjectionFrameworkAnalysis $root $fixtures[0].Session.DeviceId SYNTHETIC SECTION SystemSecurity nist-csf @($fixtures.Source) @($fixtures.Report) $snapshots
    Assert-PR ($review.Analysis.Rows.Count -ge 10 -and @($review.Analysis.Rows|Where-Object CheckId -CEQ WSA-SYS-001).Count -gt 0 -and
        @($review.Analysis.Rows|Where-Object CheckId -CEQ WSA-SYS-002).Count -gt 0 -and @($review.Analysis.ReadingReview.Sources|Where-Object ApplicabilityBasis -CEQ REVIEWED_VALUE_SEMANTICS).Count -eq 2)
}
Test-PR 'Cancellation during classification returns no replacement view' {
    $statePR=@{Cancel=$false};$f=New-PR -CancellationAction {$statePR.Cancel}.GetNewClosure() -ProgressCallback {param($e);if($e.Completed -ge 1){$statePR.Cancel=$true}}.GetNewClosure()
    Assert-PR ($null -eq $f.Result)
}
Test-PR 'Projected snapshots cannot contradict the supplied reviewed report' {
    $f=New-PR;$f.Snapshots[0].Identity.ScanId='foreign'
    Reject-PR {New-WinSecProjectionFrameworkAnalysis $root $f.Session.DeviceId SYNTHETIC CONTROL WSA-IAM-002 nist-csf $f.Sources $f.Reports $f.Snapshots}
}
foreach($case in @('WARNING','SIGNED','ENCRYPTED','UNKNOWN')){
    Test-PR ('The selected framework changes a real projected SMB predicate: '+$case) {
        Set-Alias Get-CimInstance Get-WinSecSmbFixtureCim -Scope Script
        Set-Alias Invoke-WinSecSmbQuery Invoke-WinSecSmbFixtureQuery -Scope Script
        Set-Alias Read-WinSecSmbRegistryValue Read-WinSecSmbFixtureRegistry -Scope Script
        Initialize-WinSecSmbFixture;$s=New-WinSecSmbFixtureSession
        $r=New-WinSecTechnicalReport $s WSA-NET-002 SYNTHETIC SYNTHETIC
        foreach($field in @('Server.RequireSecuritySignature','Server.EncryptData')){($r.Rows|Where-Object SettingId -CEQ $field).Value=$false}
        if($case -ceq 'SIGNED'){($r.Rows|Where-Object SettingId -CEQ Server.RequireSecuritySignature).Value=$true}
        if($case -ceq 'ENCRYPTED'){($r.Rows|Where-Object SettingId -CEQ Server.EncryptData).Value=$true}
        if($case -ceq 'UNKNOWN'){$row=$r.Rows|Where-Object SettingId -CEQ Server.EncryptData;$row.Value=$null;$row.State='UNKNOWN';$row.Reason='UNAVAILABLE'}
        $p=New-WinSecProjectionSnapshot $r
        $source=[pscustomobject]@{CheckId='WSA-NET-002';ScanId=$s.ScanId;ScopeType=$s.ScopeType;ScopeKey=$s.ScopeKey;CompletedAtUTC=$s.CompletedAtUTC;Origin='LIVE';PublicResult=(ConvertTo-WinSecPublicScanResult $s);CatalogVersion=$s.CatalogVersion;ExpectedCheckIds=@($s.ExpectedCheckIds)}
        $nist=New-WinSecProjectionFrameworkAnalysis $root $s.DeviceId SYNTHETIC CONTROL WSA-NET-002 nist-csf @($source) @($r) @($p.Snapshot)
        $mitre=New-WinSecProjectionFrameworkAnalysis $root $s.DeviceId SYNTHETIC CONTROL WSA-NET-002 mitre-attack @($source) @($r) @($p.Snapshot)
        Assert-PR (@($nist.Analysis.Rows|Where-Object CriterionId -CEQ TF-SMB-002).Count -eq 0 -and $nist.Analysis.ReadingReview.SupplementalRules.Count -eq 0)
        Assert-PR (@($mitre.Analysis.Rows|Where-Object CriterionId -CEQ TF-SMB-002).Count -eq $(if($case -ceq 'WARNING'){1}else{0}) -and
            $mitre.Analysis.ReadingReview.SupplementalRules[0].ReferenceVersion -ceq '1.2')
    }
}
foreach($change in @('Count','Identity','SnapshotHash','Catalog','Getter','AnalysisId')){
    Test-PR ('Frozen summary rejects altered '+$change) {
        $f=New-PR;$a=$f.Result.Analysis
        switch($change){Count {$a.ReadingReview.ReadingCount++};Identity {$a.ReadingReview.Sources[0].Identity.DeviceId='local:hw1-'+('c'*64)};SnapshotHash {$a.ReadingReview.Sources[0].SnapshotSha256='invalid'};Catalog {$a.ReadingReview.Sources[0].CatalogVersion='9.0.0'};Getter {$a.ReadingReview|Add-Member ScriptProperty Unsafe {throw 'Never execute'}};AnalysisId {$a.AnalysisId=$a.ReadingReview.Sources[0].Identity.SnapshotId}}
        if($change -cne 'Getter'){$a.ContentSha256=Get-WinSecFrameworkAnalysisDigest $a}
        Reject-PR {Assert-WinSecFrameworkAnalysis $a $f.Session.DeviceId CONTROL WSA-IAM-002}
    }
}
foreach($control in @('RDP','Ports','Network','Firewall')){
    Test-PR ('Every permitted nested field is classified rather than just its container: '+$control) {
        switch($control){
            RDP {
                Set-Alias Invoke-WinSecRdpQuery Invoke-WinSecRdpFixtureQuery -Scope Script;Set-Alias Read-WinSecRdpRegistryValue Read-WinSecRdpFixtureRegistry -Scope Script
                Initialize-WinSecRdpFixture;$session=New-WinSecRdpFixtureSession;$id='WSA-NET-003'
            }
            Ports {
                Set-Alias Invoke-WinSecOpenPortsQuery Invoke-WinSecOpenPortsFixtureQuery -Scope Script
                Initialize-WinSecOpenPortsFixture;$session=New-WinSecOpenPortsFixtureSession;$id='WSA-NET-004'
            }
            Network {
                Set-Alias Invoke-WinSecNetworkConfigurationQuery Invoke-WinSecNetworkConfigurationFixtureQuery -Scope Script
                Initialize-WinSecNetworkConfigurationFixture;$session=New-WinSecNetworkConfigurationFixtureSession;$id='WSA-NET-005'
            }
            Firewall {
                Set-Alias Get-CimInstance Get-WinSecFirewallFixtureCim -Scope Script;Set-Alias Invoke-WinSecFirewallQuery Invoke-WinSecFirewallFixtureQuery -Scope Script
                Initialize-WinSecFirewallFixture;$session=New-WinSecFirewallFixtureSession;$id='WSA-NET-001'
            }
        }
        $r=New-WinSecTechnicalReport $session $id SYNTHETIC SYNTHETIC;$p=New-WinSecProjectionSnapshot $r
        $source=[pscustomobject]@{CheckId=$id;ScanId=$session.ScanId;ScopeType=$session.ScopeType;ScopeKey=$session.ScopeKey;CompletedAtUTC=$session.CompletedAtUTC;Origin='LIVE';PublicResult=(ConvertTo-WinSecPublicScanResult $session);CatalogVersion=$session.CatalogVersion;ExpectedCheckIds=@($session.ExpectedCheckIds)}
        $result=New-WinSecProjectionFrameworkAnalysis $root $session.DeviceId SYNTHETIC CONTROL $id nist-csf @($source) @($r) @($p.Snapshot)
        $children=@($result.Ledger|Where-Object RecordId -clike 'Item*')
        Assert-PR ($children.Count -gt 0 -and @($children|Where-Object Field -CIN @('Rank','Length','SyncRoot','IsFixedSize')).Count -eq 0 -and $result.Analysis.ReadingReview.ReadingCount -gt $r.Rows.Count)
        foreach($row in $r.Rows|Where-Object {$_.SettingId -clike 'Inventory.*' -and $_.State -ceq 'OBSERVED'}){
            $expected=0;$kind=(Get-WinSecTechnicalRowDefinition $row.SettingId @(Get-WinSecTechnicalDefinitions $id $r.CatalogVersion)).Kind
            switch($kind){
                rdpInventory {$items=(ConvertTo-WinSecRdpInventory $row.Value).Items;foreach($item in $items){$expected+=@($item.Values.PSObject.Properties).Count}}
                networkBatch {$items=(ConvertTo-WinSecNetworkConfigurationBatch $row.Value).Items;foreach($item in $items){$expected+=@($item.Values.PSObject.Properties).Count}}
                portsBatch {$items=ConvertTo-WinSecOpenPortsBatch $row.Value;foreach($item in $items){$expected+=@($item.PSObject.Properties).Count}}
                firewallBatch {$items=ConvertTo-WinSecFirewallBatch $row.Value;foreach($item in $items){$expected+=@($item.PSObject.Properties).Count}}
                firewallMetadata {$items=ConvertTo-WinSecFirewallMetadataBatch $row.Value;foreach($item in $items){$expected+=@($item.Values.PSObject.Properties).Count}}
            }
            Assert-PR (@($children|Where-Object SettingId -CEQ $row.SettingId).Count -eq $expected)
        }
    }
}
Write-Host ('Projected framework review: '+$passed+' passed; '+$failed+' failed.');if($failed){exit 1}
