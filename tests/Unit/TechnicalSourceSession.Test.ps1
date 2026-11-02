[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Services/TechnicalSourceSession.ps1')
. (Join-Path $root 'tests/Fixtures/TechnicalSourceMemory.ps1')
foreach($command in @('Get-CimInstance','Get-CimClass','Get-MpComputerStatus','Get-MpPreference','Start-Job')){
    Set-Item ('Function:script:'+$command) {throw 'Native acquisition forbidden.'}
}
$passed=0;$failed=0;$fixture=New-WinSecTechnicalSourceFixture
function New-SessionUnitFixture {
    param([object]$Fixture)
    $owner=[pscustomobject]@{DeviceId=$Fixture.Identity.DeviceId;ScanId=$Fixture.Identity.ScanId;ScopeType=$Fixture.Identity.ScopeType;ScopeKey=$Fixture.Identity.ScopeKey}
    $stamp=Get-WinSecTechnicalSourcePackageStamp $Fixture.Package $Fixture.Identity
    $value=[pscustomobject]@{ArtifactType='WinSec.TechnicalSourceSession';SchemaVersion='1.0.0';Identity=$owner;Sources=@(
        [pscustomobject]@{Reference=$stamp.Reference;SnapshotSha256=$stamp.SnapshotSha256;Collection=$Fixture.Package.Snapshot.Collection.PSObject.Copy()});ContentSha256=''}
    $value.ContentSha256=Get-WinSecTechnicalSessionDigest $value;return $value
}
$base=New-SessionUnitFixture $fixture
function Assert-SessionUnit {param([bool]$Value);if(-not $Value){throw 'Technical session unit assertion failed.'}}
function Reject-SessionUnit {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-SessionUnit $caught}
function Test-SessionUnit {
    param([string]$Case,[scriptblock]$Action)
    $s=Copy-WinSecResultData $base;$owner=$base.Identity.PSObject.Copy()
    try{& $Action;$script:passed++;Write-Host ('[PASS] '+$Case)}catch{$script:failed++;Write-Host ('[FAIL] '+$Case+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}
}
Test-SessionUnit 'Canonical JSON reload retains reference versions, original identity and partial coverage' {
    $json=ConvertTo-WinSecTechnicalSourceSessionJson $s $owner;$copy=ConvertFrom-WinSecTechnicalSourceSessionJson $json $owner
    Assert-SessionUnit ((Get-WinSecPublicHistoryJson $copy) -ceq $json -and $copy.Sources[0].Collection.Status -ceq 'PARTIAL' -and
        $copy.Sources[0].Reference.CollectorVersion -ceq '1.3.0' -and $copy.Sources[0].Reference.CollectedAtUTC -is [string])
}
foreach($collector in @('1.0.0','1.1.0','1.2.0','1.3.0')){Test-SessionUnit ('Historical candidate combination keeps original versions: '+$collector) {
    $f=New-WinSecTechnicalSourceFixture -CatalogVersion 1.0.0 -CollectorVersion $collector;$v=New-SessionUnitFixture $f
    $v=ConvertFrom-WinSecTechnicalSourceSessionJson (ConvertTo-WinSecTechnicalSourceSessionJson $v $v.Identity) $v.Identity
    Assert-SessionUnit ($v.Sources[0].Reference.CollectorVersion -ceq $collector -and $v.Sources[0].Reference.CatalogVersion -ceq '1.0.0')
}}
Test-SessionUnit 'Reviewed projections retain schema 2.1 and never become candidate snapshots' {
    $v=New-SessionUnitFixture (New-WinSecTechnicalSourceFixture -Family PROJECTION)
    Assert-WinSecTechnicalSourceSession $v $v.Identity
    Assert-SessionUnit ($v.Sources[0].Reference.SnapshotSchemaVersion -ceq '2.1.0' -and $v.Sources[0].Reference.CatalogSchemaVersion -ceq '1.1.0')
}
foreach($damage in @('Artifact','Version','Missing','Extra','ArraySources','EmptySources','IdentityType','Device','Scan','Scope','Section','Check','SnapshotId',
    'LegacyReference','ReferenceVersion','SnapshotSchema','CatalogVersion','CollectorVersion','CatalogHash','EntryExtra','SnapshotHash','CollectionHash','HashCase')){
    Test-SessionUnit ('Reject invalid or contradictory container: '+$damage) {
        switch($damage){
            Artifact {$s.ArtifactType='WinSec.StoredSession'};Version {$s.SchemaVersion='2.0.0'};Missing {$s.PSObject.Properties.Remove('Identity')}
            Extra {$s|Add-Member Evidence 'PRIVATE-SESSION-SECRET'};ArraySources {$s.Sources=$s.Sources[0]};EmptySources {$s.Sources=@()}
            IdentityType {$s.Identity.ScanId=@($s.Identity.ScanId)};Device {$s.Identity.DeviceId='local:hw1-'+('c'*64)};Scan {$s.Sources[0].Reference.Identity.ScanId='foreign'}
            Scope {$s.Sources[0].Reference.Identity.ScopeType='SECTION';$s.Sources[0].Reference.Identity.ScopeKey='SystemSecurity'}
            Section {$s.Sources[0].Reference.Identity.SectionKey='NetworkSecurity'};Check {$s.Sources[0].Reference.Identity.CheckId='WSA-SYS-002'}
            SnapshotId {$s.Sources[0].Reference.Identity.SnapshotId='bad'};LegacyReference {$s.Sources[0].Reference=Get-WinSecLegacySourceFixtureReference $fixture}
            ReferenceVersion {$s.Sources[0].Reference.SchemaVersion='99.0.0'};SnapshotSchema {$s.Sources[0].Reference.SnapshotSchemaVersion='2.1.0'}
            CatalogVersion {$s.Sources[0].Reference.CatalogVersion='99.0.0'};CollectorVersion {$s.Sources[0].Reference.CollectorVersion='1.2.0'}
            CatalogHash {$s.Sources[0].Reference.CatalogSha256='A'*64};EntryExtra {$s.Sources[0]|Add-Member Path 'C:\private'}
            SnapshotHash {$s.Sources[0].SnapshotSha256='A'*64};CollectionHash {$s.Sources[0].Collection.Unknown++};HashCase {$s.ContentSha256=$s.ContentSha256.ToLowerInvariant()}
        };Reject-SessionUnit {Assert-WinSecTechnicalSourceSession $s $owner}
    }
}
foreach($damage in @('SameReference','OtherSnapshot','DifferentFamily')){Test-SessionUnit ('Duplicate CheckId cannot represent two sources: '+$damage) {
    $duplicate=Copy-WinSecResultData $s.Sources[0]
    if($damage -ceq 'OtherSnapshot'){$duplicate.Reference.Identity.SnapshotId='c'*32}
    if($damage -ceq 'DifferentFamily'){
        $f=New-WinSecTechnicalSourceFixture -Family PROJECTION;$duplicate.Reference=$f.Reference
        foreach($field in @('DeviceId','ScanId','ScopeType','ScopeKey')){$duplicate.Reference.Identity.$field=$owner.$field}
    }
    $s.Sources+=,$duplicate;$s.ContentSha256=Get-WinSecTechnicalSessionDigest $s
    Reject-SessionUnit {Assert-WinSecTechnicalSourceSession $s $owner}
}}
foreach($damage in @('State','Coverage','Contradiction','Negative','Fraction','Boolean','Null','Extra','Array')){Test-SessionUnit ('Coverage metadata remains strictly typed: '+$damage) {
    $c=$s.Sources[0].Collection
    switch($damage){State {$c.Status='NOT_SCORED'};Coverage {$c.Coverage='APPROVED'};Contradiction {$c.Status='PARTIAL';$c.Coverage='COMPLETE'}
        Negative {$c.Unknown=-1};Fraction {$c.Unknown=0.5};Boolean {$c.Unknown=$false};Null {$c.Unknown=$null};Extra {$c|Add-Member Score 100};Array {$c.Status=@($c.Status)}}
    $s.ContentSha256=Get-WinSecTechnicalSessionDigest $s;Reject-SessionUnit {Assert-WinSecTechnicalSourceSession $s $owner}
}}
foreach($level in @('Root','Identity','Entry','Reference','ReferenceIdentity','Collection')){Test-SessionUnit ('Getters never execute at level '+$level) {
    $script:getterCalls=0
    switch($level){Root {$node=$s;$field='Sources'};Identity {$node=$s.Identity;$field='ScanId'};Entry {$node=$s.Sources[0];$field='Reference'}
        Reference {$node=$s.Sources[0].Reference;$field='Identity'};ReferenceIdentity {$node=$s.Sources[0].Reference.Identity;$field='ScanId'}
        Collection {$node=$s.Sources[0].Collection;$field='Unknown'}}
    $node|Add-Member -MemberType ScriptProperty -Name $field -Value {$script:getterCalls++;throw 'PRIVATE-SESSION-SECRET'} -Force
    Reject-SessionUnit {Assert-WinSecTechnicalSourceSession $s $owner};Assert-SessionUnit ($script:getterCalls -eq 0)
}}
foreach($damage in @('RootArray','Malformed','Duplicate','CaseDuplicate','EscapedDuplicate','Comment','Depth','Bytes','NonString')){Test-SessionUnit ('Bounded JSON rejects '+$damage) {
    $json=ConvertTo-WinSecTechnicalSourceSessionJson $s $owner
    switch($damage){RootArray {$json='['+$json+']'};Malformed {$json='{PRIVATE-SESSION-SECRET'}
        Duplicate {$json=$json.Replace('"ArtifactType":','"ArtifactType":"WinSec.TechnicalSourceSession","ArtifactType":')}
        CaseDuplicate {$json=$json.Replace('"ArtifactType":','"artifacttype":"WinSec.TechnicalSourceSession","ArtifactType":')}
        EscapedDuplicate {$json=$json.Replace('"ArtifactType":','"\u0041rtifactType":"WinSec.TechnicalSourceSession","ArtifactType":')}
        Comment {$json='/*comment*/'+$json};Depth {$json='{"x":'+('['*18)+'0'+(']'*18)+'}'};Bytes {$json=(' '*17000)+$json};NonString {$json=@($json)}}
    Reject-SessionUnit {ConvertFrom-WinSecTechnicalSourceSessionJson $json $owner}
}}
Test-SessionUnit 'Serialization freezes valid metadata before callbacks can mutate the caller container' {
    $script:mutableSession=$s;$script:mutableOwner=$owner;$expected=$owner.PSObject.Copy()
    $json=ConvertTo-WinSecTechnicalSourceSessionJson $s $owner -CancellationAction {$script:mutableSession.Identity.ScanId='mutated';$script:mutableOwner.ScanId='mutated';$false}
    Assert-SessionUnit ((ConvertFrom-WinSecTechnicalSourceSessionJson $json $expected).Identity.ScanId -ceq $expected.ScanId)
}
Test-SessionUnit 'Digest and serialization are canonical for property order without changing source order' {
    $reversed=[ordered]@{};foreach($p in @($s.PSObject.Properties|Sort-Object Name -Descending)){$reversed[$p.Name]=$p.Value}
    Assert-SessionUnit ((ConvertTo-WinSecTechnicalSourceSessionJson ([pscustomobject]$reversed) $owner) -ceq (ConvertTo-WinSecTechnicalSourceSessionJson $s $owner))
}
foreach($phase in @('Encode','Decode','New','Resolve')){Test-SessionUnit ('Cancellation is preserved before returning a '+$phase+' result') {
    $json=ConvertTo-WinSecTechnicalSourceSessionJson $s $owner;$cancelled=$false
    try{switch($phase){Encode {ConvertTo-WinSecTechnicalSourceSessionJson $s $owner -CancellationAction {$true}}
        Decode {ConvertFrom-WinSecTechnicalSourceSessionJson $json $owner -CancellationAction {$true}}
        New {New-WinSecTechnicalSourceSession 'Z:\missing-session-fixture' @($s.Sources[0].Reference) $owner -CancellationAction {$true}}
        Resolve {Resolve-WinSecTechnicalSourceSession 'Z:\missing-session-fixture' $s $owner -CancellationAction {$true}}}}
    catch [OperationCanceledException]{$cancelled=$true};Assert-SessionUnit $cancelled
}}
Test-SessionUnit 'Non-Boolean cancellation responses are rejected' {
    Reject-SessionUnit {ConvertTo-WinSecTechnicalSourceSessionJson $s $owner -CancellationAction {'yes'}}
    Reject-SessionUnit {New-WinSecTechnicalSourceSession 'Z:\missing-session-fixture' @($s.Sources[0].Reference) $owner -CancellationAction {'yes'}}
}
Test-SessionUnit 'New session rejects duplicates and unknown versions before source file access' {
    $script:diskCalls=0
    function Get-WinSecVerifiedTechnicalSessionEntry {$script:diskCalls++;throw 'Unexpected source file access.'}
    Reject-SessionUnit {New-WinSecTechnicalSourceSession 'Z:\missing-session-fixture' @($s.Sources[0].Reference,$s.Sources[0].Reference) $owner}
    $s.Sources[0].Reference.CollectorVersion='99.0.0'
    Reject-SessionUnit {New-WinSecTechnicalSourceSession 'Z:\missing-session-fixture' @($s.Sources[0].Reference) $owner}
    Assert-SessionUnit ($script:diskCalls -eq 0)
}
Write-Host ("Technical source session unit: $passed passed; $failed failed.");if($failed){exit 1}
