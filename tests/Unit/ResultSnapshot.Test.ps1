# Ownership snapshots, synthetic data only. No audits, storage or Pester.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../../src/Core/ResultModel.ps1')
$script:passed=0; $script:failed=0
function Assert-WinSecSnapshot { param([bool]$Value) if(-not $Value){throw 'Snapshot assertion failed.'} }
function Assert-WinSecSnapshotRejected {
    param([scriptblock]$Action)
    $caught=$false
    try{$null=& $Action}catch{
        $caught=$true
        Assert-WinSecSnapshot ($_.Exception.Message -notmatch 'COPY_PRIVATE_MARKER')
    }
    Assert-WinSecSnapshot $caught
}
function Test-WinSecSnapshot {
    param([string]$Name,[scriptblock]$Action)
    try{$null=& $Action;$script:passed++;Write-Host "[PASS] $Name"}
    catch{$script:failed++;Write-Host "[FAIL] $Name : $($_.Exception.Message)"}
}
function New-WinSecSnapshotBundle {
    $common=@{DeviceId='local:SNAPSHOT-FIXTURE';ScanId='snapshot-1';CheckId='WSA-SYS-001'}
    $control=[pscustomobject]@{DeviceId=$common.DeviceId;ScanId=$common.ScanId;CheckId=$common.CheckId;
        SectionKey='SystemSecurity';Status='INFORMATIONAL';
        Evidence=[pscustomobject]@{Nested=@{Values=@('original');Bytes=[byte[]]@(1,2,3)}}}
    $evaluation=[pscustomobject]@{DeviceId=$common.DeviceId;ScanId=$common.ScanId;CheckId=$common.CheckId;
        Status='NOT_EVALUATED';Metadata=@{Value='original'}}
    $selection=[pscustomobject]@{DeviceId=$common.DeviceId;ScanId=$common.ScanId;CheckId=$common.CheckId;
        EligibleCriteria=@([pscustomobject]@{Source=@{Version='original'}})}
    $finding=[pscustomobject]@{DeviceId=$common.DeviceId;ScanId=$common.ScanId;CheckId=$common.CheckId;
        FindingId='finding-1';Kind='EVALUATION_UNAVAILABLE';Metadata=@{Value='original'}}
    $review=[pscustomobject]@{DeviceId=$common.DeviceId;ScanId=$common.ScanId;CheckId=$common.CheckId;
        ReviewId='review-1';Status='OBSERVED';Metadata=@{Value='original'}}
    return [pscustomobject]@{Control=$control;Evaluation=$evaluation;Selection=$selection;Finding=$finding;Review=$review}
}
function New-WinSecSnapshotSession {
    param([object]$Bundle)
    New-WinSecResultSession -DeviceId $Bundle.Control.DeviceId -ScanId $Bundle.Control.ScanId `
        -ControlResults @($Bundle.Control) -ExpectedCheckIds @($Bundle.Control.CheckId) `
        -EvaluationResults @($Bundle.Evaluation) -CriteriaSelections @($Bundle.Selection) `
        -Findings @($Bundle.Finding) -ReviewItems @($Bundle.Review)
}
foreach($kind in @('Control','Evaluation','Selection','Finding','Review')) {
    Test-WinSecSnapshot ('Mutating caller input cannot rewrite the session: '+$kind) {
        $bundle=New-WinSecSnapshotBundle
        $session=New-WinSecSnapshotSession $bundle
        $before=ConvertTo-Json -InputObject $session -Depth 30 -Compress
        $bundle.$kind.ScanId='foreign-scan'
        switch($kind){
            'Control'{$bundle.Control.Evidence.Nested.Values[0]='changed';$bundle.Control.Evidence.Nested.Bytes[0]=99}
            'Selection'{$bundle.Selection.EligibleCriteria[0].Source.Version='changed'}
            default{$bundle.$kind.Metadata.Value='changed'}
        }
        Assert-WinSecSnapshot ($before -ceq (ConvertTo-Json -InputObject $session -Depth 30 -Compress))
        Assert-WinSecSnapshot (Test-WinSecResultSession $session)
    }
}
Test-WinSecSnapshot 'Mutating an owned record cannot rewrite caller data or another session' {
    $bundle=New-WinSecSnapshotBundle
    $first=New-WinSecSnapshotSession $bundle
    $second=New-WinSecSnapshotSession $bundle
    $first.ControlResults[0].Evidence.Nested.Values[0]='changed'
    Assert-WinSecSnapshot ($bundle.Control.Evidence.Nested.Values[0] -ceq 'original' -and
        $second.ControlResults[0].Evidence.Nested.Values[0] -ceq 'original')
    Assert-WinSecSnapshot (-not [object]::ReferenceEquals($bundle.Control,$first.ControlResults[0]))
}
Test-WinSecSnapshot 'Unverified diagnostic score objects are copied without authorizing scores' {
    $source=[pscustomobject]@{DeviceId='local:SNAPSHOT-FIXTURE';ScanId='snapshot-1';Metadata=@{Value='original'}}
    $session=New-WinSecResultSession -DeviceId $source.DeviceId -ScanId $source.ScanId -ScoreResult $source
    $source.Metadata.Value='changed'
    Assert-WinSecSnapshot ($session.ScoreResult.Metadata.Value -ceq 'original' -and $null -eq $session.OverallScore -and
        $session.OverallStatus -ceq 'NOT_SCORED')
}
Test-WinSecSnapshot 'Typed scalars arrays nulls and singleton arrays retain their meaning' {
    $bundle=New-WinSecSnapshotBundle
    $nested=New-Object 'object[]' 1
    $nested[0]=[int[]]@(1,2)
    $bundle.Control.Evidence=[pscustomobject]@{
        Empty=@();One=@($null);Nested=$nested;Bytes=[byte[]]@(4,5);Numbers=[int[]]@(6,7)
        Timestamp=[datetime]::SpecifyKind([datetime]'2026-10-20',[DateTimeKind]::Utc)
        Offset=[datetimeoffset]'2026-10-20T00:00:00Z';Duration=[timespan]::FromMinutes(1)
        Guid=[guid]'12345678-1234-4567-89ab-123456789abc';Decimal=[decimal]1.25
    }
    $session=New-WinSecSnapshotSession $bundle
    $copy=$session.ControlResults[0].Evidence
    Assert-WinSecSnapshot ($copy.Empty -is [array] -and $copy.Empty.Count -eq 0 -and $copy.One.Count -eq 1 -and
        $null -eq $copy.One[0] -and $copy.Bytes -is [byte[]] -and $copy.Numbers -is [int[]] -and
        $copy.Timestamp -is [datetime] -and $copy.Timestamp.Kind -eq [DateTimeKind]::Utc -and
        $copy.Offset -is [datetimeoffset] -and $copy.Duration -is [timespan] -and $copy.Guid -is [guid] -and $copy.Decimal -is [decimal] -and
        $copy.Nested.Count -eq 1 -and $copy.Nested[0] -is [int[]] -and $copy.Nested[0].Count -eq 2)
    $bundle.Control.Evidence.Bytes[0]=99
    Assert-WinSecSnapshot ($copy.Bytes[0] -eq 4)
}
Test-WinSecSnapshot 'Dictionary data named Keys or Values cannot hide shared references' {
    $bundle=New-WinSecSnapshotBundle
    $bundle.Control.Evidence=@{Keys=@{Value='original'};Values=@(@{Value='original'})}
    $session=New-WinSecSnapshotSession $bundle
    $bundle.Control.Evidence['Keys'].Value='changed'
    $bundle.Control.Evidence['Values'][0].Value='changed'
    Assert-WinSecSnapshot ($session.ControlResults[0].Evidence['Keys'].Value -ceq 'original' -and
        $session.ControlResults[0].Evidence['Values'][0].Value -ceq 'original')
}
Test-WinSecSnapshot 'Ordered dictionaries and common lists own their nested records' {
    $bundle=New-WinSecSnapshotBundle
    $list=New-Object 'System.Collections.Generic.List[object]'
    $list.Add([pscustomobject]@{Value='original'})
    $bundle.Control.Evidence=[ordered]@{First=$list;Second='second'}
    $session=New-WinSecSnapshotSession $bundle
    $list[0].Value='changed'
    Assert-WinSecSnapshot ($session.ControlResults[0].Evidence -is [System.Collections.Specialized.OrderedDictionary] -and
        $session.ControlResults[0].Evidence['First'][0].Value -ceq 'original')
}
foreach($kind in @('OBJECT','DICTIONARY','ARRAY')) {
    Test-WinSecSnapshot ('Cycles reject instead of preserving a live reference: '+$kind) {
        $bundle=New-WinSecSnapshotBundle
        switch($kind){
            'OBJECT'{$value=[pscustomobject]@{Next=$null};$value.Next=$value}
            'DICTIONARY'{$value=@{};$value['Next']=$value}
            'ARRAY'{$value=New-Object 'object[]' 1;$value[0]=$value}
        }
        $bundle.Control.Evidence=$value
        Assert-WinSecSnapshotRejected {New-WinSecSnapshotSession $bundle}
    }
}
Test-WinSecSnapshot 'Repeated data references without a cycle remain supported' {
    $bundle=New-WinSecSnapshotBundle
    $shared=@{Value='original'}
    $bundle.Control.Evidence=[pscustomobject]@{First=$shared;Second=$shared}
    $session=New-WinSecSnapshotSession $bundle
    $shared.Value='changed'
    Assert-WinSecSnapshot ($session.ControlResults[0].Evidence.First.Value -ceq 'original' -and
        $session.ControlResults[0].Evidence.Second.Value -ceq 'original')
}
Test-WinSecSnapshot 'Calculated properties reject before any getter executes' {
    $bundle=New-WinSecSnapshotBundle
    $script:getterCalls=0
    $value=[pscustomobject]@{Safe='original'}
    $value | Add-Member -MemberType ScriptProperty -Name Dangerous -Value {$script:getterCalls++;throw 'COPY_PRIVATE_MARKER'}
    $bundle.Control.Evidence=$value
    Assert-WinSecSnapshotRejected {New-WinSecSnapshotSession $bundle}
    Assert-WinSecSnapshot ($script:getterCalls -eq 0)
}
Test-WinSecSnapshot 'Identity getters reject before validation reads a caller record' {
    $control=(New-WinSecSnapshotBundle).Control
    $control.PSObject.Properties.Remove('DeviceId')
    $script:getterCalls=0
    $control | Add-Member -MemberType ScriptProperty -Name DeviceId -Value {$script:getterCalls++;'local:SNAPSHOT-FIXTURE'}
    Assert-WinSecSnapshotRejected {
        New-WinSecResultSession -DeviceId 'local:SNAPSHOT-FIXTURE' -ScanId 'snapshot-1' -ControlResults @($control)
    }
    Assert-WinSecSnapshot ($script:getterCalls -eq 0)
}
Test-WinSecSnapshot 'Generic dictionaries use owned case-insensitive keys and copy values' {
    $bundle=New-WinSecSnapshotBundle
    $value=New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::OrdinalIgnoreCase)
    $value.Add('Record',@{Value='original'})
    $bundle.Control.Evidence=$value
    $session=New-WinSecSnapshotSession $bundle
    $value['Record'].Value='changed'
    Assert-WinSecSnapshot ($session.ControlResults[0].Evidence['record'].Value -ceq 'original')
}
Test-WinSecSnapshot 'Case-ambiguous dictionary keys reject instead of silently dropping values' {
    $bundle=New-WinSecSnapshotBundle
    $value=New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
    $value.Add('Record','first');$value.Add('record','second')
    $bundle.Control.Evidence=$value
    Assert-WinSecSnapshotRejected {New-WinSecSnapshotSession $bundle}
}
Test-WinSecSnapshot 'ArrayList and typed lists retain their contents without sharing rows' {
    $bundle=New-WinSecSnapshotBundle
    $rows=New-Object System.Collections.ArrayList
    $null=$rows.Add([pscustomobject]@{Value='original'})
    $strings=New-Object 'System.Collections.Generic.List[string]'
    $strings.Add('original')
    $bundle.Control.Evidence=@{Rows=$rows;Names=$strings}
    $session=New-WinSecSnapshotSession $bundle
    $rows[0].Value='changed';$strings[0]='changed'
    Assert-WinSecSnapshot ($session.ControlResults[0].Evidence.Rows -is [System.Collections.ArrayList] -and
        $session.ControlResults[0].Evidence.Rows[0].Value -ceq 'original' -and
        $session.ControlResults[0].Evidence.Names -is [System.Collections.Generic.List[string]] -and
        $session.ControlResults[0].Evidence.Names[0] -ceq 'original')
}
Test-WinSecSnapshot 'Pointer values cannot masquerade as independent snapshot data' {
    $bundle=New-WinSecSnapshotBundle
    $bundle.Control.Evidence=[IntPtr]1
    Assert-WinSecSnapshotRejected {New-WinSecSnapshotSession $bundle}
}
Test-WinSecSnapshot 'Extended scalar properties cannot smuggle mutable references into a snapshot' {
    $bundle=New-WinSecSnapshotBundle
    $value='plain' | Add-Member -NotePropertyName Nested -NotePropertyValue @{Value='COPY_PRIVATE_MARKER'} -PassThru
    $bundle.Control.Evidence=$value
    Assert-WinSecSnapshotRejected {New-WinSecSnapshotSession $bundle}
}
foreach($kind in @('TOO_DEEP','TOO_MANY','UNSUPPORTED','NON_STRING_KEY')) {
    Test-WinSecSnapshot ('Unsafe snapshot input aborts generically: '+$kind) {
        $bundle=New-WinSecSnapshotBundle
        switch($kind){
            'TOO_DEEP'{$value=@{};$tail=$value;for($i=0;$i -lt 70;$i++){$next=@{};$tail['Next']=$next;$tail=$next}}
            'TOO_MANY'{$value=New-Object 'object[]' 10001}
            'UNSUPPORTED'{$value=New-Object System.Text.StringBuilder 'COPY_PRIVATE_MARKER'}
            'NON_STRING_KEY'{$value=@{1='COPY_PRIVATE_MARKER'}}
        }
        $bundle.Control.Evidence=$value
        Assert-WinSecSnapshotRejected {New-WinSecSnapshotSession $bundle}
    }
}
Test-WinSecSnapshot 'Public projections remain separate from owned internal evidence' {
    $session=New-WinSecSnapshotSession (New-WinSecSnapshotBundle)
    $public=ConvertTo-WinSecPublicScanResult $session
    $public.ControlResults[0].Status='UNKNOWN'
    Assert-WinSecSnapshot ($session.ControlResults[0].Status -ceq 'INFORMATIONAL' -and
        $public.ContainsRawEvidence -ceq $false -and $null -eq $public.OverallScore)
}
Write-Host "Passed: $script:passed; Failed: $script:failed"
if($script:failed -gt 0){throw 'Result snapshot unit tests failed.'}
