# Public Findings UI contract. Synthetic in-memory input; no scans or storage.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
foreach($file in @('src/CLI/Invoke-WinSecCLI.ps1','src/UI/Components/Table.ps1',
    'src/UI/Screens/MainMenu.ps1','src/UI/Screens/Results.ps1','src/UI/Screens/Findings.ps1')) {. (Join-Path $root $file)}
function Get-WinSecFrameworkCatalog {[pscustomobject]@{Frameworks=@()}}
$script:passed=0;$script:failed=0
function Assert-WinSecPublicFinding {param([bool]$Condition);if(-not $Condition){throw 'Public finding assertion failed.'}}
function Test-WinSecPublicFinding {
    param([string]$Name,[scriptblock]$Action)
    try {$null=& $Action;$script:passed++;Write-Host "[PASS] $Name"}
    catch {$script:failed++;Write-Host "[FAIL] $Name";Write-Host $_.Exception.Message}
}
function New-WinSecPublicFindingFixture {
    $device='local:FINDINGS-UI';$scan='findings-ui-1'
    $controls=@(foreach($id in @('WSA-SYS-001','WSA-SYS-002','WSA-NET-001')){
        [pscustomobject]@{DeviceId=$device;ScanId=$scan;CheckId=$id;Status='NOT_EVALUATED'}
    })
    $findings=@(for($index=0;$index -lt $controls.Count;$index++){
        [pscustomobject]@{DeviceId=$device;ScanId=$scan;CheckId=$controls[$index].CheckId;
            FindingId=('finding-'+$index);Kind='EVALUATION_PENDING';EvaluationStatus='NOT_EVALUATED';
            Severity='UNASSIGNED';Priority='UNASSIGNED'}
    })
    [pscustomobject]@{
        State=[pscustomobject]@{Screen='Findings';SelectedDeviceId=$device;SectionIndex=0;ControlIndex=0;FindingsScope='Section';FindingsOffset=0}
        Controls=$controls;Findings=$findings;ScanId=$scan
    }
}
function Get-WinSecPublicFindingView {
    param($Fixture)
    Get-WinSecSelectedFindings -NavigationState $Fixture.State -ControlResults $Fixture.Controls `
        -Findings $Fixture.Findings -ScanId $Fixture.ScanId
}
function Assert-WinSecPublicFindingRejected {
    param($Fixture)
    $published=New-Object 'System.Collections.Generic.List[object]';$caught=$null
    try {Get-WinSecPublicFindingView $Fixture|ForEach-Object{$published.Add($_)}}catch{$caught=$_}
    Assert-WinSecPublicFinding ($null -ne $caught -and $published.Count -eq 0 -and
        $caught.Exception.Message -notlike '*SYNTHETIC-FINDING-PRIVATE*')
}
Test-WinSecPublicFinding 'Public CheckId-only findings resolve the section without fabricated ratings' {
    $fixture=New-WinSecPublicFindingFixture;$view=Get-WinSecPublicFindingView $fixture
    Assert-WinSecPublicFinding ($view.Findings.Count -eq 2 -and $view.Score -ceq 'NOT_SCORED' -and
        $view.Findings[0].SectionKey -ceq 'SystemSecurity' -and $view.Findings[0].Priority -ceq 'UNASSIGNED' -and
        $view.Findings[0].Severity -ceq 'UNASSIGNED' -and $view.Findings[0].Kind -ceq 'EVALUATION_PENDING' -and
        $view.Findings[0].EvaluationStatus -ceq 'NOT_EVALUATED' -and $view.Findings[0].Finding -ne 'Unnamed finding')
}
Test-WinSecPublicFinding 'Control selection uses exact CheckId' {
    $fixture=New-WinSecPublicFindingFixture;$fixture.State.FindingsScope='Control';$fixture.State.ControlIndex=1
    $view=Get-WinSecPublicFindingView $fixture
    Assert-WinSecPublicFinding ($view.Findings.Count -eq 1 -and $view.Findings[0].CheckId -ceq 'WSA-SYS-002')
}
Test-WinSecPublicFinding 'Unassigned values remain unchanged even with legacy routing fields' {
    $fixture=New-WinSecPublicFindingFixture
    $fixture.Findings[0]|Add-Member -NotePropertyName SectionKey -NotePropertyValue SystemSecurity
    $fixture.Findings[1]|Add-Member -NotePropertyName SectionKey -NotePropertyValue SystemSecurity
    $view=Get-WinSecPublicFindingView $fixture
    Assert-WinSecPublicFinding ($view.Findings.Count -eq 2 -and @($view.Findings|Where-Object{$_.Priority -cne 'UNASSIGNED' -or $_.Severity -cne 'UNASSIGNED'}).Count -eq 0)
}
foreach($kind in @('CONFIGURATION_DEVIATION','EVIDENCE_GAP','EVALUATION_UNAVAILABLE','COLLECTION_ERROR',
    'CRITERION_PENDING','EVALUATION_PENDING','CATALOG_NOT_READY','EVALUATION_NOT_TRUSTED',
    'EVALUATION_DATA_ERROR','EVALUATION_IDENTITY_ERROR','DUPLICATE_CRITERION','UNCLASSIFIED')) {
    Test-WinSecPublicFinding ("Public diagnostic kind remains a data record: $kind") {
        $fixture=New-WinSecPublicFindingFixture;$fixture.Findings[0].Kind=$kind
        $view=Get-WinSecPublicFindingView $fixture
        Assert-WinSecPublicFinding ($view.Findings[0].Kind -ceq $kind -and $view.Findings[0].Priority -ceq 'UNASSIGNED')
    }
}
foreach($field in @('DeviceId','ScanId','CheckId','FindingId')) {
    foreach($value in @($null,'',123,@('findings-ui-1'))) {
        Test-WinSecPublicFinding ("Invalid identity rejects before output: $field") {
            $fixture=New-WinSecPublicFindingFixture;$fixture.Findings[0].$field=$value
            Assert-WinSecPublicFindingRejected $fixture
        }
    }
}
foreach($spec in @(
    @{Field='DeviceId';Value='local:OTHER'},@{Field='ScanId';Value='other-scan'},
    @{Field='CheckId';Value='WSA-UNKNOWN-001'},@{Field='SectionKey';Value='NetworkSecurity'},
    @{Field='ControlKey';Value='BitLocker'},@{Field='Severity';Value='HIGH'},@{Field='Priority';Value='P1'},
    @{Field='Kind';Value='SYNTHETIC-FINDING-PRIVATE'},@{Field='EvaluationStatus';Value=@('FAIL')}
)) {
    Test-WinSecPublicFinding ('Conflicting or unapproved data rejects: '+$spec.Field) {
        $fixture=New-WinSecPublicFindingFixture
        $fixture.Findings[0]|Add-Member -NotePropertyName $spec.Field -NotePropertyValue $spec.Value -Force
        Assert-WinSecPublicFindingRejected $fixture
    }
}
foreach($field in @('Evidence','RawEvidence','OriginalResult','ObservedValue','ExpectedValue','Score','ScoringPolicy')) {
    Test-WinSecPublicFinding ("Nested private or scoring field cannot reach the view: $field") {
        $fixture=New-WinSecPublicFindingFixture
        $fixture.Findings[0]|Add-Member -NotePropertyName Metadata -NotePropertyValue @{Keys='decoy';Values=@(@{$field='SYNTHETIC-FINDING-PRIVATE'})}
        Assert-WinSecPublicFindingRejected $fixture
    }
}
foreach($field in @('FindingId','DeviceId','CheckId','Title','Recommendation')) {
    Test-WinSecPublicFinding ("Calculated property rejects without getter execution: $field") {
        $fixture=New-WinSecPublicFindingFixture;$script:getterCalls=0
        $fixture.Findings[0].PSObject.Properties.Remove($field)
        $fixture.Findings[0]|Add-Member -MemberType ScriptProperty -Name $field -Value {$script:getterCalls++;'SYNTHETIC-FINDING-PRIVATE'}
        Assert-WinSecPublicFindingRejected $fixture
        Assert-WinSecPublicFinding ($script:getterCalls -eq 0)
    }
}
Test-WinSecPublicFinding 'Duplicate FindingId rejects without partial publication' {
    $fixture=New-WinSecPublicFindingFixture;$fixture.Findings[1].FindingId=$fixture.Findings[0].FindingId
    Assert-WinSecPublicFindingRejected $fixture
}
Test-WinSecPublicFinding 'A finding requires a collected control from the same assessment' {
    $fixture=New-WinSecPublicFindingFixture;$fixture.Controls=@($fixture.Controls[1],$fixture.Controls[2])
    Assert-WinSecPublicFindingRejected $fixture
}
Test-WinSecPublicFinding 'Foreign collector identity is rejected' {
    $fixture=New-WinSecPublicFindingFixture;$fixture.Controls[0].ScanId='other-scan'
    Assert-WinSecPublicFindingRejected $fixture
}
foreach($field in @('Title','Description','Recommendation')) {
    Test-WinSecPublicFinding ("Structured legacy display data is rejected: $field") {
        $fixture=New-WinSecPublicFindingFixture
        $fixture.Findings[0]|Add-Member -NotePropertyName $field -NotePropertyValue @{Value='SYNTHETIC-FINDING-PRIVATE'}
        Assert-WinSecPublicFindingRejected $fixture
    }
}
Test-WinSecPublicFinding 'Safe legacy text stays usable without reclassifying the finding' {
    $fixture=New-WinSecPublicFindingFixture
    $fixture.Findings[0]|Add-Member -NotePropertyName Title -NotePropertyValue 'Evaluation is pending'
    $fixture.Findings[0]|Add-Member -NotePropertyName Recommendation -NotePropertyValue 'Review the approved criteria manually.'
    $view=Get-WinSecPublicFindingView $fixture
    Assert-WinSecPublicFinding ($view.Findings[0].Finding -ceq 'Evaluation is pending' -and
        $view.Findings[0].Recommendation -ceq 'Review the approved criteria manually.' -and $view.Findings[0].Evidence -ceq '')
}
Test-WinSecPublicFinding 'Mutating the view cannot rewrite caller records or later reads' {
    $fixture=New-WinSecPublicFindingFixture;$before=ConvertTo-Json -InputObject $fixture -Depth 12 -Compress
    $view=Get-WinSecPublicFindingView $fixture;$view.Findings[0].Priority='P1';$view.Findings[0].CheckId='changed'
    $next=Get-WinSecPublicFindingView $fixture
    Assert-WinSecPublicFinding ($next.Findings[0].CheckId -ceq 'WSA-SYS-001' -and $next.Findings[0].Priority -ceq 'UNASSIGNED' -and
        $before -ceq (ConvertTo-Json -InputObject $fixture -Depth 12 -Compress))
}
Test-WinSecPublicFinding 'Multiple scans without explicit selection remain ambiguous' {
    $fixture=New-WinSecPublicFindingFixture;$fixture.ScanId='';$fixture.Findings[1].ScanId='second-scan'
    $view=Get-WinSecPublicFindingView $fixture
    Assert-WinSecPublicFinding ($view.Findings.Count -eq 0 -and -not [string]::IsNullOrWhiteSpace($view.Warning))
}
Test-WinSecPublicFinding 'Missing device returns an empty warning view' {
    $fixture=New-WinSecPublicFindingFixture;$fixture.State.SelectedDeviceId=''
    $view=Get-WinSecPublicFindingView $fixture
    Assert-WinSecPublicFinding ($view.Findings.Count -eq 0 -and -not [string]::IsNullOrWhiteSpace($view.Warning))
}
Test-WinSecPublicFinding 'The UI does not invoke priority classification' {
    $fixture=New-WinSecPublicFindingFixture;$script:priorityCalls=0
    function Invoke-WinSecFindingPrioritization {param($Findings);$script:priorityCalls++;throw 'Unexpected classification.'}
    $view=Get-WinSecPublicFindingView $fixture
    Assert-WinSecPublicFinding ($view.Findings.Count -eq 2 -and $script:priorityCalls -eq 0)
}
Test-WinSecPublicFinding 'A single scan can be resolved without guessing from another section' {
    $fixture=New-WinSecPublicFindingFixture;$fixture.ScanId=''
    $view=Get-WinSecPublicFindingView $fixture
    Assert-WinSecPublicFinding ($view.ScanId -ceq 'findings-ui-1' -and $view.Findings.Count -eq 2)
}
foreach($kind in @('CYCLE','EXCESSIVE')) {
    Test-WinSecPublicFinding ("Unsafe graphs reject before publication: $kind") {
        $fixture=New-WinSecPublicFindingFixture
        $metadata=if($kind -eq 'CYCLE'){$fixture.Findings[0]}else{New-Object 'object[]' 10001}
        $fixture.Findings[0]|Add-Member -NotePropertyName Metadata -NotePropertyValue $metadata
        Assert-WinSecPublicFindingRejected $fixture
    }
}
Test-WinSecPublicFinding 'Caller supplied framework labels are not treated as configured references' {
    $fixture=New-WinSecPublicFindingFixture
    $fixture.Findings[0]|Add-Member -NotePropertyName FrameworkReferences -NotePropertyValue @(
        @{FrameworkId='forged';FrameworkName='SYNTHETIC-FINDING-PRIVATE';ReferenceId='forged'}
    )
    $view=Get-WinSecPublicFindingView $fixture
    Assert-WinSecPublicFinding ($view.Findings[0].FrameworkReferences.Count -eq 0 -and
        (ConvertTo-Json -InputObject $view -Depth 10 -Compress) -notlike '*SYNTHETIC-FINDING-PRIVATE*')
}
Test-WinSecPublicFinding 'Framework load errors do not disclose diagnostics even with Verbose' {
    $fixture=New-WinSecPublicFindingFixture
    function Get-WinSecFrameworkCatalog {[CmdletBinding()]param();throw 'SYNTHETIC-FINDING-PRIVATE'}
    $items=@(Get-WinSecSelectedFindings -NavigationState $fixture.State -ControlResults $fixture.Controls `
        -Findings $fixture.Findings -ScanId $fixture.ScanId -Verbose 4>&1)
    Assert-WinSecPublicFinding ($items.Count -eq 1 -and $items[0].FrameworkStatus -ceq 'ERROR' -and
        (ConvertTo-Json -InputObject $items -Depth 10 -Compress) -notlike '*SYNTHETIC-FINDING-PRIVATE*')
}
Test-WinSecPublicFinding 'Direct detail rendering never reads or prints an Evidence property' {
    $script:evidenceCalls=0;$script:detailFields=@{}
    $finding=[pscustomobject]@{Priority='UNASSIGNED';Severity='UNASSIGNED';Description='Pending';Recommendation='';Reference='';FrameworkReferences=@()}
    $finding|Add-Member -MemberType ScriptProperty -Name Evidence -Value {$script:evidenceCalls++;'SYNTHETIC-FINDING-PRIVATE'}
    function Write-WinSecSectionTitle {param($Title)}
    function Write-WinSecText {param($Text,$Color)}
    function Write-WinSecFindingField {param($Label,$Value,$MaxLines);$script:detailFields[$Label]=$Value}
    Write-WinSecFindingDetails -Finding $finding -DetailPlan ([pscustomobject]@{ShowDetails=$true;TextLines=1;ReferenceLines=1})
    Assert-WinSecPublicFinding ($script:evidenceCalls -eq 0 -and $script:detailFields.Evidence -ceq 'Not included in public results.')
}
Test-WinSecPublicFinding 'Navigation counts agree with the visible CheckId selection' {
    $fixture=New-WinSecPublicFindingFixture;$device=$fixture.State.SelectedDeviceId;$scan=$fixture.ScanId
    $key='{0}:{1}{2}:{3}' -f $device.Length,$device,$scan.Length,$scan
    $public=[pscustomobject]@{PublicProjection=$true;ContainsRawEvidence=$false;DeviceId=$device;ScanId=$scan;
        ScoringEligible=$false;OverallScore=$null;OverallStatus='NOT_SCORED';SectionResults=@();
        ControlResults=$fixture.Controls;Findings=$fixture.Findings}
    $context=[pscustomobject]@{PublicScans=@{$key=$public};ActiveScanByDevice=@{$device=$scan}}
    $sectionCount=Get-WinSecCLINavigationCounts -State $fixture.State -Context $context
    $fixture.State.FindingsScope='Control';$fixture.State.ControlIndex=1
    $controlCount=Get-WinSecCLINavigationCounts -State $fixture.State -Context $context
    Assert-WinSecPublicFinding ($sectionCount.FindingCount -eq 2 -and $controlCount.FindingCount -eq 1)
}
Test-WinSecPublicFinding 'Configured reference data is copied and reduced to public context fields' {
    $fixture=New-WinSecPublicFindingFixture
    $script:referenceFixture=[pscustomobject]@{FrameworkId='nist-csf';FrameworkName='NIST CSF';FrameworkVersion='2.0';
        CheckId='WSA-SYS-001';ReferenceId='PR.PS-01';PrivateNotes='SYNTHETIC-FINDING-PRIVATE'}
    function Get-WinSecCheckFrameworkReferences {
        param($CheckId,$Platform,$Catalog)
        if($CheckId -ceq 'WSA-SYS-001'){$script:referenceFixture}
    }
    $view=Get-WinSecPublicFindingView $fixture
    $reference=$view.Findings[0].FrameworkReferences[0]
    Assert-WinSecPublicFinding ($reference.ReferenceId -ceq 'PR.PS-01' -and
        $null -eq $reference.PSObject.Properties['PrivateNotes'] -and
        (ConvertTo-Json -InputObject $view -Depth 10 -Compress) -notlike '*SYNTHETIC-FINDING-PRIVATE*')
    $reference.FrameworkVersion='changed'
    Assert-WinSecPublicFinding ($script:referenceFixture.FrameworkVersion -ceq '2.0')
}
Test-WinSecPublicFinding 'A configured reference for another control is not published' {
    $fixture=New-WinSecPublicFindingFixture
    function Get-WinSecCheckFrameworkReferences {
        param($CheckId,$Platform,$Catalog)
        [pscustomobject]@{FrameworkId='nist-csf';FrameworkName='NIST CSF';FrameworkVersion='2.0';
            CheckId='WSA-OTHER-001';ReferenceId='PR.PS-01'}
    }
    Assert-WinSecPublicFindingRejected $fixture
}
foreach($field in @('SelectedDeviceId','FindingsScope')) {
    Test-WinSecPublicFinding ("Navigation arrays cannot masquerade as scalar selection: $field") {
        $fixture=New-WinSecPublicFindingFixture;$fixture.State.$field=@($fixture.State.$field)
        Assert-WinSecPublicFindingRejected $fixture
    }
}
Write-Host "Passed: $script:passed"
Write-Host "Failed: $script:failed"
if($script:failed -gt 0){throw "$script:failed public finding test(s) failed."}
