# Synthetic validator actions only. Importing the fixture does not authorize an audit.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../Fixtures/NativeValidationDiagnostics.ps1')
$script:diagPass=0;$script:diagFail=0
$script:diagOperation='12345678123456781234567812345678'
$script:diagRuntime=$PSVersionTable.PSVersion.ToString()
$script:diagMarker='PRIVATE_MARKER_DO_NOT_EXPORT'
function Test-WinSecDiagnostic {param([string]$Name,[scriptblock]$Body)
    try{& $Body;$script:diagPass++;[Console]::WriteLine('[PASS] '+$Name)}catch{$script:diagFail++;[Console]::WriteLine('[FAIL] '+$Name)}
}
function Assert-WinSecDiagnostic {param([bool]$Condition);if(-not $Condition){throw 'Synthetic diagnostic assertion failed.'}}
function New-WinSecDiagnosticSummary {
    [pscustomobject][ordered]@{OperationId=$script:diagOperation;Runtime=$script:diagRuntime;ExecutionStatus='COMPLETED';
        CollectedControls=1;ObservedStatus='INFORMATIONAL';PublicFindings=2;AssessmentMode='FRAMEWORK_REVIEW';ReadingCount=84;
        PublicHistoryRoundtripValidated=$true;InMemoryReports=3;ApplicabilityDiagnostics=@();
        RawEvidencePersisted=$false;PublicHistoryPersisted=$false;WindowsChanges=$false}
}
function Assert-WinSecDiagnosticFailure {param([scriptblock]$Action,[string]$Phase,[string]$Component,[string]$Category)
    $state=[pscustomobject]@{Diagnostic=$null};$caught=$null;$published=New-Object 'Collections.Generic.List[object]'
    try{Invoke-WinSecValidationDiagnosticAttempt $Action $script:diagOperation $script:diagRuntime $state|ForEach-Object{$published.Add($_)}}catch{$caught=$_}
    Assert-WinSecDiagnostic ($null -ne $caught -and $published.Count -eq 0)
    $diagnostic=$state.Diagnostic
    Assert-WinSecDiagnostic ($diagnostic.Phase -ceq $Phase -and $diagnostic.Component -ceq $Component -and $diagnostic.Category -ceq $Category -and $diagnostic.AttemptConsumed -ceq $true)
    $exposed=($caught|Out-String)+($caught|Format-List * -Force|Out-String)+(Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject $diagnostic -Depth 5)
    Assert-WinSecDiagnostic (-not $exposed.Contains($script:diagMarker) -and $null -eq $caught.Exception.InnerException -and $null -eq $caught.TargetObject)
    Assert-WinSecDiagnostic ($caught.FullyQualifiedErrorId.StartsWith(('WINSEC_VALIDATION_'+$Phase+'_'+$Category),[StringComparison]::Ordinal))
}
Test-WinSecDiagnostic 'Valid summary retains all fields and does not manufacture diagnostics' {
    $state=[pscustomobject]@{Diagnostic=$null};$expected=New-WinSecDiagnosticSummary
    $actual=Invoke-WinSecValidationDiagnosticAttempt {New-WinSecDiagnosticSummary|ConvertTo-Json -Depth 5} $script:diagOperation $script:diagRuntime $state
    Assert-WinSecDiagnostic ($actual -is [string] -and $null -eq $state.Diagnostic)
    Assert-WinSecDiagnostic (($actual|ConvertFrom-Json|ConvertTo-Json -Depth 5 -Compress) -ceq ($expected|ConvertTo-Json -Depth 5 -Compress))
}
foreach($case in @(
    @{Name='permission category';Type=[UnauthorizedAccessException];Category='ACCESS_DENIED'},
    @{Name='timeout category';Type=[TimeoutException];Category='TIMEOUT'},
    @{Name='cancellation category';Type=[OperationCanceledException];Category='CANCELLED'},
    @{Name='I/O category';Type=[IO.IOException];Category='IO_ERROR'},
    @{Name='unknown exception remains unknown';Type=[InvalidOperationException];Category='UNKNOWN_ERROR'})) {
    Test-WinSecDiagnostic $case.Name {
        $exception=[Activator]::CreateInstance($case.Type,@($script:diagMarker))
        Assert-WinSecDiagnosticFailure {throw $exception} VALIDATOR_EXECUTION VALIDATION_HELPER $case.Category
    }
}
Test-WinSecDiagnostic 'Wrapped exception maps a known inner type without exposing it' {
    $inner=[TimeoutException]::new($script:diagMarker);$outer=[InvalidOperationException]::new($script:diagMarker,$inner)
    Assert-WinSecDiagnosticFailure {throw $outer} VALIDATOR_EXECUTION VALIDATION_HELPER TIMEOUT
}
Test-WinSecDiagnostic 'Redirected nonterminating error never becomes valid JSON' {
    Assert-WinSecDiagnosticFailure {Write-Error $script:diagMarker -ErrorAction Continue;New-WinSecDiagnosticSummary|ConvertTo-Json} VALIDATOR_EXECUTION VALIDATION_HELPER UNKNOWN_ERROR
}
Test-WinSecDiagnostic 'Malformed JSON is distinguished from validator failure' {
    Assert-WinSecDiagnosticFailure {('{"invalid":"'+$script:diagMarker)} SUMMARY_DECODING JSON_DECODER INVALID_JSON
}
Test-WinSecDiagnostic 'Additional stdout is withheld' {
    Assert-WinSecDiagnosticFailure {$script:diagMarker;New-WinSecDiagnosticSummary|ConvertTo-Json} SUMMARY_DECODING JSON_DECODER INVALID_DATA
}
Test-WinSecDiagnostic 'Warning stream is captured without exposing its content' {
    Assert-WinSecDiagnosticFailure {Write-Warning $script:diagMarker;New-WinSecDiagnosticSummary|ConvertTo-Json} SUMMARY_DECODING JSON_DECODER INVALID_DATA
}
Test-WinSecDiagnostic 'Host stream is captured without exposing its content' {
    Assert-WinSecDiagnosticFailure {Write-Host $script:diagMarker;New-WinSecDiagnosticSummary|ConvertTo-Json} SUMMARY_DECODING JSON_DECODER INVALID_DATA
}
Test-WinSecDiagnostic 'Missing output is identified without publishing a summary' {
    Assert-WinSecDiagnosticFailure {} SUMMARY_DECODING JSON_DECODER INVALID_DATA
}
Test-WinSecDiagnostic 'Oversized output is rejected before JSON decoding' {
    Assert-WinSecDiagnosticFailure {('x'*65537)} SUMMARY_DECODING JSON_DECODER INVALID_DATA
}
foreach($field in @('OperationId','Runtime','WindowsChanges','PublicHistoryPersisted','RawEvidencePersisted','PublicHistoryRoundtripValidated','ApplicabilityDiagnostics','ReadingCount')) {
    Test-WinSecDiagnostic ('Invalid summary field: '+$field) {
        $summary=New-WinSecDiagnosticSummary
        $summary.$field=switch($field){'WindowsChanges'{$true};'PublicHistoryPersisted'{$true};'RawEvidencePersisted'{$true};'PublicHistoryRoundtripValidated'{$false};'ReadingCount'{-1};default{$script:diagMarker}}
        Assert-WinSecDiagnosticFailure {$summary|ConvertTo-Json -Depth 5} SUMMARY_VALIDATION SUMMARY_CONTRACT INVALID_DATA
    }
}
Test-WinSecDiagnostic 'Unexpected property is never exported' {
    $summary=New-WinSecDiagnosticSummary;$summary|Add-Member SensitiveField $script:diagMarker
    Assert-WinSecDiagnosticFailure {$summary|ConvertTo-Json} SUMMARY_VALIDATION SUMMARY_CONTRACT INVALID_DATA
}
Test-WinSecDiagnostic 'Textual booleans cannot masquerade as false' {
    $summary=New-WinSecDiagnosticSummary;$summary.WindowsChanges='False'
    Assert-WinSecDiagnosticFailure {$summary|ConvertTo-Json} SUMMARY_VALIDATION SUMMARY_CONTRACT INVALID_DATA
}
Test-WinSecDiagnostic 'Serialization failures have a separate component' {
    function ConvertTo-Json { [CmdletBinding()]param($InputObject,$Depth);throw [IO.IOException]::new($script:diagMarker) }
    $json=Microsoft.PowerShell.Utility\ConvertTo-Json (New-WinSecDiagnosticSummary) -Depth 5
    Assert-WinSecDiagnosticFailure {$json} SUMMARY_ENCODING JSON_ENCODER IO_ERROR
}
[Console]::WriteLine(('Diagnostic tests: {0} passed, {1} failed.' -f $script:diagPass,$script:diagFail))
if($script:diagFail){throw 'Native validation diagnostic tests failed.'}
