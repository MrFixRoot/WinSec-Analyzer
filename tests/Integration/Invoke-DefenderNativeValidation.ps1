# Explicit native validation only. Default prepares a request; never collects automatically.
# No inventory/history/report writes, no Windows changes, no execution-policy override.
[CmdletBinding()]
param(
    [switch]$PlanOnly,
    [string]$OperationId = '',
    [string]$ApprovedRequestHash = '',
    [ValidatePattern('\AWSA-W11-2[1-6]H[12]-[A-Z][A-Z0-9-]{0,39}-DEF-BASE\z')]
    [string]$Profile = 'WSA-W11-24H2-PRO-DEF-BASE',
    [AllowNull()][psobject]$DiagnosticState=$null
)
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'tests/Fixtures/NativeValidationDiagnostics.ps1')
$nativeTrace=if($null -ne $DiagnosticState){$DiagnosticState}else{[pscustomobject]@{Diagnostic=$null}}
$nativePhase='NATIVE_BOOTSTRAP';$nativeReason='UNCLASSIFIED';$nativeAuditNormalizer=$null
try {
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
. (Join-Path $root 'tests/Fixtures/FrameworkNativeValidationSupport.ps1')
$nativePhase='NATIVE_IDENTITY'
$target=New-WinSecLocalTarget
$nativePhase='NATIVE_REQUEST'
if ([string]::IsNullOrWhiteSpace($OperationId)) {
    if (-not $PlanOnly) { throw 'A prepared and explicitly approved native operation is required.' }
    $OperationId=[guid]::NewGuid().ToString('N')
}
if ($OperationId -cnotmatch '\A[a-f0-9]{32}\z') { throw 'Invalid native validation operation identifier.' }
$snapshot=Get-WinSecAssessmentCatalog $root 'WSA-SYS-001' -Profile $Profile
$rules=Get-WinSecFrameworkAnalysisCatalog $root nist-csf
$request=[pscustomobject][ordered]@{
    Operation='VALIDATE_DEFENDER_READ_ONLY';OperationId=$OperationId;DeviceId=$target.DeviceId;Hostname=$target.Hostname
    ScopeType='CONTROL';ScopeKey='WSA-SYS-001';Checks=@('Windows Defender / WSA-SYS-001')
    Runtime=$PSVersionTable.PSVersion.ToString();Profile=$Profile;CriteriaSha256=$snapshot.Sha256
    AssessmentMode='FRAMEWORK_REVIEW';FrameworkRulesSha256=$rules.RuleHash
    FrameworkProbeSha256=(Get-FileHash -LiteralPath (Join-Path $root 'tests/Fixtures/FrameworkNativeValidationSupport.ps1')).Hash
    ValidatorSha256=(Get-FileHash -LiteralPath $PSCommandPath).Hash
    CollectorSha256=(Get-FileHash -LiteralPath (Join-Path $root 'src/Checks/Defender/Test-Defender.ps1') -Algorithm SHA256).Hash
    NativeDiagnosticSchemaVersion='WinSec.ValidationDiagnostic1.1'
    DiagnosticHelperSha256=(Get-FileHash -LiteralPath (Join-Path $root 'tests/Fixtures/NativeValidationDiagnostics.ps1') -Algorithm SHA256).Hash
    ReadOnly=$true;PersistPublicHistory=$false;PersistRawEvidence=$false
    Note='Only Defender is executable in an isolated validation registry. Production check permissions are unchanged. Actual OS applicability is checked after confirmation; mismatches remain explicit gaps. Framework Findings and Markdown are checked in memory, without ratings or persistence.'
}
$json=ConvertTo-Json $request -Depth 6 -Compress
$sha=[Security.Cryptography.SHA256]::Create()
try {$hash=[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($json))).Replace('-','')} finally {$sha.Dispose()}
if ($PlanOnly) { [pscustomobject]@{Request=$request;RequestHash=$hash}|ConvertTo-Json -Depth 8; return }
$nativePhase='NATIVE_APPROVAL'
if ($ApprovedRequestHash -cnotmatch '\A[A-F0-9]{64}\z' -or $ApprovedRequestHash -cne $hash) {
    $nativeReason='APPROVAL_REJECTED';throw 'Native validation request changed or lacks explicit approval.'
}

# Same revocation guard as the coordinator, checked explicitly for a closed reason.
# The coordinator still performs its own check; this never registers or revives a target.
$nativePhase='NATIVE_INVENTORY'
$inventory=Import-WinSecDeviceInventory -ProjectRoot $root
if(Test-WinSecDeviceInventoryRemoval -Inventory $inventory -DeviceId $target.DeviceId){
    $nativeReason='TARGET_REMOVED';throw 'Target authorization was revoked.'
}
$nativePhase='NATIVE_REGISTRY'

# Validation fixture only, scoped to this process and this one approved CheckId.
# The production checks.json and executionPolicy are never edited by this helper.
$script:nativeRegistryReader=(Get-Command Get-WinSecCheckRegistry).ScriptBlock
function Get-WinSecCheckRegistry {
    param($ProjectRoot)
    $registry=& $script:nativeRegistryReader -ProjectRoot $ProjectRoot
    foreach ($check in $registry.Checks) {
        $check.ExecutionEnabled=($check.CheckId -ceq 'WSA-SYS-001')
        if ($check.CheckId -ceq 'WSA-SYS-001') {
            $check.ExecutionReady=$true;$check.ImplementationStatus='VALIDATED';$check.RegistryStatus='READY'
        }
    }
    return $registry
}
$nativePhase='NATIVE_COORDINATOR'
$coordinator=New-WinSecScanCoordinator -ProjectRoot $root
$coordinator.Registry=[pscustomobject]@{schemaVersion='1.0.0';targets=@($target)}
$coordinator.AssessmentEnabled=$true
if ($coordinator.PublicHistoryEnabled -or $coordinator.EvidenceEnabled) {
    $nativeReason='PERSISTENCE_ENABLED';throw 'Native validation must not persist results.'
}
# Observe only the validation process, forwarding the original normalizer unchanged.
# A swallowed AuditEngine error can then retain its closed origin without raw evidence.
$nativeAuditNormalizer=(Get-Command ConvertTo-WinSecAuditRecord -CommandType Function).ScriptBlock
function ConvertTo-WinSecAuditRecord {
    [CmdletBinding()]param([Parameter(Mandatory)][object]$RawResult,[Parameter(Mandatory)][object]$Check,
        [Parameter(Mandatory)][string]$DeviceId,[Parameter(Mandatory)][string]$ScanId)
    $evidence=Get-WinSecNativeDiagnosticField $RawResult Evidence
    $collected=Get-WinSecNativeDiagnosticField $evidence CollectionSuccessful
    if((Get-WinSecNativeDiagnosticField $RawResult CheckId) -ceq 'WSA-SYS-001' -and $collected -is [bool] -and $collected -ceq $false){
        $source=Get-WinSecNativeDiagnosticField $evidence StatusSource
        if($null -eq $source){Set-WinSecNativeValidationFailure $nativeTrace NATIVE_STATUS_PROVIDER STATUS_UNAVAILABLE}
        elseif($source -cin @('Get-MpComputerStatus','CIM:MSFT_MpComputerStatus')){Set-WinSecNativeValidationFailure $nativeTrace NATIVE_STATUS_PROVIDER STATUS_UNUSABLE}
    }
    try{& $nativeAuditNormalizer @PSBoundParameters}catch{
        Set-WinSecNativeValidationFailure -State $nativeTrace -Phase NATIVE_NORMALIZATION -Reason NORMALIZATION_REJECTED -Failure $_
        throw
    }
}
$nativePhase='NATIVE_SCAN'
$public=Invoke-WinSecCoordinatedScan -Coordinator $coordinator -DeviceId $target.DeviceId -ScanId ('native-'+$OperationId) `
    -ScopeType CONTROL -ScopeKey WSA-SYS-001 -AssessmentProfile $Profile -ConfirmAction {
        param($Preview)
        $Preview.DeviceId -ceq $request.DeviceId -and $Preview.ScopeType -ceq 'CONTROL' -and $Preview.ScopeKey -ceq 'WSA-SYS-001' -and
            $Preview.ReadOnly -ceq $true -and $Preview.Checks.Count -eq 1 -and $Preview.Checks[0].CheckId -ceq 'WSA-SYS-001' -and
            $Preview.AssessmentMode -ceq $request.AssessmentMode -and $null -eq $Preview.ConfigurationScoring -and
            (Get-WinSecFrameworkAnalysisCatalog $root nist-csf).RuleHash -ceq $request.FrameworkRulesSha256
    }
$nativePhase='NATIVE_CONTROL_VALIDATION'
$control=@($public.ControlResults|Where-Object CheckId -CEQ WSA-SYS-001)
$sessions=@($coordinator.Sessions.Values)
$session=if($sessions.Count -eq 1){$sessions[0].Session}else{$null}
foreach($item in @($session.ControlResults)){
    if((Get-WinSecNativeDiagnosticField $item CheckId) -ceq 'WSA-SYS-001' -and
        (Get-WinSecNativeDiagnosticField $item ObservedStatus) -ceq 'ERROR' -and
        (Get-WinSecNativeDiagnosticField $item ValidationIssue) -ceq 'Check execution failed.'){
        Set-WinSecNativeValidationFailure $nativeTrace NATIVE_CHECK_EXECUTION CHECK_EXECUTION_FAILED
    }
}
if ($control.Count -ne 1 -or $control[0].ObservedStatus -ceq 'ERROR' -or $public.ExecutionStatus -cnotin @('COMPLETED','COMPLETED_WITH_ERRORS')) {
    $nativeReason='CONTROL_RESULT_REJECTED';throw 'Native Defender validation could not collect a valid informational result.'
}
if($null -ne $session.ConfigurationAssessment){
    $nativeReason='RATING_PRESENT';throw 'Native framework review cannot publish a rating.'
}
$nativePhase='NATIVE_HISTORY_WRITE'
$record=New-WinSecPublicHistoryRecord $session
$recordJson=Get-WinSecPublicHistoryJson $record
$nativePhase='NATIVE_HISTORY_READ'
$restored=ConvertFrom-WinSecPublicHistoryRecord (ConvertFrom-WinSecStoredJson $recordJson)
$nativePhase='NATIVE_HISTORY_VALIDATION'
if((Get-WinSecPublicHistoryJson $restored.PublicResult) -cne (Get-WinSecPublicHistoryJson (ConvertTo-WinSecPublicScanResult $session))){
    $nativeReason='HISTORY_MISMATCH';throw 'Public history integrity mismatch.'
}
$nativePhase='NATIVE_TECHNICAL_PROJECTION'
$technical=New-WinSecTechnicalReport $session WSA-SYS-001 $target.Hostname $target.Hostname
$source=[pscustomobject]@{CheckId='WSA-SYS-001';ScanId=$session.ScanId;ScopeType=$session.ScopeType;ScopeKey=$session.ScopeKey;
    CompletedAtUTC=$session.CompletedAtUTC;Origin='LIVE';PublicResult=$restored.PublicResult;
    CatalogVersion=$session.CatalogVersion;ExpectedCheckIds=@($session.ExpectedCheckIds)}
$reportCount=0
foreach($framework in @('nist-csf','cis-controls','mitre-attack')){
    $frameworkTag=switch($framework){nist-csf{'NIST'};cis-controls{'CIS'};mitre-attack{'MITRE'}}
    $nativePhase='NATIVE_'+$frameworkTag+'_ANALYSIS'
    $view=New-WinSecFrameworkAnalysis -ProjectRoot $root -DeviceId $session.DeviceId -DeviceName $target.Hostname `
        -ScopeType CONTROL -ScopeKey WSA-SYS-001 -FrameworkId $framework -Sources @($source) -Reports @($technical)
    $nativePhase='NATIVE_'+$frameworkTag+'_MARKDOWN'
    $markdown=New-WinSecFrameworkMarkdown $view
    $nativePhase='NATIVE_FRAMEWORK_VALIDATION'
    if(-not $markdown -or $view.DeviceId -cne $session.DeviceId -or $view.Sources[0].ScanId -cne $session.ScanId){
        $nativeReason='FRAMEWORK_MISMATCH';throw 'Framework result identity mismatch.'
    }
    $reportCount++
}
$nativePhase='NATIVE_SUMMARY'
$selection=@($session.CriteriaSelections|Where-Object CheckId -CEQ WSA-SYS-001)
$diagnostics=@(foreach($item in @($selection.ExcludedCriteria)) {
    if ($item.Reason -cin @('WINDOWS_SCOPE_MISMATCH','CRITERION_NOT_VERIFIED','DEPENDENCIES_NOT_DECLARED','PREREQUISITES_NOT_CONFIRMED')) {$item.Reason}
})|Sort-Object -Unique
$summary=[pscustomobject]@{
    OperationId=$OperationId;Runtime=$PSVersionTable.PSVersion.ToString();ExecutionStatus=$public.ExecutionStatus
    CollectedControls=$control.Count;ObservedStatus=$control[0].ObservedStatus;PublicFindings=@($public.Findings).Count
    AssessmentMode='FRAMEWORK_REVIEW';ReadingCount=$technical.Rows.Count
    PublicHistoryRoundtripValidated=$true;InMemoryReports=$reportCount
    ApplicabilityDiagnostics=@($diagnostics)
    RawEvidencePersisted=$false;PublicHistoryPersisted=$false;WindowsChanges=$false
}
$nativePhase='NATIVE_SERIALIZATION'
$summary|ConvertTo-Json -Depth 5
}catch{
    Set-WinSecNativeValidationFailure -State $nativeTrace -Phase $nativePhase -Reason $nativeReason -Failure $_
    $safeDiagnostic=Copy-WinSecNativeValidationDiagnostic $nativeTrace.Diagnostic
    if($null -eq $safeDiagnostic){throw 'Invalid internal diagnostic; native validation failed.'}
    $safeMessage='Native validation failed. Phase={0}; Component={1}; Category={2}; Reason={3}.' -f
        $safeDiagnostic.Phase,$safeDiagnostic.Component,$safeDiagnostic.Category,$safeDiagnostic.Reason
    $safeError=[Management.Automation.ErrorRecord]::new([InvalidOperationException]::new($safeMessage),
        ('WINSEC_NATIVE_'+$safeDiagnostic.Phase+'_'+$safeDiagnostic.Category),[Management.Automation.ErrorCategory]::InvalidResult,$null)
    $PSCmdlet.ThrowTerminatingError($safeError)
}finally{
    if($null -ne $nativeAuditNormalizer){Set-Item -Path Function:ConvertTo-WinSecAuditRecord -Value $nativeAuditNormalizer}
}
