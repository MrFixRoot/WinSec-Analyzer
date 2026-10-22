# Explicit native validation only. Default prepares a request; never collects automatically.
# No inventory/history/report writes, no Windows changes, no execution-policy override.
[CmdletBinding()]
param(
    [switch]$PlanOnly,
    [string]$OperationId = '',
    [string]$ApprovedRequestHash = '',
    [ValidatePattern('\AWSA-W11-2[1-6]H[12]-[A-Z][A-Z0-9-]{0,39}-DEF-BASE\z')]
    [string]$Profile = 'WSA-W11-24H2-PRO-DEF-BASE'
)
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
$target=New-WinSecLocalTarget
if ([string]::IsNullOrWhiteSpace($OperationId)) {
    if (-not $PlanOnly) { throw 'A prepared and explicitly approved native operation is required.' }
    $OperationId=[guid]::NewGuid().ToString('N')
}
if ($OperationId -cnotmatch '\A[a-f0-9]{32}\z') { throw 'Invalid native validation operation identifier.' }
$snapshot=Get-WinSecAssessmentCatalog $root 'WSA-SYS-001' -Profile $Profile
$scoring=Get-WinSecConfigurationScoringPolicy $root
$request=[pscustomobject][ordered]@{
    Operation='VALIDATE_DEFENDER_READ_ONLY';OperationId=$OperationId;DeviceId=$target.DeviceId;Hostname=$target.Hostname
    ScopeType='CONTROL';ScopeKey='WSA-SYS-001';Checks=@('Windows Defender / WSA-SYS-001')
    Runtime=$PSVersionTable.PSVersion.ToString();Profile=$Profile;CriteriaSha256=$snapshot.Sha256;ScoringPolicySha256=$scoring.Sha256
    CollectorSha256=(Get-FileHash -LiteralPath (Join-Path $root 'src/Checks/Defender/Test-Defender.ps1') -Algorithm SHA256).Hash
    ReadOnly=$true;PersistPublicHistory=$false;PersistRawEvidence=$false
    Note='Only Defender is executable in an isolated validation registry. Production check permissions are unchanged. Actual OS applicability is checked after confirmation; mismatches remain NOT_SCORED.'
}
$json=ConvertTo-Json $request -Depth 6 -Compress
$sha=[Security.Cryptography.SHA256]::Create()
try {$hash=[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($json))).Replace('-','')} finally {$sha.Dispose()}
if ($PlanOnly) { [pscustomobject]@{Request=$request;RequestHash=$hash}|ConvertTo-Json -Depth 8; return }
if ($ApprovedRequestHash -cnotmatch '\A[A-F0-9]{64}\z' -or $ApprovedRequestHash -cne $hash) { throw 'Native validation request changed or lacks explicit approval.' }

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
$coordinator=New-WinSecScanCoordinator -ProjectRoot $root
$coordinator.Registry=[pscustomobject]@{schemaVersion='1.0.0';targets=@($target)}
$coordinator.AssessmentEnabled=$true
if ($coordinator.PublicHistoryEnabled -or $coordinator.EvidenceEnabled) { throw 'Native validation must not persist results.' }
$public=Invoke-WinSecCoordinatedScan -Coordinator $coordinator -DeviceId $target.DeviceId -ScanId ('native-'+$OperationId) `
    -ScopeType CONTROL -ScopeKey WSA-SYS-001 -AssessmentProfile $Profile -ConfirmAction {
        param($Preview)
        $Preview.DeviceId -ceq $request.DeviceId -and $Preview.ScopeType -ceq 'CONTROL' -and $Preview.ScopeKey -ceq 'WSA-SYS-001' -and
            $Preview.ReadOnly -ceq $true -and $Preview.Checks.Count -eq 1 -and $Preview.Checks[0].CheckId -ceq 'WSA-SYS-001'
    }
$control=@($public.ControlResults|Where-Object CheckId -CEQ WSA-SYS-001)
if ($control.Count -ne 1 -or $control[0].ObservedStatus -ceq 'ERROR' -or $public.ExecutionStatus -cnotin @('COMPLETED','COMPLETED_WITH_ERRORS')) {
    throw 'Native Defender validation could not collect a valid informational result.'
}
$summary=Get-WinSecResultField $public 'ConfigurationAssessment'
$session=(@($coordinator.Sessions.Values)[0]).Session
$selection=@($session.CriteriaSelections|Where-Object CheckId -CEQ WSA-SYS-001)
$diagnostics=@(foreach($item in @($selection.ExcludedCriteria)) {
    if ($item.Reason -cin @('WINDOWS_SCOPE_MISMATCH','CRITERION_NOT_VERIFIED','DEPENDENCIES_NOT_DECLARED','PREREQUISITES_NOT_CONFIRMED')) {$item.Reason}
})|Sort-Object -Unique
[pscustomobject]@{
    OperationId=$OperationId;Runtime=$PSVersionTable.PSVersion.ToString();ExecutionStatus=$public.ExecutionStatus
    CollectedControls=$control.Count;ObservedStatus=$control[0].ObservedStatus;PublicFindings=@($public.Findings).Count
    ConfigurationScore=if ($null -ne $summary) {$summary.Controls[0].Value} else {$null}
    ConfigurationStatus=if ($null -ne $summary) {$summary.Controls[0].Status} else {'NOT_SCORED'}
    ApplicabilityDiagnostics=@($diagnostics)
    RawEvidencePersisted=$false;PublicHistoryPersisted=$false;WindowsChanges=$false
}|ConvertTo-Json -Depth 5
