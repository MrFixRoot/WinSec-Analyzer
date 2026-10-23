# Validación nativa explícita. PlanOnly identifica el equipo; no consulta BitLocker.
# La ejecución exige aprobación del hash de una operación concreta. Sin persistencia.
[CmdletBinding()]
param(
    [switch]$PlanOnly,
    [string]$OperationId='',
    [string]$ApprovedRequestHash='',
    [ValidatePattern('\AWSA-W11-2[1-6]H[12]-[A-Z][A-Z0-9-]{0,39}-DEF-BASE\z')]
    [string]$Profile='WSA-W11-23H2-PRO-DEF-BASE'
)
$ErrorActionPreference='Stop'
if([string]::IsNullOrWhiteSpace($OperationId)) {
    if(-not $PlanOnly){throw 'A prepared and explicitly approved native operation is required.'}
    $OperationId=[guid]::NewGuid().ToString('N')
}
if($OperationId -cnotmatch '\A[a-f0-9]{32}\z'){throw 'Invalid native validation operation identifier.'}
if(-not $PlanOnly -and $ApprovedRequestHash -cnotmatch '\A[A-F0-9]{64}\z'){throw 'Explicit approval of a prepared request hash is required.'}
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
$target=New-WinSecLocalTarget
$snapshot=Get-WinSecAssessmentCatalog $root WSA-SYS-002 -Profile $Profile
$scoring=Get-WinSecConfigurationScoringPolicy $root
$checksPath=Join-Path $root 'config/checks.json'
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
try {$processElevated=([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)}
finally {$identity.Dispose()}
$request=[pscustomobject][ordered]@{
    Operation='VALIDATE_BITLOCKER_READ_ONLY';OperationId=$OperationId;DeviceId=$target.DeviceId;Hostname=$target.Hostname
    ScopeType='CONTROL';ScopeKey='WSA-SYS-002';Checks=@('BitLocker / WSA-SYS-002');VolumeScope='OS_VOLUME_ONLY'
    Runtime=$PSVersionTable.PSVersion.ToString();ProcessElevated=$processElevated;Profile=$Profile;CriteriaSha256=$snapshot.Sha256;ScoringPolicySha256=$scoring.Sha256
    CollectorSha256=(Get-FileHash -LiteralPath (Join-Path $root 'src/Checks/BitLocker/Test-BitLocker.ps1') -Algorithm SHA256).Hash
    RegistrySha256=(Get-FileHash -LiteralPath $checksPath -Algorithm SHA256).Hash
    ValidatorSha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash
    ReadOnly=$true;PersistPublicHistory=$false;PersistRawEvidence=$false
    Note='Only BitLocker runs in an isolated in-memory registry, on the Windows volume. Actual Windows version/edition is checked after approval; mismatches remain NOT_SCORED. No recovery keys, protectors, TPM, other volumes or remediation. No production permission changes.'
}
$sha=[Security.Cryptography.SHA256]::Create()
try {$hash=[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes((ConvertTo-Json $request -Depth 6 -Compress)))).Replace('-','')}
finally {$sha.Dispose()}
if($PlanOnly){[pscustomobject]@{Request=$request;RequestHash=$hash}|ConvertTo-Json -Depth 8;return}
if($ApprovedRequestHash -cne $hash){throw 'Native BitLocker request changed or lacks explicit approval.'}

# Permiso de validación limitado al proceso; jamás se modifica checks.json.
$script:bitLockerNativeRegistryReader=(Get-Command Get-WinSecCheckRegistry).ScriptBlock
function Get-WinSecCheckRegistry {
    param($ProjectRoot)
    $registry=& $script:bitLockerNativeRegistryReader -ProjectRoot $ProjectRoot
    foreach($check in $registry.Checks) {
        $check.ExecutionEnabled=($check.CheckId -ceq 'WSA-SYS-002')
        if($check.CheckId -ceq 'WSA-SYS-002'){
            $check.ExecutionReady=$true;$check.ImplementationStatus='VALIDATED';$check.RegistryStatus='READY'
        }
    }
    return $registry
}
function Save-WinSecPublicHistory {throw 'Native BitLocker validation prohibits history writes.'}
function Save-WinSecCoordinatedEvidence {throw 'Native BitLocker validation prohibits evidence writes.'}
$coordinator=New-WinSecScanCoordinator -ProjectRoot $root
$coordinator.Registry=[pscustomobject]@{schemaVersion='1.0.0';targets=@($target)}
$coordinator.AssessmentEnabled=$true
if($coordinator.PublicHistoryEnabled -or $coordinator.EvidenceEnabled){throw 'Native validation must not persist results.'}
try {
    $public=Invoke-WinSecCoordinatedScan -Coordinator $coordinator -DeviceId $target.DeviceId -ScanId ('native-blk-'+$OperationId) `
        -ScopeType CONTROL -ScopeKey WSA-SYS-002 -AssessmentProfile $Profile -ConfirmAction {
            param($preview)
            $policies=@($preview.EvaluationProfile.Policies)
            $preview.DeviceId -ceq $request.DeviceId -and $preview.ScopeType -ceq 'CONTROL' -and $preview.ScopeKey -ceq 'WSA-SYS-002' -and
                $preview.ReadOnly -ceq $true -and $preview.Checks.Count -eq 1 -and $preview.Checks[0].CheckId -ceq 'WSA-SYS-002' -and
                $preview.EvaluationProfile.Profile -ceq $request.Profile -and $policies.Count -eq 1 -and
                $policies[0].CheckId -ceq 'WSA-SYS-002' -and $policies[0].CatalogSha256 -ceq $request.CriteriaSha256 -and
                $preview.ConfigurationScoring.PolicySha256 -ceq $request.ScoringPolicySha256 -and
                (Get-FileHash -LiteralPath $checksPath -Algorithm SHA256).Hash -ceq $request.RegistrySha256 -and
                (Get-FileHash -LiteralPath (Join-Path $root 'src/Checks/BitLocker/Test-BitLocker.ps1') -Algorithm SHA256).Hash -ceq $request.CollectorSha256
        }
    $controls=@($public.ControlResults|Where-Object CheckId -CEQ WSA-SYS-002)
    if($controls.Count -ne 1 -or $public.ScopeType -cne 'CONTROL' -or $public.ScopeKey -cne 'WSA-SYS-002') {throw 'Invalid native result scope.'}
    $session=Get-WinSecCoordinatorSession $coordinator $public.DeviceId $public.ScanId
    $internal=@($session.ControlResults|Where-Object CheckId -CEQ WSA-SYS-002)[0]
    $collection=$internal.Evidence
    $complete=($controls[0].ObservedStatus -ceq 'INFORMATIONAL' -and $collection.CollectionSuccessful -is [bool] -and
        $collection.CollectionSuccessful -and $collection.CollectionComplete -is [bool] -and $collection.CollectionComplete)
    # Sólo códigos de incidencias normalizados; nunca mensajes/objetos del proveedor.
    $allowedIssues=@('OS_VOLUME_QUERY_FAILED','OS_VOLUME_IDENTITY_INVALID','BITLOCKER_PROVIDER_UNAVAILABLE','OS_VOLUME_NOT_FOUND',
        'BITLOCKER_VOLUME_IDENTITY_INVALID','GetProtectionStatus_UNAVAILABLE','GetConversionStatus_UNAVAILABLE',
        'GetEncryptionMethod_UNAVAILABLE','GetLockStatus_UNAVAILABLE','ProtectionStatus_UNKNOWN','ConversionStatus_UNKNOWN',
        'EncryptionMethod_UNKNOWN','LockStatus_UNKNOWN','ENCRYPTION_PERCENTAGE_UNKNOWN')
    $failureKinds=@('ACCESS_DENIED','TIMEOUT','NAMESPACE_NOT_FOUND','CLASS_NOT_FOUND','PROPERTY_NOT_FOUND','INVALID_QUERY',
        'PROVIDER_NOT_REGISTERED','PROVIDER_LOAD_FAILED','PROVIDER_INITIALIZATION_FAILED','VOLUME_LOCKED','INVALID_PARAMETER',
        'OPERATION_UNSUPPORTED','QUERY_UNSUPPORTED','METHOD_UNAVAILABLE')
    foreach($prefix in @('OS_VOLUME_QUERY','BITLOCKER_PROVIDER','GetProtectionStatus','GetConversionStatus','GetEncryptionMethod','GetLockStatus')) {
        foreach($kind in $failureKinds){$allowedIssues+=($prefix+'_'+$kind)}
    }
    $issues=@(foreach($issue in @($collection.CollectionIssues)){if($issue -isnot [string] -or $issue -cnotin $allowedIssues){throw 'Invalid native collection diagnostic.'};$issue})
    $diagnostics=@(@(foreach($selection in $session.CriteriaSelections){foreach($item in @($selection.ExcludedCriteria)){
        if($item.Reason -cin @('WINDOWS_SCOPE_MISMATCH','CRITERION_NOT_VERIFIED','DEPENDENCIES_NOT_DECLARED','PREREQUISITES_NOT_CONFIRMED')){$item.Reason}
    }})|Sort-Object -Unique)
    # Recorrido público/histórico y reporte en memoria. No se imprime ni guarda su contenido.
    $record=New-WinSecPublicHistoryRecord $session
    $restored=ConvertFrom-WinSecPublicHistoryRecord (ConvertFrom-WinSecStoredJson (Get-WinSecPublicHistoryJson $record))
    $canonical=ConvertTo-WinSecPublicScanResult $session
    if((Get-WinSecPublicHistoryJson $restored.PublicResult) -cne (Get-WinSecPublicHistoryJson $canonical)){throw 'Native history roundtrip mismatch.'}
    foreach($file in @('src/CLI/Invoke-WinSecCLI.ps1','src/UI/Core/NavigationController.ps1','src/UI/Screens/MainMenu.ps1','src/UI/Screens/Results.ps1',
        'src/UI/Screens/Findings.ps1','src/Services/FrameworkService.ps1','src/Core/FrameworkMappingEngine.ps1','src/Services/ReportService.ps1')){. (Join-Path $root $file)}
    $state=New-WinSecNavigationState;$state.Screen='Findings';$state.FindingsScope='Control';$state.ControlIndex=1;$state.SelectedDeviceId=$target.DeviceId
    $assessment=Get-WinSecResultField $restored.PublicResult 'ConfigurationAssessment'
    $view=Get-WinSecSelectedFindings -NavigationState $state -ControlResults $restored.PublicResult.ControlResults `
        -Findings $restored.PublicResult.Findings -ReviewItems $restored.PublicResult.ReviewItems -ScanId $public.ScanId -ConfigurationAssessment $assessment
    $reportCount=0
    if($view.Rows.Count) {
        $key='{0}:{1}{2}:{3}' -f $public.DeviceId.Length,$public.DeviceId,$public.ScanId.Length,$public.ScanId
        $context=[pscustomobject]@{ProjectRoot=$root;Devices=@($target);PublicScans=@{$key=$restored.PublicResult};ActiveScanByDevice=@{};
            ActiveScanByScope=@{(Get-WinSecCLIScopeKey $public.DeviceId CONTROL WSA-SYS-002)=$public.ScanId}}
        $selection=Get-WinSecCLIFindingsExportSelection $state $context
        foreach($framework in @('cis-controls','nist-csf','mitre-attack')) {
            $report=New-WinSecFindingsMarkdown $selection -FrameworkId $framework
            if($report.DeviceId -cne $target.DeviceId -or $report.ScanId -cne $public.ScanId){throw 'Invalid native report identity.'}
            $reportCount++
        }
    }
    if((Get-FileHash -LiteralPath $checksPath -Algorithm SHA256).Hash -cne $request.RegistrySha256 -or
        (Get-WinSecConfigurationScoringPolicy $root).Sha256 -cne $request.ScoringPolicySha256){throw 'Production policy changed during validation.'}
    [pscustomobject]@{
        OperationId=$OperationId;Runtime=$PSVersionTable.PSVersion.ToString();ProcessElevated=$processElevated;ExecutionStatus=$public.ExecutionStatus
        CollectionValidated=$complete;ObservedStatus=$controls[0].ObservedStatus;CollectionIssues=$issues;ApplicabilityDiagnostics=$diagnostics
        ConfigurationScore=if($null -ne $assessment){$assessment.Controls[0].Value}else{$null}
        ConfigurationStatus=if($null -ne $assessment){$assessment.Controls[0].Status}else{'NOT_SCORED'}
        CriterionCount=$view.CheckRows.Count;InformationalObservations=$view.ReviewItems.Count;PublicFindings=@($public.Findings).Count
        PublicHistoryRoundtripValidated=$true;InMemoryReports=$reportCount
        RawEvidencePersisted=$false;PublicHistoryPersisted=$false;WindowsChanges=$false;ProductionPermissionsChanged=$false
    }|ConvertTo-Json -Depth 5
} catch {throw 'Native BitLocker validation failed. No successful validation is confirmed; production permissions remain unchanged.'}
