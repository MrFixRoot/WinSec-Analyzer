# PlanOnly identifica el equipo y prepara consentimiento; no consulta Windows Update.
# Ejecutar exige el hash aprobado para esta operacion, perfil, runtime y dia UTC.
# Sin busqueda de actualizaciones, remediacion ni persistencia de resultados.
[CmdletBinding()]
param(
    [switch]$PlanOnly,
    [string]$OperationId='',
    [string]$ApprovedRequestHash='',
    [string]$Profile=''
)
$ErrorActionPreference='Stop'
if([string]::IsNullOrWhiteSpace($OperationId)) {
    if(-not $PlanOnly){throw 'Prepare and explicitly approve a native Windows Update request first.'}
    $OperationId=[guid]::NewGuid().ToString('N')
}
if($OperationId -cnotmatch '\A[a-f0-9]{32}\z' -or
    $Profile -cnotmatch '\AWSA-W11-2[1-6]H[12]-[A-Z][A-Z0-9-]{0,39}-DEF-BASE\z') {
    throw 'A valid operation and explicit Windows profile are required.'
}
if(($PlanOnly -and $ApprovedRequestHash) -or
    (-not $PlanOnly -and $ApprovedRequestHash -cnotmatch '\A[A-F0-9]{64}\z')) {
    throw 'Explicit approval of one prepared request is required.'
}
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'tests/Fixtures/WindowsUpdateNativeValidationSupport.ps1')
. (Join-Path $root 'tests/Fixtures/FrameworkNativeValidationSupport.ps1')
$lease=Open-WinSecWindowsUpdateValidationSnapshot $root
try {
    # Definitions only. No startup, inventory/history import or UI input loop.
    foreach($file in @('src/Core/ScanCoordinator.ps1','src/CLI/Invoke-WinSecCLI.ps1',
        'src/UI/Core/NavigationController.ps1','src/UI/Screens/MainMenu.ps1','src/UI/Screens/Results.ps1',
        'src/UI/Screens/Findings.ps1','src/Services/FrameworkService.ps1',
        'src/Core/FrameworkMappingEngine.ps1','src/Services/ReportService.ps1')){. (Join-Path $root $file)}
    $target=New-WinSecLocalTarget
    # DEF-BASE is the existing Windows context ID, not a request to run Defender.
    $snapshot=Get-WinSecAssessmentCatalog $root WSA-SYS-003 -Profile $Profile
    $rules=Get-WinSecFrameworkAnalysisCatalog $root nist-csf
    $reference=(Get-WinSecWindowsUpdateReferenceCatalog $root).Catalog
    $now=Get-WinSecWindowsUpdateNativeUtcNow
    $asOf=([datetime]$reference.AsOfUTC).ToUniversalTime()
    $until=([datetime]$reference.ValidUntilUTC).ToUniversalTime()
    $request=[pscustomobject][ordered]@{
        Operation='VALIDATE_WINDOWS_UPDATE_READ_ONLY';OperationId=$OperationId
        DeviceId=$target.DeviceId;Hostname=$target.Hostname
        ScopeType='CONTROL';ScopeKey='WSA-SYS-003';Checks=@('Windows Update / WSA-SYS-003')
        Runtime=$PSVersionTable.PSVersion.ToString();Is64BitProcess=[Environment]::Is64BitProcess
        ProcessElevated=(Get-WinSecWindowsUpdateNativeElevation);Profile=$Profile
        ApprovalDateUTC=$now.ToString('yyyy-MM-dd')
        InstallationSha256=(Get-WinSecWindowsUpdateValidationHash $root)
        CriteriaSha256=$snapshot.Sha256;AssessmentMode='FRAMEWORK_REVIEW';FrameworkRulesSha256=$rules.RuleHash
        ReferenceVersion=$reference.CatalogVersion;ReferenceAsOfUTC=$asOf.ToString('o');ReferenceValidUntilUTC=$until.ToString('o')
        DependencyManifestSha256=$lease.Sha256;DependencyCount=$lease.Files.Count
        DependencyCoverage=@('src/**/*.ps1','config/**/*.json','native validator and support script')
        ReadOnly=$true;UpdateSearchPerformed=$false;PersistPublicHistory=$false;PersistRawEvidence=$false;PersistReports=$false
        Note='Only Windows Update runs in an isolated in-memory registry. Reads local OS/service metadata, allowlisted DWORD policies, build/UBR, WUA reboot state and NamedPolicy getters. No search, detection, download, installation, reboot, policy changes, other checks or production permission changes. In-memory framework Findings, public history roundtrip and Markdown for three frameworks, without ratings. Unknown or mismatched evidence remains an explicit gap; patch coverage is the reviewed OS cumulative baseline only.'
    }
    $hash=Get-WinSecWindowsUpdateValidationHash (ConvertTo-Json $request -Depth 6 -Compress)
    Assert-WinSecWindowsUpdateValidationSnapshot $root $lease
    if($PlanOnly){[pscustomobject]@{Request=$request;RequestHash=$hash}|ConvertTo-Json -Depth 8;return}
    if($hash -cne $ApprovedRequestHash){throw 'Windows Update request changed or was not approved.'}
    if($now -lt $asOf -or $now -ge $until){throw 'Reviewed Windows Update references are not current; prepare a reviewed request.'}

    # Scope-local validation permission only; production checks.json is read-locked.
    $registryReader=(Get-Command Get-WinSecCheckRegistry -CommandType Function).ScriptBlock
    function Get-WinSecCheckRegistry {
        param($ProjectRoot)
        $registry=& $registryReader -ProjectRoot $ProjectRoot
        foreach($check in $registry.Checks) {
            $check.ExecutionEnabled=($check.CheckId -ceq 'WSA-SYS-003')
            if($check.CheckId -ceq 'WSA-SYS-003') {
                $check.ExecutionReady=$true;$check.ImplementationStatus='VALIDATED';$check.RegistryStatus='READY'
            }
        }
        return $registry
    }
    function Save-WinSecPublicHistory {throw 'Native validation prohibits history writes.'}
    function Save-WinSecCoordinatedEvidence {throw 'Native validation prohibits evidence writes.'}
    function Save-WinSecEvidence {throw 'Native validation prohibits evidence writes.'}
    function Write-WinSecMarkdownArtifact {throw 'Native validation prohibits report writes.'}
    $coordinator=New-WinSecScanCoordinator -ProjectRoot $root
    $coordinator.Registry=[pscustomobject]@{schemaVersion='1.0.0';targets=@($target)}
    $coordinator.AssessmentEnabled=$true
    if($coordinator.PublicHistoryEnabled -or $coordinator.AutomaticEvidencePersistence -or $coordinator.RequireDeviceInventory) {
        throw 'Native validation must not use persistent data.'
    }
    $public=Invoke-WinSecCoordinatedScan -Coordinator $coordinator -DeviceId $target.DeviceId -ScanId ('native-wup-'+$OperationId) `
        -ScopeType CONTROL -ScopeKey WSA-SYS-003 -AssessmentProfile $Profile -ConfirmAction {
            param($preview)
            Assert-WinSecWindowsUpdateValidationSnapshot $root $lease
            $confirmationTime=Get-WinSecWindowsUpdateNativeUtcNow
            $policies=@($preview.EvaluationProfile.Policies)
            return ($confirmationTime.ToString('yyyy-MM-dd') -ceq $request.ApprovalDateUTC -and $confirmationTime -ge $asOf -and $confirmationTime -lt $until -and
                $preview.DeviceId -ceq $request.DeviceId -and $preview.ScopeType -ceq 'CONTROL' -and $preview.ScopeKey -ceq 'WSA-SYS-003' -and
                $preview.ReadOnly -ceq $true -and $preview.Checks.Count -eq 1 -and $preview.Checks[0].CheckId -ceq 'WSA-SYS-003' -and
                $preview.EvaluationProfile.Profile -ceq $request.Profile -and $policies.Count -eq 1 -and
                $policies[0].CheckId -ceq 'WSA-SYS-003' -and $policies[0].CatalogSha256 -ceq $request.CriteriaSha256 -and
                $preview.AssessmentMode -ceq $request.AssessmentMode -and $null -eq $preview.ConfigurationScoring -and
                (Get-WinSecFrameworkAnalysisCatalog $root nist-csf).RuleHash -ceq $request.FrameworkRulesSha256)
        }
    if($null -eq $public){throw 'Validation cancelled; no completed operation.'}
    $executed=@($public.ControlResults|Where-Object Status -CNE NOT_SELECTED)
    if($executed.Count -ne 1 -or $executed[0].CheckId -cne 'WSA-SYS-003' -or $public.ScopeType -cne 'CONTROL' -or
        $public.ScopeKey -cne 'WSA-SYS-003' -or $public.DeviceId -cne $target.DeviceId -or $public.ExecutionStatus -cne 'COMPLETED') {
        throw 'Unexpected native validation scope.'
    }
    $session=Get-WinSecCoordinatorSession $coordinator $public.DeviceId $public.ScanId
    $internal=@($session.ControlResults|Where-Object CheckId -CEQ WSA-SYS-003)[0]
    $issues=@(Get-WinSecWindowsUpdateNativeIssues $internal.Evidence)
    $complete=($executed[0].ObservedStatus -ceq 'INFORMATIONAL' -and
        $internal.Evidence.CollectionSuccessful -ceq $true -and $internal.Evidence.CollectionComplete -ceq $true -and $issues.Count -eq 0)
    $record=New-WinSecPublicHistoryRecord $session
    $restored=ConvertFrom-WinSecPublicHistoryRecord (ConvertFrom-WinSecStoredJson (Get-WinSecPublicHistoryJson $record))
    if((Get-WinSecPublicHistoryJson $restored.PublicResult) -cne (Get-WinSecPublicHistoryJson (ConvertTo-WinSecPublicScanResult $session))) {
        throw 'Native public history roundtrip mismatch.'
    }
    $probe=Test-WinSecNativeFrameworkViews $root $session WSA-SYS-003 $target.Hostname
    Assert-WinSecWindowsUpdateValidationSnapshot $root $lease
    $diagnostics=@(foreach($review in @($restored.PublicResult.ReviewItems)) {
        $setting=Get-WinSecResultField $review 'WindowsUpdateSetting'
        if($null -ne $setting) {
            # Already validated by the public model: closed codes, no observed values.
            [pscustomobject]@{CriterionId=$setting.CriterionId;State=$setting.State;Reason=$setting.Reason}
        }
    })
    $applicability=@(foreach($selectionRecord in $session.CriteriaSelections) {
        foreach($excluded in @($selectionRecord.ExcludedCriteria)) {
            if($excluded.Reason -cin @('WINDOWS_SCOPE_MISMATCH','CRITERION_NOT_VERIFIED','DEPENDENCIES_NOT_DECLARED','PREREQUISITES_NOT_CONFIRMED')){$excluded.Reason}
        }
    })
    [pscustomobject]@{
        OperationId=$OperationId;Runtime=$request.Runtime;ProcessElevated=$request.ProcessElevated;ExecutionStatus=$public.ExecutionStatus
        CollectionValidated=$complete;ObservedStatus=$executed[0].ObservedStatus;CollectionIssues=$issues
        CriterionDiagnostics=$diagnostics;ApplicabilityDiagnostics=@($applicability|Sort-Object -Unique)
        AssessmentMode='FRAMEWORK_REVIEW';ReadingCount=$probe.ReadingCount
        CriterionCount=$probe.CriterionCount;PublicFindings=@($public.Findings).Count
        PublicHistoryRoundtripValidated=$probe.PublicHistoryRoundtripValidated;InMemoryMarkdownReports=$probe.InMemoryReports
        RawEvidencePersisted=$false;PublicHistoryPersisted=$false;ReportsPersisted=$false
        UpdateSearchPerformed=$false;WindowsChanges=$false;ProductionPermissionsChanged=$false
    }|ConvertTo-Json -Depth 5
} catch {throw 'Windows Update native validation failed or was rejected. No successful validation is confirmed; production permissions remain unchanged.'}
finally {foreach($stream in $lease.Streams){$stream.Dispose()}}
