# PlanOnly reads identity and code metadata, never Rdp configuration.
# Execution requires approval of this exact request, runtime and UTC date.
[CmdletBinding()]
param([switch]$PlanOnly,[string]$OperationId='',[string]$ApprovedRequestHash='',
    [string]$Profile='WSA-W11-23H2-PRO-DEF-BASE')
$ErrorActionPreference='Stop'
if(-not $OperationId){if(-not $PlanOnly){throw 'Prepare and approve a Rdp request first.'};$OperationId=[guid]::NewGuid().ToString('N')}
if($OperationId -cnotmatch '\A[a-f0-9]{32}\z' -or
    ($PlanOnly -and $ApprovedRequestHash) -or (-not $PlanOnly -and $ApprovedRequestHash -cnotmatch '\A[A-F0-9]{64}\z')){throw 'Invalid Rdp approval.'}
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'tests/Fixtures/RdpNativeValidationSupport.ps1')
. (Join-Path $root 'tests/Fixtures/FrameworkNativeValidationSupport.ps1')
$lease=Open-WinSecRdpValidationSnapshot $root
try {
    . (Join-Path $root 'src/Core/ScanCoordinator.ps1')
    $target=New-WinSecLocalTarget
    $profilePlan=Get-WinSecAssessmentProfilePlan $root @('WSA-NET-003') $Profile
    $request=[pscustomobject][ordered]@{
        Operation='VALIDATE_RDP_READ_ONLY';OperationId=$OperationId;DeviceId=$target.DeviceId;Hostname=$target.Hostname
        ScopeType='CONTROL';ScopeKey='WSA-NET-003';Checks=@('Remote Desktop / WSA-NET-003')
        Runtime=$PSVersionTable.PSVersion.ToString();Is64BitProcess=[Environment]::Is64BitProcess
        ProcessElevated=(Get-WinSecRdpNativeElevation);ApprovalDateUTC=([datetime]::UtcNow.ToString('yyyy-MM-dd'))
        Profile=$Profile;ProfileSha256=$profilePlan.Preview.Policies[0].CatalogSha256
        DependencyManifestSha256=$lease.Sha256;DependencyCount=$lease.Files.Count
        ReadOnly=$true;PersistPublicHistory=$false;PersistRawEvidence=$false;PersistReports=$false
        Note='Only Remote Desktop runs in an isolated in-memory registry. Reads local Windows metadata, RDP services, reviewed TerminalServices class metadata and available reviewed configuration fields for all returned listeners, plus fixed machine registry policies. Scan completion requires successful queries and required readings; informational unknowns remain visible as limited coverage. Documented retired DWM fields are not applicable on reviewed observed Windows 11 builds. Windows Home host providers are not applicable. No users, sessions, credentials, saved connections, certificates, security descriptors, network connections, port probes or service/policy changes. Custom listener names are hashed. Technical Markdown, immutable public-history roundtrip and three framework reports are checked only in memory. No production permissions change.'
    }
    $hash=Get-WinSecRdpValidationHash (ConvertTo-Json $request -Depth 6 -Compress)
    Assert-WinSecRdpValidationSnapshot $root $lease
    if($PlanOnly){[pscustomobject]@{Request=$request;RequestHash=$hash}|ConvertTo-Json -Depth 8;return}
    if($hash -cne $ApprovedRequestHash){throw 'Rdp request changed or was not approved.'}
    $reader=(Get-Command Get-WinSecCheckRegistry -CommandType Function).ScriptBlock
    function Get-WinSecCheckRegistry {
        param($ProjectRoot)
        $registry=& $reader -ProjectRoot $ProjectRoot
        foreach($check in $registry.Checks) {
            $check.ExecutionEnabled=($check.CheckId -ceq 'WSA-NET-003')
            if($check.CheckId -ceq 'WSA-NET-003'){$check.ExecutionReady=$true;$check.ImplementationStatus='VALIDATED';$check.RegistryStatus='READY'}
        }
        return $registry
    }
    function Save-WinSecPublicHistory {throw 'Native Rdp validation prohibits writes.'}
    function Save-WinSecEvidence {throw 'Native Rdp validation prohibits writes.'}
    function Save-WinSecTechnicalReports {throw 'Native Rdp validation prohibits writes.'}
    function Write-WinSecTechnicalArtifact {throw 'Native Rdp validation prohibits writes.'}
    function Export-WinSecFrameworkAnalysis {throw 'Native Rdp validation prohibits writes.'}
    $c=New-WinSecScanCoordinator -ProjectRoot $root
    $c.Registry=[pscustomobject]@{schemaVersion='1.0.0';targets=@($target)};$c.AssessmentEnabled=$true
    if($c.PublicHistoryEnabled -or $c.AutomaticEvidencePersistence -or $c.TechnicalReportsEnabled -or $c.RequireDeviceInventory){throw 'Persistent native validation is prohibited.'}
    $script:rdpNativeEvents=New-Object 'Collections.Generic.List[object]'
    $public=Invoke-WinSecCoordinatedScan -Coordinator $c -DeviceId $target.DeviceId -ScanId ('native-rdp-'+$OperationId) `
        -ScopeType CONTROL -ScopeKey WSA-NET-003 -AssessmentProfile $Profile -ProgressCallback {param($event);$script:rdpNativeEvents.Add($event)} -ConfirmAction {
            param($preview)
            Assert-WinSecRdpValidationSnapshot $root $lease
            return ($request.ApprovalDateUTC -ceq [datetime]::UtcNow.ToString('yyyy-MM-dd') -and $preview.DeviceId -ceq $request.DeviceId -and
                $preview.ScopeType -ceq 'CONTROL' -and $preview.ScopeKey -ceq 'WSA-NET-003' -and $preview.ReadOnly -ceq $true -and
                $preview.Checks.Count -eq 1 -and $preview.Checks[0].CheckId -ceq 'WSA-NET-003' -and
                $preview.EvaluationProfile.Policies.Count -eq 1 -and $preview.EvaluationProfile.Profile -ceq $request.Profile -and
                $preview.EvaluationProfile.Policies[0].CatalogSha256 -ceq $request.ProfileSha256)
        }
    if($null -eq $public){throw 'Native Rdp validation was not executed.'}
    Assert-WinSecRdpValidationSnapshot $root $lease
    $session=$c.Sessions[(Get-WinSecScanSessionKey $target.DeviceId $public.ScanId)].Session
    $control=@($session.ControlResults|Where-Object CheckId -CEQ WSA-NET-003)[0]
    if(@($session.ControlResults|Where-Object {$_.Status -cne 'NOT_SELECTED' -and $_.CheckId -cne 'WSA-NET-003'}).Count){throw 'Unexpected executed control.'}
    $e=$control.Evidence
    $issues=@(Get-WinSecRdpNativeDiagnostics $control)
    $technical=New-WinSecTechnicalReport $session WSA-NET-003 $target.Hostname $target.Hostname
    $body=ConvertTo-WinSecTechnicalMarkdown $technical
    $meta=[ordered]@{SchemaVersion='2.0.0';DeviceId=$technical.DeviceId;ScanId=$technical.ScanId;CheckId=$technical.CheckId;
        ScopeType=$technical.ScopeType;ScopeKey=$technical.ScopeKey;ContentSha256=(Get-WinSecReportTextHash $body)}
    $artifact="<!-- WinSec technical report`n"+(ConvertTo-Json $meta -Compress)+"`n-->`n"+$body
    $null=ConvertFrom-WinSecTechnicalMarkdownArtifact $artifact $target.DeviceId
    $views=Test-WinSecNativeFrameworkViews $root $session WSA-NET-003 $target.Hostname
    $unavailable=@(foreach($row in @($technical.Rows|Where-Object {$_.SettingId -clike 'Inventory.*' -and $_.State -ceq 'OBSERVED'})){
        $batch=ConvertTo-WinSecRdpInventory $row.Value
        $excluded=if($null -ne $batch.PSObject.Properties['NotApplicableFields']){@($batch.NotApplicableFields)}else{@()}
        foreach($item in $batch.Items){foreach($field in $item.Values.PSObject.Properties){if($null -eq $field.Value -and $field.Name -cnotin $excluded){$batch.Class+'.'+$field.Name}}}
    })
    [pscustomobject]@{OperationId=$OperationId;Runtime=$PSVersionTable.PSVersion.ToString();ExecutionStatus=$session.ExecutionStatus;
        CollectionValidated=($null -ne $e -and $e.CollectionSuccessful -ceq $true);
        CollectionSuccessful=($e.CollectionSuccessful -ceq $true);CollectionComplete=($e.CollectionComplete -ceq $true);CollectionIssues=$issues;
        ObservedStatus=$control.ObservedStatus;ActualBuild=$e.Platform.BuildNumber;HostSupport=$e.HostSupport;
        UnknownFieldCount=$e.UnknownFieldCount;UnavailableFields=@($unavailable|Sort-Object -Unique);
        CoverageComplete=$e.CoverageComplete;RequiredUnknownFieldCount=$e.RequiredUnknownFieldCount;
        InformationalUnknownFieldCount=$e.InformationalUnknownFieldCount;NotApplicableFieldCount=$e.NotApplicableFieldCount;
        FieldDiagnostics=@(Get-WinSecRdpNativeDetailDiagnostics $control Field);ProviderDiagnostics=@(Get-WinSecRdpNativeDetailDiagnostics $control Provider);
        TechnicalMarkdownValidated=$true;PublicHistoryRoundtripValidated=$views.PublicHistoryRoundtripValidated;InMemoryFrameworkReports=$views.InMemoryReports;
        ProgressEvents=$script:rdpNativeEvents.Count;PublicHistoryPersisted=$false;RawEvidencePersisted=$false;ReportsPersisted=$false;
        WindowsChanges=$false;ProductionPermissionsChanged=$false}|ConvertTo-Json -Depth 5
} finally {foreach($stream in $lease.Streams){$stream.Dispose()}}
