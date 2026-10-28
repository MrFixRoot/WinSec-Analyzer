# PlanOnly reads identity and code metadata, never Smb configuration.
# Execution requires approval of this exact request, runtime and UTC date.
[CmdletBinding()]
param([switch]$PlanOnly,[string]$OperationId='',[string]$ApprovedRequestHash='',
    [string]$Profile='WSA-W11-23H2-PRO-DEF-BASE')
$ErrorActionPreference='Stop'
if(-not $OperationId){if(-not $PlanOnly){throw 'Prepare and approve a Smb request first.'};$OperationId=[guid]::NewGuid().ToString('N')}
if($OperationId -cnotmatch '\A[a-f0-9]{32}\z' -or
    ($PlanOnly -and $ApprovedRequestHash) -or (-not $PlanOnly -and $ApprovedRequestHash -cnotmatch '\A[A-F0-9]{64}\z')){throw 'Invalid Smb approval.'}
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'tests/Fixtures/SmbNativeValidationSupport.ps1')
. (Join-Path $root 'tests/Fixtures/FrameworkNativeValidationSupport.ps1')
$lease=Open-WinSecSmbValidationSnapshot $root
try {
    . (Join-Path $root 'src/Core/ScanCoordinator.ps1')
    $target=New-WinSecLocalTarget
    $profilePlan=Get-WinSecAssessmentProfilePlan $root @('WSA-NET-002') $Profile
    $request=[pscustomobject][ordered]@{
        Operation='VALIDATE_SMBV1_READ_ONLY';OperationId=$OperationId;DeviceId=$target.DeviceId;Hostname=$target.Hostname
        ScopeType='CONTROL';ScopeKey='WSA-NET-002';Checks=@('SMBv1 / WSA-NET-002')
        Runtime=$PSVersionTable.PSVersion.ToString();Is64BitProcess=[Environment]::Is64BitProcess
        ProcessElevated=(Get-WinSecSmbNativeElevation);ApprovalDateUTC=([datetime]::UtcNow.ToString('yyyy-MM-dd'))
        Profile=$Profile;ProfileSha256=$profilePlan.Preview.Policies[0].CatalogSha256
        DependencyManifestSha256=$lease.Sha256;DependencyCount=$lease.Files.Count
        ReadOnly=$true;PersistPublicHistory=$false;PersistRawEvidence=$false;PersistReports=$false
        Note='Only SMBv1 runs in an isolated in-memory registry. Reads local Windows metadata, reviewed SMB server/client scalar configuration, SMB1 optional-feature states, Lanman services and eight fixed registry values. No shares, sessions, peer names, files, credentials, connections, port probes, remote sessions, DISM or service/policy changes. Technical Markdown, immutable public-history roundtrip and three framework reports are checked only in memory. No production permissions change.'
    }
    $hash=Get-WinSecSmbValidationHash (ConvertTo-Json $request -Depth 6 -Compress)
    Assert-WinSecSmbValidationSnapshot $root $lease
    if($PlanOnly){[pscustomobject]@{Request=$request;RequestHash=$hash}|ConvertTo-Json -Depth 8;return}
    if($hash -cne $ApprovedRequestHash){throw 'Smb request changed or was not approved.'}
    $reader=(Get-Command Get-WinSecCheckRegistry -CommandType Function).ScriptBlock
    function Get-WinSecCheckRegistry {
        param($ProjectRoot)
        $registry=& $reader -ProjectRoot $ProjectRoot
        foreach($check in $registry.Checks) {
            $check.ExecutionEnabled=($check.CheckId -ceq 'WSA-NET-002')
            if($check.CheckId -ceq 'WSA-NET-002'){$check.ExecutionReady=$true;$check.ImplementationStatus='VALIDATED';$check.RegistryStatus='READY'}
        }
        return $registry
    }
    function Save-WinSecPublicHistory {throw 'Native Smb validation prohibits writes.'}
    function Save-WinSecEvidence {throw 'Native Smb validation prohibits writes.'}
    function Save-WinSecTechnicalReports {throw 'Native Smb validation prohibits writes.'}
    function Write-WinSecTechnicalArtifact {throw 'Native Smb validation prohibits writes.'}
    function Export-WinSecFrameworkAnalysis {throw 'Native Smb validation prohibits writes.'}
    $c=New-WinSecScanCoordinator -ProjectRoot $root
    $c.Registry=[pscustomobject]@{schemaVersion='1.0.0';targets=@($target)};$c.AssessmentEnabled=$true
    if($c.PublicHistoryEnabled -or $c.AutomaticEvidencePersistence -or $c.TechnicalReportsEnabled -or $c.RequireDeviceInventory){throw 'Persistent native validation is prohibited.'}
    $script:smbNativeEvents=New-Object 'Collections.Generic.List[object]'
    $public=Invoke-WinSecCoordinatedScan -Coordinator $c -DeviceId $target.DeviceId -ScanId ('native-smb-'+$OperationId) `
        -ScopeType CONTROL -ScopeKey WSA-NET-002 -AssessmentProfile $Profile -ProgressCallback {param($event);$script:smbNativeEvents.Add($event)} -ConfirmAction {
            param($preview)
            Assert-WinSecSmbValidationSnapshot $root $lease
            return ($request.ApprovalDateUTC -ceq [datetime]::UtcNow.ToString('yyyy-MM-dd') -and $preview.DeviceId -ceq $request.DeviceId -and
                $preview.ScopeType -ceq 'CONTROL' -and $preview.ScopeKey -ceq 'WSA-NET-002' -and $preview.ReadOnly -ceq $true -and
                $preview.Checks.Count -eq 1 -and $preview.Checks[0].CheckId -ceq 'WSA-NET-002' -and
                $preview.EvaluationProfile.Policies.Count -eq 1 -and $preview.EvaluationProfile.Profile -ceq $request.Profile -and
                $preview.EvaluationProfile.Policies[0].CatalogSha256 -ceq $request.ProfileSha256)
        }
    if($null -eq $public){throw 'Native Smb validation was not executed.'}
    Assert-WinSecSmbValidationSnapshot $root $lease
    $session=$c.Sessions[(Get-WinSecScanSessionKey $target.DeviceId $public.ScanId)].Session
    $control=@($session.ControlResults|Where-Object CheckId -CEQ WSA-NET-002)[0]
    if(@($session.ControlResults|Where-Object {$_.Status -cne 'NOT_SELECTED' -and $_.CheckId -cne 'WSA-NET-002'}).Count){throw 'Unexpected executed control.'}
    $e=$control.Evidence
    $issues=@(Get-WinSecSmbNativeDiagnostics $control)
    $technical=New-WinSecTechnicalReport $session WSA-NET-002 $target.Hostname $target.Hostname
    $body=ConvertTo-WinSecTechnicalMarkdown $technical
    $meta=[ordered]@{SchemaVersion='2.0.0';DeviceId=$technical.DeviceId;ScanId=$technical.ScanId;CheckId=$technical.CheckId;
        ScopeType=$technical.ScopeType;ScopeKey=$technical.ScopeKey;ContentSha256=(Get-WinSecReportTextHash $body)}
    $artifact="<!-- WinSec technical report`n"+(ConvertTo-Json $meta -Compress)+"`n-->`n"+$body
    $null=ConvertFrom-WinSecTechnicalMarkdownArtifact $artifact $target.DeviceId
    $views=Test-WinSecNativeFrameworkViews $root $session WSA-NET-002 $target.Hostname
    [pscustomobject]@{OperationId=$OperationId;Runtime=$PSVersionTable.PSVersion.ToString();ExecutionStatus=$session.ExecutionStatus;
        CollectionValidated=($null -ne $e -and $e.CollectionSuccessful -ceq $true);
        CollectionSuccessful=($e.CollectionSuccessful -ceq $true);CollectionComplete=($e.CollectionComplete -ceq $true);CollectionIssues=$issues;
        ObservedStatus=$control.ObservedStatus;ActualBuild=$e.Platform.BuildNumber;
        TechnicalMarkdownValidated=$true;PublicHistoryRoundtripValidated=$views.PublicHistoryRoundtripValidated;InMemoryFrameworkReports=$views.InMemoryReports;
        ProgressEvents=$script:smbNativeEvents.Count;PublicHistoryPersisted=$false;RawEvidencePersisted=$false;ReportsPersisted=$false;
        WindowsChanges=$false;ProductionPermissionsChanged=$false}|ConvertTo-Json -Depth 5
} finally {foreach($stream in $lease.Streams){$stream.Dispose()}}
