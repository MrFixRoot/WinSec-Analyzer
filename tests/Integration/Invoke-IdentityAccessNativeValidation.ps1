# One explicitly approved IAM control, one runtime, one local operation. No result persistence.
[CmdletBinding()]
param([switch]$PlanOnly,[ValidateSet('WSA-IAM-001','WSA-IAM-002','WSA-IAM-003')][string]$CheckId='WSA-IAM-001',
    [string]$OperationId='',[string]$ApprovedRequestHash='',[string]$Profile='WSA-W11-23H2-PRO-DEF-BASE')
$ErrorActionPreference='Stop'
if(-not $OperationId){if(-not $PlanOnly){throw 'Prepare and approve an IdentityAccess request first.'};$OperationId=[guid]::NewGuid().ToString('N')}
if($OperationId -cnotmatch '\A[a-f0-9]{32}\z' -or ($PlanOnly -and $ApprovedRequestHash) -or
    (-not $PlanOnly -and $ApprovedRequestHash -cnotmatch '\A[A-F0-9]{64}\z')){throw 'Invalid IdentityAccess approval.'}
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'tests/Fixtures/IdentityAccessNativeValidationSupport.ps1')
. (Join-Path $root 'tests/Fixtures/FrameworkNativeValidationSupport.ps1')
$lease=Open-WinSecIdentityAccessValidationSnapshot $root
try {
    . (Join-Path $root 'src/Core/ScanCoordinator.ps1')
    $target=New-WinSecLocalTarget;$plan=Get-WinSecAssessmentProfilePlan $root @($CheckId) $Profile
    $request=New-WinSecIdentityAccessValidationRequest $target $CheckId $OperationId $PSVersionTable.PSVersion.ToString() `
        ([Environment]::Is64BitProcess) (Get-WinSecIdentityAccessNativeElevation) ([datetime]::UtcNow.ToString('yyyy-MM-dd')) $plan $lease
    $hash=Get-WinSecIdentityAccessValidationHash (ConvertTo-Json $request -Depth 6 -Compress)
    Assert-WinSecIdentityAccessValidationSnapshot $root $lease
    if($PlanOnly){[pscustomobject]@{Request=$request;RequestHash=$hash}|ConvertTo-Json -Depth 8;return}
    if($hash -cne $ApprovedRequestHash){throw 'IdentityAccess request changed or was not approved.'}
    $reader=(Get-Command Get-WinSecCheckRegistry -CommandType Function).ScriptBlock
    function Get-WinSecCheckRegistry {
        param($ProjectRoot)
        $registry=& $reader $ProjectRoot
        foreach($check in $registry.Checks){$check.ExecutionEnabled=($check.CheckId -ceq $CheckId);$check.ExecutionReady=$check.ExecutionEnabled
            if($check.ExecutionEnabled){$check.ImplementationStatus='VALIDATED';$check.RegistryStatus='READY'}};return $registry
    }
    function Save-WinSecPublicHistory {throw 'Native IAM validation prohibits persistence.'}
    function Save-WinSecEvidence {throw 'Native IAM validation prohibits persistence.'}
    function Save-WinSecTechnicalReports {throw 'Native IAM validation prohibits persistence.'}
    function Write-WinSecTechnicalArtifact {throw 'Native IAM validation prohibits persistence.'}
    function Export-WinSecFrameworkAnalysis {throw 'Native IAM validation prohibits persistence.'}
    $c=New-WinSecScanCoordinator $root;$c.Registry=[pscustomobject]@{schemaVersion='1.0.0';targets=@($target)};$c.AssessmentEnabled=$true
    if($c.PublicHistoryEnabled -or $c.AutomaticEvidencePersistence -or $c.TechnicalReportsEnabled -or $c.RequireDeviceInventory){throw 'Persistent native validation is prohibited.'}
    $script:identityNativeEvents=New-Object 'Collections.Generic.List[object]'
    $public=Invoke-WinSecCoordinatedScan $c -DeviceId $target.DeviceId -ScanId ('native-identity-'+$OperationId) -ScopeType CONTROL -ScopeKey $CheckId -AssessmentProfile $Profile `
        -ProgressCallback {param($event);$script:identityNativeEvents.Add($event)} -ConfirmAction {
            param($preview)
            Assert-WinSecIdentityAccessValidationSnapshot $root $lease
            return ($request.ApprovalDateUTC -ceq [datetime]::UtcNow.ToString('yyyy-MM-dd') -and $preview.DeviceId -ceq $request.DeviceId -and
                $preview.ScopeType -ceq 'CONTROL' -and $preview.ScopeKey -ceq $CheckId -and $preview.ReadOnly -ceq $true -and
                $preview.Checks.Count -eq 1 -and $preview.Checks[0].CheckId -ceq $CheckId -and $preview.EvaluationProfile.Profile -ceq $request.Profile -and
                $preview.EvaluationProfile.Policies.Count -eq 1 -and $preview.EvaluationProfile.Policies[0].CatalogSha256 -ceq $request.ProfileSha256)
        }
    if($null -eq $public){throw 'Native IAM validation was not executed.'}
    Assert-WinSecIdentityAccessValidationSnapshot $root $lease
    $session=$c.Sessions[(Get-WinSecScanSessionKey $target.DeviceId $public.ScanId)].Session
    if(@($session.ControlResults|Where-Object {$_.Status -cne 'NOT_SELECTED' -and $_.CheckId -cne $CheckId}).Count){throw 'Unexpected executed control.'}
    $control=@($session.ControlResults|Where-Object CheckId -CEQ $CheckId)[0];$e=$control.Evidence
    $technical=New-WinSecTechnicalReport $session $CheckId $target.Hostname $target.Hostname
    $body=ConvertTo-WinSecTechnicalMarkdown $technical
    $meta=[ordered]@{SchemaVersion='2.0.0';DeviceId=$technical.DeviceId;ScanId=$technical.ScanId;CheckId=$CheckId;
        ScopeType=$technical.ScopeType;ScopeKey=$technical.ScopeKey;ContentSha256=(Get-WinSecReportTextHash $body)}
    $artifact="<!-- WinSec technical report`n"+(ConvertTo-Json $meta -Compress)+"`n-->`n"+$body
    $null=ConvertFrom-WinSecTechnicalMarkdownArtifact $artifact $target.DeviceId
    $views=Test-WinSecNativeFrameworkViews $root $session $CheckId $target.Hostname
    [pscustomobject]@{OperationId=$OperationId;CheckId=$CheckId;Runtime=$PSVersionTable.PSVersion.ToString();ExecutionStatus=$session.ExecutionStatus;
        CollectionValidated=($null -ne $e -and $e.CollectionSuccessful -ceq $true);CollectionSuccessful=$e.CollectionSuccessful;CollectionComplete=$e.CollectionComplete;
        CollectionIssues=@($e.CollectionIssues);ObservedStatus=$control.ObservedStatus;ActualBuild=$e.Platform.BuildNumber;
        CoverageComplete=$e.CoverageComplete;UnknownFieldCount=$e.UnknownFieldCount;TechnicalMarkdownValidated=$true;
        PublicHistoryRoundtripValidated=$views.PublicHistoryRoundtripValidated;InMemoryFrameworkReports=$views.InMemoryReports;ProgressEvents=$script:identityNativeEvents.Count;
        PublicHistoryPersisted=$false;RawEvidencePersisted=$false;ReportsPersisted=$false;WindowsChanges=$false;ProductionPermissionsChanged=$false}|ConvertTo-Json -Depth 5
}finally{foreach($stream in $lease.Streams){$stream.Dispose()}}
