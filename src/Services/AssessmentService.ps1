# Read-only evaluation orchestration. Catalogs are data; no scripts/remediation.
. (Join-Path $PSScriptRoot 'DefenderProfileRegistry.ps1')
. (Join-Path $PSScriptRoot 'DefenderCriteriaRevision.ps1')
. (Join-Path $PSScriptRoot 'BitLockerCriteriaService.ps1')
. (Join-Path $PSScriptRoot 'WindowsUpdateCriteriaService.ps1')
function Get-WinSecInstalledAssessmentProfiles {
    [CmdletBinding()]
    param([string]$ProjectRoot = ([IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))))
    Get-WinSecDefenderProfileDefinitions -ProjectRoot $ProjectRoot
}

function Get-WinSecBaseAssessmentCatalog {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectRoot, [Parameter(Mandatory)][string]$CheckId,
        [string]$Profile)
    if($CheckId -ceq 'WSA-SYS-003') {
        if(-not $PSBoundParameters.ContainsKey('Profile')){return $null}
        return Get-WinSecWindowsUpdateAssessmentCatalog -ProjectRoot $ProjectRoot -Profile $Profile
    }
    if($CheckId -ceq 'WSA-SYS-002') {
        if(-not $PSBoundParameters.ContainsKey('Profile')){return $null}
        return Get-WinSecBitLockerAssessmentCatalog -ProjectRoot $ProjectRoot -Profile $Profile
    }
    if ($CheckId -cne 'WSA-SYS-001') { return $null }
    $path = Join-Path $ProjectRoot 'config/criteria/defender.json'
    if ($PSBoundParameters.ContainsKey('Profile')) {
        $definition=@(Get-WinSecInstalledAssessmentProfiles -ProjectRoot $ProjectRoot|Where-Object {$_.Profile -ceq $Profile})
        if ($definition.Count -ne 1) { throw 'Unknown installed assessment profile.' }
        if ($null -eq $definition[0].FileName) { return Get-WinSecExpandedDefenderCatalog -ProjectRoot $ProjectRoot -Profile $Profile }
        $path=Join-Path $ProjectRoot ('config/criteria/profiles/' + $definition[0].FileName)
    }
    Assert-WinSecDeviceRemovalPath -ProjectRoot $ProjectRoot -Path $path
    $file = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if ($file.PSIsContainer -or $file.Length -gt 1048576) { throw 'Invalid assessment catalog file.' }
    $before = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash
    $catalog = ConvertFrom-WinSecStoredJson (Get-Content -LiteralPath $path -Raw -Encoding UTF8 -ErrorAction Stop)
    foreach ($criterion in @($catalog.Criteria)) {
        $reviewed = Get-WinSecCriteriaField (Get-WinSecCriteriaField $criterion 'Verification') 'ReviewedAtUTC'
        if ($reviewed -is [datetime] -and $reviewed.Kind -eq [DateTimeKind]::Utc) {
            $criterion.Verification.ReviewedAtUTC = $reviewed.ToString('o')
        }
    }
    if ($before -cne (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash -or
        $catalog.CheckId -cne $CheckId -or -not (Test-WinSecCriteriaCatalog $catalog).Valid) {
        throw 'Invalid or changed assessment catalog.'
    }
    if ($PSBoundParameters.ContainsKey('Profile') -and @($catalog.Criteria|Where-Object {$_.Applicability.Profile -cne $Profile}).Count) {
        throw 'Installed profile does not match its catalog.'
    }
    [pscustomobject]@{Catalog=$catalog;Sha256=$before}
}

function Get-WinSecAssessmentCatalog {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectRoot,[Parameter(Mandatory)][string]$CheckId,[string]$Profile)
    $snapshot=Get-WinSecBaseAssessmentCatalog @PSBoundParameters
    if($CheckId -cin @('WSA-SYS-002','WSA-SYS-003') -or $null -eq $snapshot -or -not $PSBoundParameters.ContainsKey('Profile')){return $snapshot}
    Add-WinSecDefenderCriteriaRevision -ProjectRoot $ProjectRoot -Snapshot $snapshot -Profile $Profile
}

function Assert-WinSecAssessmentProfilePreview {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Preview)
    $copy = Copy-WinSecResultData $Preview
    if ($copy -isnot [pscustomobject] -or @($copy.PSObject.Properties).Count -ne 2 -or
        @($copy.PSObject.Properties|Where-Object {$_.Name -cnotin @('Profile','Policies')}).Count -gt 0 -or
        -not (Test-WinSecTargetIdentifier $copy.Profile) -or $copy.Profile -in @('UNRESOLVED','PENDING_SELECTION') -or
        $copy.Policies -isnot [array] -or $copy.Policies.Count -eq 0 -or $copy.Policies.Count -gt 128) {
        throw 'Invalid assessment profile preview.'
    }
    $fields = @('CheckId','CatalogId','CatalogVersion','CatalogSha256','OSFamily','OSRelease','Edition')
    $seen = @{}
    foreach ($policy in $copy.Policies) {
        if ($policy -isnot [pscustomobject] -or @($policy.PSObject.Properties).Count -ne $fields.Count -or
            @($policy.PSObject.Properties|Where-Object {$_.Name -cnotin $fields}).Count -gt 0) {
            throw 'Invalid assessment profile policy.'
        }
        foreach ($field in $fields) {
            $value = $policy.$field
            if ($value -isnot [string] -or [string]::IsNullOrWhiteSpace($value) -or $value.Length -gt 256 -or
                $value -match '[\p{C}]') { throw 'Invalid assessment profile policy metadata.' }
        }
        if (-not (Test-WinSecTargetIdentifier $policy.CheckId) -or $seen.ContainsKey($policy.CheckId) -or
            $policy.CatalogSha256 -cnotmatch '\A[A-F0-9]{64}\z' -or $policy.OSFamily -cne 'Windows' -or
            $policy.OSRelease -in @('*','UNRESOLVED','PENDING_SELECTION') -or
            $policy.Edition -in @('*','UNRESOLVED','PENDING_SELECTION')) { throw 'Unresolved assessment profile policy.' }
        $seen[$policy.CheckId] = $true
    }
    return $copy
}

function Get-WinSecAssessmentProfilePlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ProjectRoot,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$CheckIds,
        [Parameter(Mandatory)][object]$Profile
    )
    if (-not (Test-WinSecTargetIdentifier $Profile) -or $Profile -in @('UNRESOLVED','PENDING_SELECTION')) {
        throw 'A concrete assessment profile identifier is required.'
    }
    $snapshots = @{}
    $policies = New-Object 'System.Collections.Generic.List[object]'
    foreach ($checkId in $CheckIds) {
        if (-not (Test-WinSecTargetIdentifier $checkId) -or $snapshots.ContainsKey($checkId)) {
            throw 'Invalid assessment profile control selection.'
        }
        $snapshot = Copy-WinSecResultData (Get-WinSecAssessmentCatalog -ProjectRoot $ProjectRoot -CheckId $checkId)
        if ($checkId -cin @('WSA-SYS-001','WSA-SYS-002','WSA-SYS-003') -and @((Get-WinSecInstalledAssessmentProfiles -ProjectRoot $ProjectRoot)|Where-Object {$_.Profile -ceq $Profile}).Count -eq 1) {
            $snapshot=Copy-WinSecResultData (Get-WinSecAssessmentCatalog -ProjectRoot $ProjectRoot -CheckId $checkId -Profile $Profile)
        }
        $snapshots[$checkId] = $snapshot
        if ($null -eq $snapshot -or -not (Test-WinSecCriteriaCatalog $snapshot.Catalog).ReadyForEvaluation) { continue }
        $rules = @($snapshot.Catalog.Criteria)
        $scope = $rules[0].Applicability
        # A profile never releases a subset of a catalog or chooses an OS scope.
        if (@($rules|Where-Object {
            $_.Applicability.Profile -cne $Profile -or $_.Applicability.OSFamily -cne $scope.OSFamily -or
            $_.Applicability.OSRelease -cne $scope.OSRelease -or $_.Applicability.Edition -cne $scope.Edition
        }).Count -gt 0) { continue }
        $policies.Add([pscustomobject]@{CheckId=$checkId;CatalogId=$snapshot.Catalog.CatalogId;
            CatalogVersion=$snapshot.Catalog.CatalogVersion;CatalogSha256=$snapshot.Sha256;
            OSFamily=$scope.OSFamily;OSRelease=$scope.OSRelease;Edition=$scope.Edition})
    }
    if ($policies.Count -eq 0) { throw 'The requested profile has no approved evaluation catalog in this selection.' }
    $preview = Assert-WinSecAssessmentProfilePreview ([pscustomobject]@{Profile=$Profile;Policies=@($policies.ToArray())})
    [pscustomobject]@{Preview=$preview;Catalogs=$snapshots}
}

function Get-WinSecAssessmentProfileOptions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ProjectRoot,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$CheckIds
    )
    $seen = @{}
    $names = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($id in $CheckIds) {
        if (-not (Test-WinSecTargetIdentifier $id) -or $seen.ContainsKey($id)) { throw 'Invalid profile discovery selection.' }
        $seen[$id] = $true
        $snapshot = Get-WinSecAssessmentCatalog -ProjectRoot $ProjectRoot -CheckId $id
        if ($null -eq $snapshot -or -not (Test-WinSecCriteriaCatalog $snapshot.Catalog).ReadyForEvaluation) { continue }
        $scope = $snapshot.Catalog.Criteria[0].Applicability
        if (@($snapshot.Catalog.Criteria|Where-Object {
            $_.Applicability.Profile -cne $scope.Profile -or $_.Applicability.OSFamily -cne $scope.OSFamily -or
            $_.Applicability.OSRelease -cne $scope.OSRelease -or $_.Applicability.Edition -cne $scope.Edition
        }).Count -gt 0) { continue }
        $null = $names.Add($scope.Profile)
    }
    foreach ($name in @($names|Sort-Object -CaseSensitive)) {
        # Reuse the exact approval and metadata contract of the coordinator.
        (Get-WinSecAssessmentProfilePlan -ProjectRoot $ProjectRoot -CheckIds $CheckIds -Profile $name).Preview
    }
    if (@($CheckIds|Where-Object {$_ -cin @('WSA-SYS-001','WSA-SYS-002','WSA-SYS-003')}).Count) {
        $installed = @(Get-WinSecInstalledAssessmentProfiles -ProjectRoot $ProjectRoot)
        $expanded = @($installed | Where-Object {$null -eq $_.FileName})
        $template = $null
        if ($expanded.Count -and $CheckIds -ccontains 'WSA-SYS-001') {
            $template = Get-WinSecBaseAssessmentCatalog $ProjectRoot 'WSA-SYS-001' -Profile 'WSA-W11-24H2-PRO-DEF-BASE'
            if (-not (Test-WinSecCriteriaCatalog $template.Catalog).ReadyForEvaluation -or
                @($expanded | Where-Object {$_.TemplateSha256 -cne $template.Sha256}).Count) { throw 'Expanded profile template is unavailable or changed.' }
        }
        $revision=$null;$bitlocker=$null
        if($CheckIds -ccontains 'WSA-SYS-001'){$revision=Get-WinSecDefenderCriteriaRevision $ProjectRoot}
        if($CheckIds -ccontains 'WSA-SYS-002'){$bitlocker=Get-WinSecBitLockerCriteriaTemplate $ProjectRoot}
        $update=$null;$reference=$null;$referenceContent=$null
        if($CheckIds -ccontains 'WSA-SYS-003') {
            $update=Get-WinSecWindowsUpdateCriteriaTemplate $ProjectRoot
            $reference=Get-WinSecWindowsUpdateReferenceCatalog $ProjectRoot
            $referenceContent=Get-WinSecWindowsUpdateReferenceFingerprint $reference.Catalog
        }
        foreach ($definition in $installed) {
            if ($names.Contains($definition.Profile)) { continue }
            if ($null -ne $definition.FileName) {
                (Get-WinSecAssessmentProfilePlan -ProjectRoot $ProjectRoot -CheckIds $CheckIds -Profile $definition.Profile).Preview
                continue
            }
            # Discovery offers metadata only. Materialize and validate the selected
            # catalog in Get-WinSecAssessmentProfilePlan before scan confirmation.
            $policies=@()
            if($CheckIds -ccontains 'WSA-SYS-001') {
                $policies+=@([pscustomobject]@{CheckId='WSA-SYS-001';CatalogId=$definition.Profile;CatalogVersion=$revision.Catalog.CatalogVersion;
                    CatalogSha256=(Get-WinSecDefenderRevisionFingerprint (Get-WinSecDefenderProfileFingerprint $definition.MatrixSha256 $template.Sha256 $definition.Profile) $revision.Sha256 $definition.Profile);
                    OSFamily='Windows';OSRelease=$definition.OSRelease;Edition=$definition.Edition})
            }
            if($CheckIds -ccontains 'WSA-SYS-002') {
                $policies+=@([pscustomobject]@{CheckId='WSA-SYS-002';CatalogId=($definition.Profile -creplace '-DEF-BASE\z','-BLK-BASE');
                    CatalogVersion=$bitlocker.Catalog.CatalogVersion;
                    CatalogSha256=(Get-WinSecBitLockerCriteriaFingerprint $bitlocker.Sha256 $definition.MatrixSha256 $definition.Profile);
                    OSFamily='Windows';OSRelease=$definition.OSRelease;Edition=$definition.Edition})
            }
            if($CheckIds -ccontains 'WSA-SYS-003') {
                $policies+=@([pscustomobject]@{CheckId='WSA-SYS-003';CatalogId=($definition.Profile -creplace '-DEF-BASE\z','-WUP-BASE');
                    CatalogVersion=($update.Catalog.CatalogVersion+'+'+$reference.Catalog.CatalogVersion);
                    CatalogSha256=(Get-WinSecWindowsUpdateCriteriaFingerprint $update.Sha256 $definition.MatrixSha256 $reference.Sha256 $referenceContent $definition.Profile);
                    OSFamily='Windows';OSRelease=$definition.OSRelease;Edition=$definition.Edition})
            }
            Assert-WinSecAssessmentProfilePreview ([pscustomobject]@{Profile=$definition.Profile;Policies=$policies})
        }
    }
}

function Resolve-WinSecAssessmentDependencies {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$ControlResult,
        [AllowNull()][System.Collections.IDictionary]$DeclaredDependencies = $null
    )
    $dependencies = if ($null -eq $DeclaredDependencies) { @{} } else { Copy-WinSecResultData $DeclaredDependencies }
    $control = Copy-WinSecResultData $ControlResult
    if((Get-WinSecResultField $control 'CheckId') -ceq 'WSA-SYS-003') {
        return ,(Resolve-WinSecWindowsUpdateDependencies -ControlResult $control -DeclaredDependencies $dependencies)
    }
    if((Get-WinSecResultField $control 'CheckId') -ceq 'WSA-SYS-002') {
        return ,(Resolve-WinSecBitLockerDependencies -ControlResult $control -DeclaredDependencies $dependencies)
    }
    if ((Get-WinSecResultField $control 'CheckId') -cne 'WSA-SYS-001') { return ,$dependencies }

    # Explicit false or a malformed declaration cannot be upgraded by telemetry.
    # Conversely, a caller's true never substitutes for this scan's observation.
    $key = 'active-antivirus-mode'
    $declaredAllows = (-not $dependencies.Contains($key) -or
        ($dependencies[$key] -is [bool] -and $dependencies[$key] -ceq $true))
    $dependencies[$key] = $false
    $evidence = Get-WinSecResultField $control 'Evidence'
    $completeIdentity = $true
    foreach ($field in @('CheckId','DeviceId','ScanId')) {
        $expected = Get-WinSecResultField $control $field
        $observed = Get-WinSecResultField $evidence $field
        if (-not (Test-WinSecTargetIdentifier $expected)) { throw 'Invalid assessment prerequisite identity.' }
        if ($null -ne $observed -and ($observed -isnot [string] -or $observed -cne $expected)) {
            throw 'Foreign or invalid evidence in assessment prerequisites.'
        }
        if ($null -eq $observed) { $completeIdentity = $false }
    }
    $successful = Get-WinSecResultField $evidence 'CollectionSuccessful'
    $status = Get-WinSecResultField $control 'Status'
    $observedStatus = Get-WinSecResultField $control 'ObservedStatus'
    if (-not $completeIdentity -or -not $declaredAllows -or
        $status -isnot [string] -or $status -cne 'INFORMATIONAL' -or
        ($null -ne $observedStatus -and ($observedStatus -isnot [string] -or $observedStatus -cne 'INFORMATIONAL')) -or
        $successful -isnot [bool] -or $successful -cne $true) { return ,$dependencies }

    $mode = Get-WinSecResultField (Get-WinSecResultField $evidence 'DefenderStatus') 'AMRunningMode'
    # Runtime mode only; this does not select or approve a policy profile, prove
    # third-party AV absence, or claim that each protection is enabled/effective.
    if ($mode -is [string] -and [string]::Equals($mode, 'Normal', [StringComparison]::OrdinalIgnoreCase)) {
        $dependencies[$key] = $true
    }
    return ,$dependencies
}

function Invoke-WinSecScanAssessment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$AuditResult,
        [Parameter(Mandatory)][string]$ProjectRoot,
        [AllowNull()][object]$TargetContext = $null,
        [AllowNull()][System.Collections.IDictionary]$DependencyEvidence = $null,
        [AllowNull()][System.Collections.IDictionary]$CatalogSnapshots = $null
    )
    $evaluations = New-Object 'System.Collections.Generic.List[object]'
    $selections = New-Object 'System.Collections.Generic.List[object]'
    $findings = New-Object 'System.Collections.Generic.List[object]'
    if ($null -eq $TargetContext) {
        # Do not guess Windows release, edition, profile or prerequisites from a hostname.
        $TargetContext = [pscustomobject]@{DeviceId=$AuditResult.DeviceId;ScanId=$AuditResult.ScanId;
            OSFamily='Windows';OSRelease='UNRESOLVED';Edition='UNRESOLVED';Profile='UNRESOLVED'}
    }
    $context = Copy-WinSecResultData $TargetContext
    if ($context.DeviceId -cne $AuditResult.DeviceId -or $context.ScanId -cne $AuditResult.ScanId) {
        throw 'Assessment context belongs to another device or scan.'
    }
    foreach ($inputControl in $AuditResult.ControlResults) {
        if ($inputControl.Status -ceq 'NOT_SELECTED') { continue }
        $control = Copy-WinSecResultData $inputControl
        if ($control.DeviceId -cne $AuditResult.DeviceId -or $control.ScanId -cne $AuditResult.ScanId) {
            throw 'Foreign control in assessment input.'
        }
        # AuditEngine retains a technical ERROR in ObservedStatus even when unscored.
        if ($control.ObservedStatus -ceq 'ERROR') { $control.Status = 'ERROR' }
        $snapshot = if ($null -ne $CatalogSnapshots) {
            if (-not $CatalogSnapshots.Contains($control.CheckId)) { throw 'Assessment catalog was not prepared for this control.' }
            Copy-WinSecResultData $CatalogSnapshots[$control.CheckId]
        } else { Get-WinSecAssessmentCatalog -ProjectRoot $ProjectRoot -CheckId $control.CheckId }
        $selection = $null
        $criteria = @()
        if ($null -ne $snapshot) {
            $dependencies = $null
            if ($null -ne $DependencyEvidence -and $DependencyEvidence.Contains($control.CheckId)) {
                $dependencies = $DependencyEvidence[$control.CheckId]
                if ($dependencies -isnot [System.Collections.IDictionary]) { throw 'Invalid assessment prerequisites.' }
            }
            $dependencies = Resolve-WinSecAssessmentDependencies -ControlResult $control -DeclaredDependencies $dependencies
            $selection = Get-WinSecApplicableCriteria -Catalog $snapshot.Catalog -TargetContext $context `
                -ControlResult $control -ProjectRoot $ProjectRoot -DependencyEvidence $dependencies -ForEvaluation
            $selection|Add-Member -NotePropertyName CatalogVersion -NotePropertyValue $snapshot.Catalog.CatalogVersion
            $selection|Add-Member -NotePropertyName CatalogSha256 -NotePropertyValue $snapshot.Sha256
            $selections.Add($selection)
            if ($selection.Status -ceq 'READY') { $criteria = @($selection.EligibleCriteria) }
        }
        $evaluation = Invoke-WinSecControlEvaluation -ControlResult $control -Criteria $criteria -TargetContext $context
        $generated = ConvertTo-WinSecFindings -EvaluationResult $evaluation -ControlResult $control -SelectionResult $selection
        if ($generated.Status -ceq 'INVALID_INPUT') { throw 'Assessment findings validation failed.' }
        $evaluations.Add($evaluation)
        foreach ($finding in $generated.Findings) {
            if ($finding.Kind -ceq 'CONFIGURATION_DEVIATION') {
                $criterion = @($criteria|Where-Object {$_.CriterionId -ceq $finding.CriterionId})
                if ($criterion.Count -ne 1 -or -not (Test-WinSecCriteriaApprovalReady $criterion[0])) {
                    throw 'A deviation has no verified applicable criterion.'
                }
                $rule = $criterion[0]
                $guidance = [pscustomobject]@{
                    SchemaVersion='1.0.0';CheckId=$control.CheckId;CatalogId=$snapshot.Catalog.CatalogId
                    CatalogVersion=$snapshot.Catalog.CatalogVersion;CatalogSha256=$snapshot.Sha256
                    CriterionId=$rule.CriterionId;CriterionTitle=$rule.Name;Recommendation=$rule.Recommendation
                    Framework=$rule.Source.Framework;FrameworkVersion=$rule.Source.Version
                    ReferenceId=$rule.Source.ControlId;ReferenceTitle=$rule.Source.Title;ReferenceUrl=$rule.Source.Url
                    VerifiedAtUTC=([DateTimeOffset]::Parse($rule.Verification.ReviewedAtUTC)).UtcDateTime.ToString('o')
                    OSFamily=$rule.Applicability.OSFamily;OSRelease=$rule.Applicability.OSRelease
                    Edition=$rule.Applicability.Edition;Profile=$rule.Applicability.Profile
                }
                $finding|Add-Member -NotePropertyName Guidance -NotePropertyValue `
                    (ConvertTo-WinSecPublicFindingGuidance $finding $guidance)
            }
            $findings.Add($finding)
        }
    }
    [pscustomobject]@{EvaluationResults=@($evaluations.ToArray());CriteriaSelections=@($selections.ToArray());
        Findings=@($findings.ToArray())}
}
