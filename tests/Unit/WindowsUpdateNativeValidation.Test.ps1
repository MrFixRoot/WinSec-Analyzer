# Validador real con limites de proveedores simulados. Sin consultas Windows ni persistencia.
[CmdletBinding()]
param([switch]$Integration,[string]$CasePattern='*')
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$validator=Join-Path $root 'tests/Integration/Invoke-WindowsUpdateNativeValidation.ps1'
. (Join-Path $root 'tests/Fixtures/WindowsUpdateNativeValidationSupport.ps1')
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
# Reuse provider fixtures in memory with an explicit shared test state. The entry
# script has a child script scope, so script: state would not cross that boundary.
$fixture=[IO.File]::ReadAllText((Join-Path $root 'tests/Fixtures/WindowsUpdateMemory.ps1'))
. ([scriptblock]::Create($fixture.Replace('$script:WU','$global:WinSecWindowsUpdateNativeTest')))
$aliases=New-Object 'System.Collections.Generic.List[string]'
$script:passed=0;$script:failed=0
$production=@{}
foreach($path in @('config/checks.json','config/scoring.json','config/criteria/windows-update.json')) {
    $production[$path]=(Get-FileHash -LiteralPath (Join-Path $root $path) -Algorithm SHA256).Hash
}
function Assert-WinSecNativeUpdate {param([bool]$Condition);if(-not $Condition){throw 'Native Update fixture assertion failed.'}}
function Assert-WinSecNativeUpdateRejected {
    param([scriptblock]$Action)
    $caught=$false;try{$null=& $Action}catch{$caught=$true}
    Assert-WinSecNativeUpdate $caught
    Assert-WinSecNativeUpdate ($global:WinSecWindowsUpdateNativeTest.CimReads -eq 0 -and
        $global:WinSecWindowsUpdateNativeTest.KeyReads -eq 0 -and $global:WinSecWindowsUpdateNativeTest.VersionReads -eq 0 -and
        $global:WinSecWindowsUpdateNativeTest.NamedPolicyReads -eq 0 -and $global:WinSecWindowsUpdateNativeTest.RebootReads -eq 0)
}
function Test-WinSecNativeUpdate {
    param([string]$Name,[scriptblock]$Action)
    if($Name -notlike $CasePattern){return}
    Reset-WinSecWindowsUpdateFixture
    $global:WinSecWindowsUpdateNativeTest.Systems[0].Caption='Microsoft Windows 11 Pro'
    $global:WinSecWindowsUpdateNativeTest.Systems[0].Version='10.0.26200'
    $global:WinSecWindowsUpdateNativeTest.Systems[0].BuildNumber='26200'
    $global:WinSecWindowsUpdateNativeTest.VersionValues.CurrentBuildNumber='26200'
    $global:WinSecWindowsUpdateNativeTest.Clock=([datetime]'2026-10-25T12:00:00Z').ToUniversalTime()
    $global:WinSecWindowsUpdateNativeTest.Elevated=$false
    $global:WinSecWindowsUpdateNativeTest.ChangedDependency=''
    $global:WinSecWindowsUpdateNativeTest.ChangeDuringCollection=$false
    try{$null=& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}
    catch {
        $script:failed++;Write-Host ('[FAIL] '+$Name+' : '+$_.Exception.Message)
        Write-Host $_.ScriptStackTrace
        foreach($detail in @($Error|Select-Object -First 3)){Write-Host $detail.Exception.Message;Write-Host $detail.ScriptStackTrace}
    }
}
# Aliases intercept the actual IO boundaries even when the entry script loads
# production function definitions. No registry/COM/WinRT provider is ever used.
$boundaries=@('Get-WinSecLocalHardwareDeviceId','Open-WinSecWindowsUpdatePolicyKey',
    'Open-WinSecWindowsUpdateVersionKey','Get-WinSecWindowsUpdateRebootRequired','Read-WinSecWindowsUpdateNamedPolicy')
$index=0
foreach($name in $boundaries) {
    $replacement='Invoke-WinSecNativeUpdateBoundary'+$index;$index++
    Set-Item -LiteralPath ('Function:\'+$replacement) -Value (Get-Command $name -CommandType Function).ScriptBlock
    Set-Alias -Name $name -Value $replacement;$aliases.Add($name)
}
$fixtureCim=(Get-Command Get-CimInstance -CommandType Function).ScriptBlock
function Invoke-WinSecNativeUpdateCim {
    [CmdletBinding()]param($Namespace,$ClassName,$Property,$Filter,$OperationTimeoutSec)
    if($global:WinSecWindowsUpdateNativeTest.ChangeDuringCollection) {
        $global:WinSecWindowsUpdateNativeTest.ChangedDependency='src/Core/ResultModel.ps1'
    }
    if($ClassName -ceq 'Win32_OperatingSystem' -and ($Property -join ',') -ceq 'Caption,Version,BuildNumber,OperatingSystemSKU,ProductType') {
        $global:WinSecWindowsUpdateNativeTest.CimReads++
        return $global:WinSecWindowsUpdateNativeTest.Systems
    }
    & $fixtureCim @PSBoundParameters
}
Set-Alias Get-CimInstance Invoke-WinSecNativeUpdateCim;$aliases.Add('Get-CimInstance')
function Invoke-WinSecNativeUpdateClock {return $global:WinSecWindowsUpdateNativeTest.Clock}
function Invoke-WinSecNativeUpdateElevation {return $global:WinSecWindowsUpdateNativeTest.Elevated}
Set-Alias Get-WinSecWindowsUpdateNativeUtcNow Invoke-WinSecNativeUpdateClock;$aliases.Add('Get-WinSecWindowsUpdateNativeUtcNow')
Set-Alias Get-WinSecWindowsUpdateNativeElevation Invoke-WinSecNativeUpdateElevation;$aliases.Add('Get-WinSecWindowsUpdateNativeElevation')
$originalHash=(Get-Command Get-WinSecWindowsUpdateValidationHash -CommandType Function).ScriptBlock
function Invoke-WinSecNativeUpdateHash {
    param([string]$Text)
    $changed=$global:WinSecWindowsUpdateNativeTest.ChangedDependency
    if($changed -and $Text.StartsWith('[') -and $Text.Contains($changed)){$Text=$Text.Replace($changed,$changed+'.changed')}
    & $originalHash $Text
}
Set-Alias Get-WinSecWindowsUpdateValidationHash Invoke-WinSecNativeUpdateHash;$aliases.Add('Get-WinSecWindowsUpdateValidationHash')
function Get-MpComputerStatus {throw 'Forbidden Defender query.'}
function Get-MpPreference {throw 'Forbidden Defender query.'}
function Get-BitLockerVolume {throw 'Forbidden BitLocker query.'}
function Invoke-CimMethod {throw 'Forbidden CIM method.'}
$profile='WSA-W11-25H2-PRO-DEF-BASE'
$operation='b'*32
try {
    if(-not $Integration) {
    Test-WinSecNativeUpdate 'No-argument invocation rejects before hardware or security queries' {
        Assert-WinSecNativeUpdateRejected {& $validator}
        Assert-WinSecNativeUpdate ($global:WinSecWindowsUpdateNativeTest.IdentityReads -eq 0)
    }
    foreach($arguments in @(@{PlanOnly=$true},@{PlanOnly=$true;Profile='bad';OperationId=$operation},
        @{PlanOnly=$true;Profile=$profile;OperationId='../bad'},@{PlanOnly=$true;Profile=$profile;ApprovedRequestHash=('A'*64)})) {
        Test-WinSecNativeUpdate 'Malformed or ambiguous preparation cannot query the device' {
            Assert-WinSecNativeUpdateRejected {& $validator @arguments}
            Assert-WinSecNativeUpdate ($global:WinSecWindowsUpdateNativeTest.IdentityReads -eq 0)
        }
    }
    Test-WinSecNativeUpdate 'PlanOnly binds identity, runtime, criteria, references and all transitive dependencies without scanning' {
        $plan=(& $validator -PlanOnly -Profile $profile -OperationId $operation)|ConvertFrom-Json
        $again=(& $validator -PlanOnly -Profile $profile -OperationId $operation)|ConvertFrom-Json
        Assert-WinSecNativeUpdate ($plan.RequestHash -ceq $again.RequestHash -and $plan.Request.Runtime -ceq $PSVersionTable.PSVersion.ToString() -and
            $plan.Request.ScopeKey -ceq 'WSA-SYS-003' -and $plan.Request.Checks.Count -eq 1 -and
            $plan.Request.DependencyCount -gt 50 -and $plan.Request.CriteriaSha256 -cmatch '\A[A-F0-9]{64}\z' -and
            $plan.Request.DependencyManifestSha256 -cmatch '\A[A-F0-9]{64}\z' -and $plan.Request.ReadOnly -and
            -not $plan.Request.PersistReports -and -not $plan.Request.PersistPublicHistory -and -not $plan.Request.PersistRawEvidence -and
            -not $plan.Request.UpdateSearchPerformed -and $global:WinSecWindowsUpdateNativeTest.CimReads -eq 0 -and
            $global:WinSecWindowsUpdateNativeTest.KeyReads -eq 0 -and $global:WinSecWindowsUpdateNativeTest.NamedPolicyReads -eq 0)
    }
    Test-WinSecNativeUpdate 'Snapshot covers policy reader, reference, scoring, public model, reports and itself and holds read-only leases' {
        $lease=Open-WinSecWindowsUpdateValidationSnapshot $root
        try {
            foreach($path in @('src/Checks/System/WindowsUpdatePolicyReader.ps1','config/criteria/windows-update-servicing.json',
                'src/Core/ResultModel.ps1','src/Services/ReportService.ps1','config/scoring.json',
                'tests/Integration/Invoke-WindowsUpdateNativeValidation.ps1','tests/Fixtures/WindowsUpdateNativeValidationSupport.ps1')) {
                Assert-WinSecNativeUpdate (@($lease.Files|Where-Object Path -CEQ $path).Count -eq 1)
            }
            $blocked=$false;$writer=$null
            try {$writer=[IO.File]::Open((Join-Path $root 'src/Checks/System/WindowsUpdatePolicyReader.ps1'),[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::Read)}
            catch {$blocked=$true} finally {if($null -ne $writer){$writer.Dispose()}}
            Assert-WinSecNativeUpdate $blocked
        } finally {foreach($stream in $lease.Streams){$stream.Dispose()}}
    }
    foreach($fault in @('NoHash','WrongHash','Operation','Profile','Device','Elevation','UTCDate',
        'src/Checks/System/WindowsUpdatePolicyReader.ps1','src/Core/ResultModel.ps1','config/frameworks/nist-csf.json','config/criteria/windows-update-servicing.json')) {
        Test-WinSecNativeUpdate ('Changed or unapproved request rejects before collection: '+$fault) {
            $plan=(& $validator -PlanOnly -Profile $profile -OperationId $operation)|ConvertFrom-Json
            $argsForRun=@{Profile=$profile;OperationId=$operation;ApprovedRequestHash=$plan.RequestHash}
            switch($fault) {
                NoHash {$argsForRun.Remove('ApprovedRequestHash')}
                WrongHash {$argsForRun.ApprovedRequestHash='A'*64}
                Operation {$argsForRun.OperationId='c'*32}
                Profile {$argsForRun.Profile='WSA-W11-24H2-PRO-DEF-BASE'}
                Device {$global:WinSecWindowsUpdateNativeTest.LocalIds=@('local:hw1-'+('c'*64))}
                Elevation {$global:WinSecWindowsUpdateNativeTest.Elevated=$true}
                UTCDate {$global:WinSecWindowsUpdateNativeTest.Clock=$global:WinSecWindowsUpdateNativeTest.Clock.AddDays(1)}
                default {$global:WinSecWindowsUpdateNativeTest.ChangedDependency=$fault}
            }
            Assert-WinSecNativeUpdateRejected {& $validator @argsForRun}
        }
    }
    Test-WinSecNativeUpdate 'Expired reference rejects an otherwise matching request before collection' {
        $global:WinSecWindowsUpdateNativeTest.Clock=([datetime]'2026-10-31T00:00:00Z').ToUniversalTime()
        $plan=(& $validator -PlanOnly -Profile $profile -OperationId $operation)|ConvertFrom-Json
        if($plan.Request.ApprovalDateUTC -cne '2026-10-31' -or ([datetime]$plan.Request.ReferenceValidUntilUTC).ToUniversalTime().ToString('o') -cne '2026-10-31T00:00:00.0000000Z') {
            throw ('Incorrect UTC binding: '+$plan.Request.ApprovalDateUTC+' / '+$plan.Request.ReferenceValidUntilUTC)
        }
        Assert-WinSecNativeUpdateRejected {& $validator -Profile $profile -OperationId $operation -ApprovedRequestHash $plan.RequestHash}
    }
    } else {
        foreach($scenario in @('Healthy','Disabled','PolicyFailure','ServiceFailure','Reboot','Mismatch','Home')) {
            Test-WinSecNativeUpdate ('Approved synthetic operation validates real collection, Findings, history and Markdown: '+$scenario) {
                $selectedProfile=$profile
                switch($scenario) {
                    Disabled {$global:WinSecWindowsUpdateNativeTest.Services[0].StartMode='Disabled'}
                    PolicyFailure {$global:WinSecWindowsUpdateNativeTest.NamedPolicyFailures=@('AllowAutoUpdate')}
                    ServiceFailure {$global:WinSecWindowsUpdateNativeTest.FailClasses=@('Win32_Service')}
                    Reboot {$global:WinSecWindowsUpdateNativeTest.RebootValue=$true}
                    Mismatch {$selectedProfile='WSA-W11-24H2-PRO-DEF-BASE'}
                    Home {$selectedProfile='WSA-W11-25H2-HOME-DEF-BASE';$global:WinSecWindowsUpdateNativeTest.Systems[0].OperatingSystemSKU=[uint32]98}
                }
                $plan=(& $validator -PlanOnly -Profile $selectedProfile -OperationId $operation)|ConvertFrom-Json
                Assert-WinSecNativeUpdate ($global:WinSecWindowsUpdateNativeTest.CimReads -eq 0 -and
                    $global:WinSecWindowsUpdateNativeTest.KeyReads -eq 0 -and $global:WinSecWindowsUpdateNativeTest.NamedPolicyReads -eq 0)
                $json=& $validator -Profile $selectedProfile -OperationId $operation -ApprovedRequestHash $plan.RequestHash
                $result=$json|ConvertFrom-Json
                Assert-WinSecNativeUpdate ($result.ExecutionStatus -ceq 'COMPLETED' -and $result.PublicHistoryRoundtripValidated -and
                    $result.InMemoryMarkdownReports -eq 3 -and $result.CriterionCount -eq 3 -and $result.AssessmentMode -ceq 'FRAMEWORK_REVIEW' -and
                    -not $result.RawEvidencePersisted -and -not $result.PublicHistoryPersisted -and -not $result.ReportsPersisted -and
                    -not $result.UpdateSearchPerformed -and -not $result.WindowsChanges -and -not $result.ProductionPermissionsChanged -and
                    ($json -join '') -notmatch 'PRIVATE|PolicyRegistry|AutomationPolicy|NamedPolicy|ObservedValue|"Evidence"|ConfigurationScore|ConfigurationStatus' -and
                    $global:WinSecWindowsUpdateNativeTest.KeyReads -eq 2 -and $global:WinSecWindowsUpdateNativeTest.VersionReads -eq 1 -and
                    $global:WinSecWindowsUpdateNativeTest.RebootReads -eq 1 -and $global:WinSecWindowsUpdateNativeTest.NamedPolicyReads -eq 5)
                switch($scenario) {
                    Healthy {Assert-WinSecNativeUpdate ($result.CollectionValidated -and $result.ReadingCount -eq 53)}
                    Disabled {Assert-WinSecNativeUpdate ($result.CollectionValidated -and $result.ReadingCount -eq 53 -and $result.PublicFindings -gt 0)}
                    PolicyFailure {Assert-WinSecNativeUpdate (-not $result.CollectionValidated -and $null -eq $result.ConfigurationScore -and
                        $result.CollectionIssues -ccontains 'UPDATE_POLICY_AllowAutoUpdate_QUERY_FAILED')}
                    ServiceFailure {Assert-WinSecNativeUpdate (-not $result.CollectionValidated -and $null -eq $result.ConfigurationScore -and
                        $result.CollectionIssues -ccontains 'UPDATE_SERVICE_QUERY_FAILED')}
                    default {Assert-WinSecNativeUpdate ($result.CollectionValidated -and $null -eq $result.ConfigurationScore)}
                }
            }
        }
        Test-WinSecNativeUpdate 'A dependency inconsistency during collection cannot publish a successful validation' {
            $plan=(& $validator -PlanOnly -Profile $profile -OperationId $operation)|ConvertFrom-Json
            $global:WinSecWindowsUpdateNativeTest.ChangeDuringCollection=$true
            $caught=$false;$output=$null
            try {$output=& $validator -Profile $profile -OperationId $operation -ApprovedRequestHash $plan.RequestHash}
            catch {$caught=$true;Assert-WinSecNativeUpdate ($_.Exception.Message -notmatch 'PRIVATE')}
            Assert-WinSecNativeUpdate ($caught -and $null -eq $output -and $global:WinSecWindowsUpdateNativeTest.CimReads -gt 0)
        }
    }
} finally {
    foreach($path in $production.Keys) {
        Assert-WinSecNativeUpdate ($production[$path] -ceq (Get-FileHash -LiteralPath (Join-Path $root $path) -Algorithm SHA256).Hash)
    }
    foreach($name in $aliases){Remove-Item -LiteralPath ('Alias:\'+$name) -Force}
    Remove-Variable WinSecWindowsUpdateNativeTest -Scope Global -ErrorAction SilentlyContinue
}
Write-Host ('Windows Update native validator: {0} passed, {1} failed.' -f $script:passed,$script:failed)
if($script:failed){throw 'Windows Update native validator unit tests failed.'}
