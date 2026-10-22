# Evaluación y nota BitLocker con evidencia sintética; sin consultas o escrituras.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
function Get-CimInstance {throw 'Unexpected Windows query in BitLocker criteria unit tests.'}
. (Join-Path $PSScriptRoot '../../src/Core/ScanCoordinator.ps1')
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$profile='WSA-W11-24H2-PRO-DEF-BASE'
$snapshot=Get-WinSecAssessmentCatalog $root WSA-SYS-002 -Profile $profile
$registry=Get-WinSecCheckRegistry $root;$policy=Get-WinSecConfigurationScoringPolicy $root
$script:passed=0;$script:failed=0
function Assert-WinSecBitLockerCriteria {param([bool]$Condition);if(-not $Condition){throw 'BitLocker criteria assertion failed.'}}
function Test-WinSecBitLockerCriteriaCase {
    param([string]$Name,[scriptblock]$Action)
    $script:context=[pscustomobject]@{DeviceId=('local:hw1-'+('a'*64));ScanId='bitlocker-criteria-unit';OSFamily='Windows';
        OSRelease='Windows 11 10.0.26100';Edition='SKU:48';Profile=$profile}
    $script:control=[pscustomobject]@{CheckId='WSA-SYS-002';DeviceId=$script:context.DeviceId;ScanId=$script:context.ScanId;
        SectionKey='SystemSecurity';Status='INFORMATIONAL';ObservedStatus='INFORMATIONAL';Evidence=[pscustomobject]@{
            SchemaVersion='1.0.0';CheckId='WSA-SYS-002';DeviceId=$script:context.DeviceId;ScanId=$script:context.ScanId;
            Scope='OS_VOLUME_ONLY';CollectionSuccessful=$true;CollectionComplete=$true;SystemVolume=[pscustomobject]@{
                DriveLetter='D:';ConversionStatus='FULLY_ENCRYPTED';ProtectionStatus='ON';EncryptionMethod='XTS_AES_128';LockStatus='UNLOCKED';EncryptionPercentage=100}}}
    $script:declared=$null
    try{$null=& $Action;$script:passed++;[Console]::WriteLine('[PASS] '+$Name)}
    catch{$script:failed++;[Console]::WriteLine('[FAIL] '+$Name+' : '+$_.Exception.Message);[Console]::WriteLine($_.ScriptStackTrace)}
}
function Invoke-WinSecBitLockerCriteriaFixture {
    $audit=[pscustomobject]@{DeviceId=$script:context.DeviceId;ScanId=$script:context.ScanId;CatalogVersion='0.9.0';ControlResults=@($script:control)}
    $arguments=@{AuditResult=$audit;ProjectRoot=$root;TargetContext=$script:context;CatalogSnapshots=@{'WSA-SYS-002'=$snapshot}}
    if($null -ne $script:declared){$arguments.DependencyEvidence=@{'WSA-SYS-002'=$script:declared}}
    $assessment=Invoke-WinSecScanAssessment @arguments
    $configuration=New-WinSecConfigurationAssessment -Audit $audit -Assessment $assessment -Context $script:context -Registry $registry `
        -Catalogs @{'WSA-SYS-002'=$snapshot} -PolicySnapshot $policy -ScopeType CONTROL -ScopeKey WSA-SYS-002 -ProjectRoot $root
    [pscustomobject]@{Assessment=$assessment;Configuration=$configuration}
}
Test-WinSecBitLockerCriteriaCase 'Approved independent two-rule policy has its own codes, recommendations and reproducible fingerprint' {
    $again=Get-WinSecAssessmentCatalog $root WSA-SYS-002 -Profile $profile
    Assert-WinSecBitLockerCriteria ($snapshot.Catalog.CatalogId -ceq 'WSA-W11-24H2-PRO-BLK-BASE' -and
        ($snapshot.Catalog.Criteria.CriterionId -join ',') -ceq 'WSA-BLK-BASE-001,WSA-BLK-BASE-002' -and
        (Test-WinSecCriteriaCatalog $snapshot.Catalog).ReadyForScoring -and $snapshot.Sha256 -ceq $again.Sha256 -and
        $snapshot.Catalog.Criteria[0].ExpectedValue -ceq 'FULLY_ENCRYPTED' -and $snapshot.Catalog.Criteria[1].ExpectedValue -ceq 'ON' -and
        @($snapshot.Catalog.Criteria|Where-Object {$_.Recommendation -notmatch 'WinSec'}).Count -eq 0)
    Assert-WinSecBitLockerCriteria ($null -eq (Get-WinSecAssessmentCatalog $root WSA-SYS-002))
}
foreach($spec in @(@{Conversion='FULLY_ENCRYPTED';Protection='ON';Score=100;Failures=0},
    @{Conversion='FULLY_ENCRYPTED';Protection='OFF';Score=50;Failures=1},
    @{Conversion='FULLY_DECRYPTED';Protection='OFF';Score=0;Failures=2})) {
    Test-WinSecBitLockerCriteriaCase ('Stable approved configuration scores exactly '+$spec.Score) {
        $script:control.Evidence.SystemVolume.ConversionStatus=$spec.Conversion
        $script:control.Evidence.SystemVolume.ProtectionStatus=$spec.Protection
        $r=Invoke-WinSecBitLockerCriteriaFixture
        Assert-WinSecBitLockerCriteria ($r.Configuration.Controls[0].Value -eq $spec.Score -and
            $r.Configuration.Controls[0].Criteria.Count -eq 2 -and $r.Configuration.Controls[0].EvaluatedCriteria -eq 2 -and
            @($r.Assessment.Findings|Where-Object Kind -CEQ CONFIGURATION_DEVIATION).Count -eq $spec.Failures)
        foreach($finding in @($r.Assessment.Findings|Where-Object Kind -CEQ CONFIGURATION_DEVIATION)) {
            Assert-WinSecBitLockerCriteria ($finding.Guidance.CatalogSha256 -ceq $snapshot.Sha256 -and $finding.Guidance.CheckId -ceq 'WSA-SYS-002')
        }
    }
}
foreach($state in @('ENCRYPTION_IN_PROGRESS','DECRYPTION_IN_PROGRESS','ENCRYPTION_PAUSED','DECRYPTION_PAUSED','UNKNOWN',$null,@('FULLY_ENCRYPTED'))) {
    Test-WinSecBitLockerCriteriaCase 'Transient missing or malformed conversion cannot earn a score or produce configuration failures' {
        $script:control.Evidence.SystemVolume.ConversionStatus=$state
        $script:control.Evidence.SystemVolume.ProtectionStatus='OFF'
        $r=Invoke-WinSecBitLockerCriteriaFixture
        Assert-WinSecBitLockerCriteria ($null -eq $r.Configuration.Controls[0].Value -and
            @($r.Assessment.Findings|Where-Object Kind -CEQ CONFIGURATION_DEVIATION).Count -eq 0 -and
            @($r.Configuration.Controls[0].Criteria|Where-Object Status -CEQ FAIL).Count -eq 0)
    }
}
foreach($state in @('UNKNOWN',$null,1,$true,@('ON'))) {
    Test-WinSecBitLockerCriteriaCase 'Unknown or malformed protection cannot be coerced or excluded to invent a numeric score' {
        $script:control.Evidence.SystemVolume.ProtectionStatus=$state
        $r=Invoke-WinSecBitLockerCriteriaFixture
        Assert-WinSecBitLockerCriteria ($null -eq $r.Configuration.Controls[0].Value -and
            @($r.Assessment.Findings|Where-Object Kind -CEQ CONFIGURATION_DEVIATION).Count -eq 0 -and
            @($r.Configuration.Controls[0].Criteria|Where-Object Status -CEQ NOT_APPLICABLE).Count -eq 0)
    }
}
Test-WinSecBitLockerCriteriaCase 'Contradictory fully decrypted but protected telemetry is blocked' {
    $script:control.Evidence.SystemVolume.ConversionStatus='FULLY_DECRYPTED'
    $r=Invoke-WinSecBitLockerCriteriaFixture
    Assert-WinSecBitLockerCriteria ($null -eq $r.Configuration.Controls[0].Value -and
        @($r.Assessment.Findings|Where-Object Kind -CEQ CONFIGURATION_DEVIATION).Count -eq 0)
}
Test-WinSecBitLockerCriteriaCase 'Encryption percentage algorithm and lock state are not additional scored criteria' {
    $script:control.Evidence.SystemVolume.EncryptionPercentage=$null
    $script:control.Evidence.SystemVolume.EncryptionMethod='UNKNOWN';$script:control.Evidence.SystemVolume.LockStatus='UNKNOWN'
    $script:control.Evidence.CollectionComplete=$false
    $r=Invoke-WinSecBitLockerCriteriaFixture
    Assert-WinSecBitLockerCriteria ($r.Configuration.Controls[0].Value -eq 100 -and $r.Configuration.Controls[0].TotalCriteria -eq 2)
}
foreach($field in @('OSRelease','Edition','Profile')) {
    Test-WinSecBitLockerCriteriaCase ('A mismatched Windows context blocks both criteria: '+$field) {
        $script:context.$field='OTHER';$r=Invoke-WinSecBitLockerCriteriaFixture
        Assert-WinSecBitLockerCriteria ($null -eq $r.Configuration.Controls[0].Value -and
            @($r.Assessment.Findings|Where-Object Kind -CEQ CONFIGURATION_DEVIATION).Count -eq 0)
    }
}
foreach($key in @('bitlocker-os-volume','bitlocker-stable-conversion','bitlocker-valid-protection')) {
    Test-WinSecBitLockerCriteriaCase ('A declared false prerequisite is never upgraded while scoring: '+$key) {
        $script:declared=@{$key=$false};$r=Invoke-WinSecBitLockerCriteriaFixture
        Assert-WinSecBitLockerCriteria ($null -eq $r.Configuration.Controls[0].Value -and
            @($r.Assessment.Findings|Where-Object Kind -CEQ CONFIGURATION_DEVIATION).Count -eq 0)
    }
}
foreach($fault in @('Scope','Schema','Collection','ObservedStatus','DriveLetter','MissingIdentity')) {
    Test-WinSecBitLockerCriteriaCase ('Unverified prerequisite evidence is blocked: '+$fault) {
        switch($fault) {
            Scope {$script:control.Evidence.Scope='ALL_VOLUMES'}
            Schema {$script:control.Evidence.SchemaVersion='UNKNOWN'}
            Collection {$script:control.Evidence.CollectionSuccessful=$false}
            ObservedStatus {$script:control.ObservedStatus='ERROR'}
            DriveLetter {$script:control.Evidence.SystemVolume.DriveLetter='\\server\share'}
            MissingIdentity {$script:control.Evidence.PSObject.Properties.Remove('ScanId')}
        }
        $r=Invoke-WinSecBitLockerCriteriaFixture
        Assert-WinSecBitLockerCriteria ($null -eq $r.Configuration.Controls[0].Value -and
            @($r.Assessment.Findings|Where-Object Kind -CEQ CONFIGURATION_DEVIATION).Count -eq 0)
    }
}
Test-WinSecBitLockerCriteriaCase 'Foreign evidence is rejected without returning a partial assessment' {
    $script:control.Evidence.DeviceId='local:OTHER';$caught=$false
    try{$null=Invoke-WinSecBitLockerCriteriaFixture}catch{$caught=$true}
    Assert-WinSecBitLockerCriteria $caught
}
foreach($fault in @('Scope','Collection')) {
    Test-WinSecBitLockerCriteriaCase ('Public projection independently rejects lost BitLocker prerequisites even when criterion values are unchanged: '+$fault) {
        $script:control.Evidence.SystemVolume.ProtectionStatus='OFF'
        $r=Invoke-WinSecBitLockerCriteriaFixture
        $session=New-WinSecResultSession -DeviceId $script:context.DeviceId -ScanId $script:context.ScanId -CollectionMode LOCAL `
            -ScopeType CONTROL -ScopeKey WSA-SYS-002 -CatalogVersion '0.9.0' -ExpectedCheckIds @('WSA-SYS-002') `
            -ControlResults @($script:control) -EvaluationResults $r.Assessment.EvaluationResults -CriteriaSelections $r.Assessment.CriteriaSelections `
            -Findings $r.Assessment.Findings -ConfigurationAssessment $r.Configuration -ExecutionStatus COMPLETED `
            -StartedAtUTC '2026-10-22T00:00:00Z' -CompletedAtUTC '2026-10-22T00:01:00Z'
        $valid=ConvertTo-WinSecPublicScanResult $session
        Assert-WinSecBitLockerCriteria ($valid.ConfigurationAssessment.Controls[0].Value -eq 50 -and $valid.Findings.Count -eq 1)
        if($fault -ceq 'Scope'){$session.ControlResults[0].Evidence.Scope='ALL_VOLUMES'}else{$session.ControlResults[0].Evidence.CollectionSuccessful=$false}
        $caught=$false
        try {
            $null=ConvertTo-WinSecPublicScanResult $session
        }catch{$caught=$true}
        Assert-WinSecBitLockerCriteria $caught
    }
}
Test-WinSecBitLockerCriteriaCase 'Profile discovery is bounded and shares Windows contexts without inheriting Defender criteria' {
    $options=@(Get-WinSecAssessmentProfileOptions $root @('WSA-SYS-002'))
    Assert-WinSecBitLockerCriteria ($options.Count -eq 101 -and @($options|Where-Object {$_.Policies.Count -ne 1 -or $_.Policies[0].CheckId -cne 'WSA-SYS-002'}).Count -eq 0)
    foreach($name in @('WSA-W11-21H2-HOME-DEF-BASE','WSA-W11-24H2-PRO-DEF-BASE','WSA-W11-26H1-EDU-N-DEF-BASE','WSA-W11-26H2-PRO-WORKSTATION-N-DEF-BASE')) {
        $plan=Get-WinSecAssessmentProfilePlan $root @('WSA-SYS-002') $name
        $preview=@($options|Where-Object Profile -CEQ $name)[0]
        Assert-WinSecBitLockerCriteria ($preview.Policies[0].CatalogSha256 -ceq $plan.Preview.Policies[0].CatalogSha256 -and
            $plan.Catalogs['WSA-SYS-002'].Catalog.Criteria.Count -eq 2 -and
            @($plan.Catalogs['WSA-SYS-002'].Catalog.Criteria|Where-Object {$_.Applicability.Profile -cne $name}).Count -eq 0)
    }
    $combined=@(Get-WinSecAssessmentProfileOptions $root @('WSA-SYS-001','WSA-SYS-002'))
    Assert-WinSecBitLockerCriteria ($combined.Count -eq 101 -and @($combined|Where-Object {$_.Policies.Count -ne 2}).Count -eq 0)
}
Test-WinSecBitLockerCriteriaCase 'Invalid profile identifiers cannot become file paths' {
    foreach($name in @('../bitlocker','unknown','WSA-W11-24H2-PRO-BLK-BASE')) {
        $caught=$false;try{$null=Get-WinSecAssessmentCatalog $root WSA-SYS-002 -Profile $name}catch{$caught=$true}
        Assert-WinSecBitLockerCriteria $caught
    }
}
[Console]::WriteLine(('BitLocker criteria: {0} passed, {1} failed.' -f $script:passed,$script:failed))
if($script:failed){throw 'BitLocker criteria tests failed.'}
