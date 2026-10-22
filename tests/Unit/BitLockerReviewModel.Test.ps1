# Datos sintéticos en memoria; prohibidas consultas y escrituras de Windows.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ResultModel.ps1')
. (Join-Path $root 'src/Core/FrameworkMappingEngine.ps1')
$script:passed=0;$script:failed=0
function Get-CimInstance {throw 'Unexpected Windows query.'}
function Invoke-CimMethod {throw 'Unexpected Windows query.'}
function Assert-WinSecBitLockerReview {param([bool]$Value);if(-not $Value){throw 'BitLocker review assertion failed.'}}
function Test-WinSecBitLockerReview {
    param([string]$Name,[scriptblock]$Action)
    $script:collector=[pscustomobject]@{CheckId='WSA-SYS-002';DeviceId='local:review-blk';ScanId='review-blk-1';SectionKey='SystemSecurity';Status='INFORMATIONAL';
        Evidence=[pscustomobject]@{SchemaVersion='1.0.0';CheckId='WSA-SYS-002';DeviceId='local:review-blk';ScanId='review-blk-1';CollectionSuccessful=$true;
            Scope='OS_VOLUME_ONLY';SystemVolume=[pscustomobject]@{DriveLetter='D:';EncryptionMethod='XTS_AES_128';EncryptionPercentage=100;LockStatus='UNLOCKED';
                RecoveryPassword='PRIVATE-BLK-REVIEW'};VolumeId='PRIVATE-BLK-REVIEW'}}
    try{$null=& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}
    catch{$script:failed++;Write-Host ('[FAIL] '+$Name+' : '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}
}
foreach($algorithm in @('NONE','AES_128_WITH_DIFFUSER','AES_256_WITH_DIFFUSER','AES_128','AES_256','HARDWARE_ENCRYPTION','XTS_AES_128','XTS_AES_256','UNKNOWN')) {
    Test-WinSecBitLockerReview ('Allowed algorithm is informational: '+$algorithm) {
        $collector.Evidence.SystemVolume.EncryptionMethod=$algorithm
        $items=@(New-WinSecBitLockerReviewItems $collector)
        Assert-WinSecBitLockerReview ($items.Count -eq 3 -and $items[0].BitLockerSetting.Value -ceq $algorithm -and
            (ConvertTo-Json $items -Depth 12) -notmatch 'PRIVATE|DriveLetter|VolumeId|RecoveryPassword|PASS|FAIL|ScoringEligible')
    }
}
foreach($percent in @(0,[uint32]50,[long]100,$null,$true,'100',1.5,-1,101)) {
    Test-WinSecBitLockerReview 'Native progress accepts only bounded integers and never grades them' {
        $collector.Evidence.SystemVolume.EncryptionPercentage=$percent
        $expected=if($null -ne $percent -and $percent -isnot [bool] -and $percent -isnot [string] -and
            $percent -isnot [double] -and $percent -ge 0 -and $percent -le 100){[string]$percent}else{'UNKNOWN'}
        $items=@(New-WinSecBitLockerReviewItems $collector)
        Assert-WinSecBitLockerReview ($items[1].BitLockerSetting.Value -ceq $expected)
        $row=@(ConvertTo-WinSecBitLockerReviewRows @($items[1]))[0]
        Assert-WinSecBitLockerReview ($row.ConfigurationPercent -ceq 'N/A' -and $row.ConfigurationState -ceq 'REVIEW_ONLY' -and $row.EvaluationStatus -ceq 'NOT_EVALUATED')
    }
}
foreach($fault in @('ForeignDevice','ForeignScan','ForeignCheck','InvalidAlgorithm','WrongScope','WrongStatus','ExtraRawField','MixedExtension','InvalidId','BadProgress','NullSchema')) {
    Test-WinSecBitLockerReview ('Rejects malformed public observation: '+$fault) {
        $item=@(New-WinSecBitLockerReviewItems $collector)[0]
        switch($fault) {
            ForeignDevice {$item.DeviceId='local:other'};ForeignScan {$item.ScanId='other'};ForeignCheck {$item.CheckId='WSA-SYS-001'}
            InvalidAlgorithm {$item.BitLockerSetting.Value='PRIVATE'};WrongScope {$item.BitLockerSetting.Scope='ALL_VOLUMES'};WrongStatus {$item.Status='FAIL'}
            ExtraRawField {$item.BitLockerSetting|Add-Member RecoveryPassword 'PRIVATE'};MixedExtension {$item|Add-Member DefenderSetting ([pscustomobject]@{})}
            InvalidId {$item.ReviewId='wrong'};BadProgress {$item.BitLockerSetting.SettingId='EncryptionProgress';$item.BitLockerSetting.Value='010'}
            NullSchema {$item.BitLockerSetting.SchemaVersion=$null}
        }
        $caught=$false;try{$null=ConvertTo-WinSecBitLockerReviewItem $item $collector}catch{$caught=$true}
        Assert-WinSecBitLockerReview $caught
    }
}
foreach($fault in @('ForeignEvidence','WrongScope','WrongSchema','MissingDrive')) {
    Test-WinSecBitLockerReview ('Rejects untrusted collection without publishing partial observations: '+$fault) {
        switch($fault){ForeignEvidence {$collector.Evidence.ScanId='other'};WrongScope {$collector.Evidence.Scope='DATA'};
            WrongSchema {$collector.Evidence.SchemaVersion='0.0.0'};MissingDrive {$collector.Evidence.SystemVolume.DriveLetter=$null}}
        $published=New-Object 'System.Collections.Generic.List[object]';$caught=$false
        try{New-WinSecBitLockerReviewItems $collector|ForEach-Object {$published.Add($_)}}catch{$caught=$true}
        Assert-WinSecBitLockerReview ($caught -and $published.Count -eq 0)
    }
}
Test-WinSecBitLockerReview 'Error and unselected collectors create no observations' {
    foreach($state in @('ERROR','UNKNOWN','NOT_SELECTED')) {$collector.Status=$state;Assert-WinSecBitLockerReview (@(New-WinSecBitLockerReviewItems $collector).Count -eq 0)}
}
Test-WinSecBitLockerReview 'Projection copies allowlisted values and rejects forged observations against original collection' {
    $items=@(New-WinSecBitLockerReviewItems $collector)
    $session=New-WinSecResultSession -DeviceId $collector.DeviceId -ScanId $collector.ScanId -ControlResults @($collector) -ReviewItems $items
    $public=ConvertTo-WinSecPublicScanResult $session
    Assert-WinSecBitLockerReview ($public.ReviewItems.Count -eq 3 -and $null -eq $public.OverallScore -and
        (ConvertTo-Json $public -Depth 20) -notmatch 'PRIVATE|DriveLetter|VolumeId|RecoveryPassword|"Evidence"')
    $public.ReviewItems[0].BitLockerSetting.Value='XTS_AES_256'
    Assert-WinSecBitLockerReview ($session.ReviewItems[0].BitLockerSetting.Value -ceq 'XTS_AES_128')
    $session.ReviewItems[0].BitLockerSetting.Value='XTS_AES_256'
    $caught=$false;try{$null=ConvertTo-WinSecPublicScanResult $session}catch{$caught=$true};Assert-WinSecBitLockerReview $caught
}
Test-WinSecBitLockerReview 'Historical sessions without the optional observations retain their original contract' {
    $session=New-WinSecResultSession -DeviceId $collector.DeviceId -ScanId $collector.ScanId -ControlResults @($collector)
    Assert-WinSecBitLockerReview ((ConvertTo-WinSecPublicScanResult $session).ReviewItems.Count -eq 0)
}
Test-WinSecBitLockerReview 'Reviewed framework references correlate only with the two approved criteria' {
    foreach($id in @('cis-controls','nist-csf','mitre-attack')) {
        $fw=Get-Content -LiteralPath (Join-Path $root ('config/frameworks/'+$id+'.json')) -Raw|ConvertFrom-Json
        foreach($criterion in @('WSA-BLK-BASE-001','WSA-BLK-BASE-002')) {
            $refs=@(Get-WinSecFrameworkMappings -CheckId WSA-SYS-002 -CriterionId $criterion -Platform Windows -Frameworks @($fw))
            Assert-WinSecBitLockerReview ($refs.Count -eq 1)
            if($id -ceq 'mitre-attack'){Assert-WinSecBitLockerReview ($refs[0].ReferenceType -ceq 'Mitigation' -and $refs[0].ReferenceId -ceq 'M1041' -and -not $refs[0].TechniqueId)}
        }
        Assert-WinSecBitLockerReview (@(Get-WinSecFrameworkMappings -CheckId WSA-SYS-002 -CriterionId EncryptionMethod -Platform Windows -Frameworks @($fw)).Count -eq 0)
    }
}
foreach($fault in @('Undeclared','TechniqueSpoof','WrongId','WrongType','Disabled')) {
    Test-WinSecBitLockerReview ('Mitigation reference cannot masquerade as an attack technique: '+$fault) {
        $fw=Get-Content -LiteralPath (Join-Path $root 'config/frameworks/mitre-attack.json') -Raw|ConvertFrom-Json
        $ref=$fw.mappings[0].references[0]
        switch($fault){Undeclared {$fw.mitigations=@()};TechniqueSpoof {$ref|Add-Member techniqueId T1119};WrongId {$ref.id='M9999'};
            WrongType {$ref.type='Technique'};Disabled {$fw.mappingRules.includeMitigations=$false}}
        Assert-WinSecBitLockerReview (@(Get-WinSecFrameworkMappings -CheckId WSA-SYS-002 -CriterionId WSA-BLK-BASE-001 -Platform Windows -Frameworks @($fw)).Count -eq 0)
    }
}
Write-Host ('BitLocker review: {0} passed, {1} failed.' -f $script:passed,$script:failed)
if($script:failed){throw 'BitLocker review tests failed.'}
