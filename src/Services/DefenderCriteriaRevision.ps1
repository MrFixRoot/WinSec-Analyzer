# Approved additive catalog revision. Original profile files remain immutable.
function Get-WinSecDefenderCriteriaRevision {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectRoot)
    $path=Join-Path $ProjectRoot 'config/criteria/defender-additional.json'
    Assert-WinSecDeviceRemovalPath -ProjectRoot $ProjectRoot -Path $path
    $file=Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if($file.PSIsContainer -or $file.Length -gt 1048576){throw 'Invalid Defender criteria revision file.'}
    $hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    $catalog=ConvertFrom-WinSecStoredJson (Get-Content -LiteralPath $path -Raw -Encoding UTF8)
    if($hash -cne (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -or
        $catalog.SchemaVersion -cne '1.0.0' -or $catalog.CatalogVersion -cne '0.3.0' -or
        $catalog.Status -cne 'APPROVED' -or $catalog.CheckId -cne 'WSA-SYS-001' -or
        $catalog.EvaluationEnabled -isnot [bool] -or -not $catalog.EvaluationEnabled -or
        $catalog.ScoringEnabled -isnot [bool] -or -not $catalog.ScoringEnabled -or
        $catalog.DeviceChangesAllowed -isnot [bool] -or $catalog.DeviceChangesAllowed -or
        $catalog.Criteria -isnot [array] -or $catalog.Criteria.Count -ne 4){throw 'Unapproved or changed Defender criteria revision.'}
    foreach($rule in $catalog.Criteria) {
        if($rule.Verification.ReviewedAtUTC -is [datetime]){
            if($rule.Verification.ReviewedAtUTC.Kind -ne [DateTimeKind]::Utc){throw 'Defender review timestamp must be UTC.'}
            $rule.Verification.ReviewedAtUTC=$rule.Verification.ReviewedAtUTC.ToString('o')
        }
    }
    if(-not (Test-WinSecCriteriaCatalog $catalog).ReadyForScoring){throw 'Defender criteria revision is not ready.'}
    [pscustomobject]@{Catalog=$catalog;Sha256=$hash}
}

function Get-WinSecDefenderRevisionFingerprint {
    param([string]$BaseSha256,[string]$RevisionSha256,[string]$Profile)
    if($BaseSha256 -cnotmatch '\A[A-F0-9]{64}\z' -or $RevisionSha256 -cnotmatch '\A[A-F0-9]{64}\z' -or
        -not (Test-WinSecTargetIdentifier $Profile)){throw 'Invalid Defender revision fingerprint.'}
    $sha=[Security.Cryptography.SHA256]::Create()
    try{[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes("WSA-DEFENDER-REVISION-1`n$BaseSha256`n$RevisionSha256`n$Profile"))).Replace('-','')}
    finally{$sha.Dispose()}
}

function Add-WinSecDefenderCriteriaRevision {
    [CmdletBinding()]
    param([string]$ProjectRoot,[object]$Snapshot,[string]$Profile)
    $revision=Get-WinSecDefenderCriteriaRevision $ProjectRoot
    $catalog=Copy-WinSecResultData $Snapshot.Catalog
    $scope=Copy-WinSecResultData $catalog.Criteria[0].Applicability
    $rules=Copy-WinSecResultData $revision.Catalog.Criteria
    foreach($rule in $rules){$rule.Applicability=Copy-WinSecResultData $scope}
    $catalog.Criteria=@($catalog.Criteria)+@($rules)
    $catalog.CatalogVersion=$revision.Catalog.CatalogVersion
    $catalog.Description='Eight approved local Defender configuration criteria. ASR grading is limited to vulnerable signed driver abuse; other ASR rules are inventory only. Not an effectiveness or compliance certification.'
    $catalog.ApprovalReference='D-051: explicit owner approval of additional Defender configuration scoring and complete check tables.'
    if(-not (Test-WinSecCriteriaCatalog $catalog).ReadyForScoring){throw 'Invalid composed Defender revision.'}
    [pscustomobject]@{Catalog=$catalog;Sha256=(Get-WinSecDefenderRevisionFingerprint $Snapshot.Sha256 $revision.Sha256 $Profile)}
}
