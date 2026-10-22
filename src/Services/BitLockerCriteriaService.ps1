# Política BitLocker independiente; sólo datos/lecturas locales, sin recolector.
. (Join-Path $PSScriptRoot '../Core/BitLockerCriterionPrerequisites.ps1')
function Get-WinSecBitLockerCriteriaTemplate {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectRoot)
    $path=Join-Path $ProjectRoot 'config/criteria/bitlocker.json'
    Assert-WinSecDeviceRemovalPath -ProjectRoot $ProjectRoot -Path $path
    $file=Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if($file.PSIsContainer -or $file.Length -gt 1048576){throw 'Invalid BitLocker criteria file.'}
    $hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    $catalog=ConvertFrom-WinSecStoredJson (Get-Content -LiteralPath $path -Raw -Encoding UTF8)
    if($hash -cne (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -or
        $catalog.SchemaVersion -cne '1.0.0' -or $catalog.CatalogVersion -cne '1.0.0' -or
        $catalog.CheckId -cne 'WSA-SYS-002' -or $catalog.Criteria -isnot [array] -or $catalog.Criteria.Count -ne 2) {
        throw 'Invalid or changed BitLocker criteria.'
    }
    $ids=@('WSA-BLK-BASE-001','WSA-BLK-BASE-002')
    $paths=@('SystemVolume.ConversionStatus','SystemVolume.ProtectionStatus');$expected=@('FULLY_ENCRYPTED','ON')
    for($i=0;$i -lt 2;$i++) {
        $rule=$catalog.Criteria[$i]
        if($rule.Verification.ReviewedAtUTC -is [datetime]) {
            if($rule.Verification.ReviewedAtUTC.Kind -ne [DateTimeKind]::Utc){throw 'BitLocker review timestamp must be UTC.'}
            $rule.Verification.ReviewedAtUTC=$rule.Verification.ReviewedAtUTC.ToString('o')
        }
        if($rule.CriterionId -cne $ids[$i] -or $rule.Operator -cne 'Equals' -or $rule.EvidencePath -cne $paths[$i] -or
            $rule.ExpectedValue -isnot [string] -or $rule.ExpectedValue -cne $expected[$i] -or
            $rule.ActivationDependencies -isnot [array] -or $rule.ActivationDependencies.Count -ne 3 -or
            ($rule.ActivationDependencies -join '|') -cne 'bitlocker-os-volume|bitlocker-stable-conversion|bitlocker-valid-protection') {
            throw 'BitLocker criteria differ from the approved two-rule policy.'
        }
    }
    if(-not (Test-WinSecCriteriaCatalog $catalog).ReadyForScoring){throw 'BitLocker criteria are not approved for scoring.'}
    [pscustomobject]@{Catalog=$catalog;Sha256=$hash}
}

function Get-WinSecBitLockerCriteriaFingerprint {
    param([string]$TemplateSha256,[string]$MatrixSha256,[string]$Profile)
    if($TemplateSha256 -cnotmatch '\A[A-F0-9]{64}\z' -or $MatrixSha256 -cnotmatch '\A[A-F0-9]{64}\z' -or
        -not (Test-WinSecTargetIdentifier $Profile)){throw 'Invalid BitLocker profile fingerprint.'}
    $sha=[Security.Cryptography.SHA256]::Create()
    try {[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes("WSA-BITLOCKER-OS-1`n$TemplateSha256`n$MatrixSha256`n$Profile"))).Replace('-','')}
    finally {$sha.Dispose()}
}

function Get-WinSecBitLockerAssessmentCatalog {
    [CmdletBinding()]
    param([string]$ProjectRoot,[string]$Profile)
    $definitions=@(Get-WinSecInstalledAssessmentProfiles -ProjectRoot $ProjectRoot|Where-Object {$_.Profile -ceq $Profile})
    if($definitions.Count -ne 1){throw 'Unknown Windows context for BitLocker.'}
    $definition=$definitions[0];$snapshot=Get-WinSecBitLockerCriteriaTemplate $ProjectRoot
    $catalog=Copy-WinSecResultData $snapshot.Catalog
    $catalog.CatalogId=$Profile -creplace '-DEF-BASE\z','-BLK-BASE'
    if($catalog.CatalogId -ceq $Profile){throw 'Unsupported Windows context identifier for BitLocker.'}
    foreach($rule in $catalog.Criteria) {
        $rule.Applicability=[pscustomobject]@{OSFamily='Windows';OSRelease=$definition.OSRelease;Edition=$definition.Edition;Profile=$Profile}
    }
    if(-not (Test-WinSecCriteriaCatalog $catalog).ReadyForScoring){throw 'Invalid scoped BitLocker catalog.'}
    [pscustomobject]@{Catalog=$catalog;Sha256=(Get-WinSecBitLockerCriteriaFingerprint $snapshot.Sha256 $definition.MatrixSha256 $Profile)}
}

