# Local policy + pinned reference data. No native provider or online refresh.
. (Join-Path $PSScriptRoot 'WindowsUpdateReferenceService.ps1')
. (Join-Path $PSScriptRoot '../Core/WindowsUpdateCriterionEvidence.ps1')

function Get-WinSecWindowsUpdateCriteriaTemplate {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectRoot)
    $path=Join-Path $ProjectRoot 'config/criteria/windows-update.json'
    Assert-WinSecDeviceRemovalPath -ProjectRoot $ProjectRoot -Path $path
    $stream=$null;$sha=$null
    try {
        $current=[IO.Path]::GetFullPath($path);$isFile=$true
        while(-not [string]::IsNullOrEmpty($current)) {
            $item=Get-Item -LiteralPath $current -Force -ErrorAction Stop
            if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                ($isFile -and $item.PSIsContainer) -or (-not $isFile -and -not $item.PSIsContainer)) {throw 'Invalid criteria path.'}
            $isFile=$false;$current=[IO.Path]::GetDirectoryName($current)
        }
        $stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        if($stream.Length -lt 2 -or $stream.Length -gt 1048576){throw 'Invalid criteria size.'}
        $bytes=New-Object byte[] ([int]$stream.Length);$offset=0
        while($offset -lt $bytes.Length) {
            $count=$stream.Read($bytes,$offset,$bytes.Length-$offset)
            if($count -le 0){throw 'Incomplete criteria snapshot.'};$offset+=$count
        }
        $catalog=ConvertFrom-WinSecStoredJson ((New-Object Text.UTF8Encoding($false,$true)).GetString($bytes))
        foreach($rule in @($catalog.Criteria)) {
            if($rule.Verification.ReviewedAtUTC -is [datetime] -and $rule.Verification.ReviewedAtUTC.Kind -eq [DateTimeKind]::Utc) {
                $rule.Verification.ReviewedAtUTC=$rule.Verification.ReviewedAtUTC.ToString('o')
            }
        }
        $sha=[Security.Cryptography.SHA256]::Create()
        $hash=[BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','')
        if($catalog.SchemaVersion -cne '1.0.0' -or $catalog.CatalogVersion -cne '1.1.0' -or
            $catalog.CheckId -cne 'WSA-SYS-003' -or $catalog.Criteria -isnot [array] -or $catalog.Criteria.Count -ne 3 -or
            -not (Test-WinSecCriteriaCatalog $catalog).ReadyForScoring){throw 'Unapproved Windows Update policy.'}
        for($i=0;$i -lt 3;$i++) {
            $rule=$catalog.Criteria[$i]
            if($rule.CriterionId -cne ('WSA-WUP-BASE-00'+($i+1)) -or $rule.Operator -cne 'Equals' -or
                $rule.EvidencePath -cne @('WindowsUpdate.Automation','WindowsUpdate.SecurityBaseline','WindowsUpdate.SecuritySupport')[$i] -or
                $rule.ExpectedValue -isnot [bool] -or -not $rule.ExpectedValue -or
                (Get-WinSecCriterionWeight $rule) -ne @(15,35,50)[$i] -or
                $rule.ActivationDependencies -isnot [array] -or $rule.ActivationDependencies.Count -ne 1 -or
                $rule.ActivationDependencies[0] -cne 'windows-update-local-evidence' -or
                $null -ne $rule.PSObject.Properties['WindowsUpdateReference']){throw 'Windows Update criteria differ from approved policy.'}
        }
        [pscustomobject]@{Catalog=$catalog;Sha256=$hash}
    } catch {throw 'Windows Update criteria could not be validated.'}
    finally {if($null -ne $sha){$sha.Dispose()};if($null -ne $stream){$stream.Dispose()}}
}

function Get-WinSecWindowsUpdateCriteriaFingerprint {
    param([string]$TemplateSha256,[string]$MatrixSha256,[string]$ReferenceSha256,[string]$ContentSha256,[string]$Profile)
    foreach($hash in @($TemplateSha256,$MatrixSha256,$ReferenceSha256,$ContentSha256)) {
        if($hash -cnotmatch '\A[A-F0-9]{64}\z'){throw 'Invalid Windows Update policy fingerprint.'}
    }
    if(-not (Test-WinSecTargetIdentifier $Profile)){throw 'Invalid Windows Update profile.'}
    $sha=[Security.Cryptography.SHA256]::Create()
    try {[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes("WSA-WINDOWS-UPDATE-1`n$TemplateSha256`n$MatrixSha256`n$ReferenceSha256`n$ContentSha256`n$Profile"))).Replace('-','')}
    finally {$sha.Dispose()}
}

function Get-WinSecWindowsUpdateAssessmentCatalog {
    [CmdletBinding()]
    param([string]$ProjectRoot,[string]$Profile)
    $definitions=@(Get-WinSecInstalledAssessmentProfiles $ProjectRoot|Where-Object {$_.Profile -ceq $Profile})
    if($definitions.Count -ne 1){throw 'Unknown Windows context for Windows Update.'}
    $definition=$definitions[0];$template=Get-WinSecWindowsUpdateCriteriaTemplate $ProjectRoot
    $reference=Get-WinSecWindowsUpdateReferenceCatalog $ProjectRoot
    $content=Get-WinSecWindowsUpdateReferenceFingerprint $reference.Catalog
    $catalog=Copy-WinSecResultData $template.Catalog
    $catalog.CatalogId=$Profile -creplace '-DEF-BASE\z','-WUP-BASE'
    if($catalog.CatalogId -ceq $Profile){throw 'Unsupported Windows Update context identifier.'}
    $catalog.CatalogVersion=$catalog.CatalogVersion+'+'+$reference.Catalog.CatalogVersion
    foreach($rule in $catalog.Criteria) {
        $rule.Applicability=[pscustomobject]@{OSFamily='Windows';OSRelease=$definition.OSRelease;Edition=$definition.Edition;Profile=$Profile}
        $rule.Source.Version=$catalog.CatalogVersion
        $rule|Add-Member WindowsUpdateReference (Copy-WinSecResultData ([pscustomobject]@{
            Catalog=$reference.Catalog;Sha256=$reference.Sha256;ContentSha256=$content}))
    }
    if(-not (Test-WinSecCriteriaCatalog $catalog).ReadyForScoring){throw 'Invalid scoped Windows Update criteria.'}
    [pscustomobject]@{Catalog=$catalog;Sha256=(Get-WinSecWindowsUpdateCriteriaFingerprint $template.Sha256 $definition.MatrixSha256 $reference.Sha256 $content $Profile)}
}
