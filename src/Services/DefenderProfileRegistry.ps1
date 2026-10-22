# Matriz de aplicabilidad declarada; sin consultas Windows ni escrituras.
function Get-WinSecDefenderProfileMatrix {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectRoot)
    $path = Join-Path $ProjectRoot 'config/criteria/profiles/defender-windows11-matrix.json'
    Assert-WinSecDeviceRemovalPath -ProjectRoot $ProjectRoot -Path $path
    $file = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if ($file.PSIsContainer -or $file.Length -gt 1048576) { throw 'Invalid Defender profile matrix file.' }
    $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    $matrix = ConvertFrom-WinSecStoredJson (Get-Content -LiteralPath $path -Raw -Encoding UTF8)
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne $hash) { throw 'Profile matrix changed while reading.' }
    Assert-WinSecConfigurationFields $matrix @('SchemaVersion','CatalogVersion','Status','ApprovalReference','ReviewedAtUTC','TemplateSha256','Sources','Releases','Editions')
    if ($matrix.ReviewedAtUTC -is [datetime] -and $matrix.ReviewedAtUTC.Kind -eq [DateTimeKind]::Utc) {
        $matrix.ReviewedAtUTC = $matrix.ReviewedAtUTC.ToString('o')
    }
    foreach ($field in @('SchemaVersion','CatalogVersion','Status','ApprovalReference','ReviewedAtUTC','TemplateSha256')) {
        if ($matrix.$field -isnot [string] -or [string]::IsNullOrWhiteSpace($matrix.$field) -or
            $matrix.$field.Length -gt 512 -or $matrix.$field -match '[\p{C}]') { throw 'Invalid profile matrix metadata.' }
    }
    $date = [datetimeoffset]::MinValue
    if ($matrix.SchemaVersion -cne '1.0.0' -or $matrix.CatalogVersion -cne '0.2.0' -or $matrix.Status -cne 'APPROVED' -or
        $matrix.TemplateSha256 -cnotmatch '\A[A-F0-9]{64}\z' -or
        -not [datetimeoffset]::TryParse($matrix.ReviewedAtUTC,[ref]$date) -or $date.Offset -ne [timespan]::Zero -or
        $matrix.Releases -isnot [array] -or $matrix.Releases.Count -eq 0 -or $matrix.Releases.Count -gt 16 -or
        $matrix.Editions -isnot [array] -or $matrix.Editions.Count -eq 0 -or $matrix.Editions.Count -gt 32 -or
        $matrix.Sources -isnot [array] -or $matrix.Sources.Count -eq 0 -or $matrix.Sources.Count -gt 16) {
        throw 'Unsupported or unapproved Defender profile matrix.'
    }
    foreach ($source in $matrix.Sources) {
        if ($source -isnot [string] -or $source.Length -gt 1024 -or
            $source -cnotmatch '\Ahttps://learn\.microsoft\.com/[A-Za-z0-9/_-]+\z') { throw 'Invalid profile matrix source.' }
    }
    $releases = @{}; $builds = @{}
    foreach ($release in $matrix.Releases) {
        Assert-WinSecConfigurationFields $release @('Name','Build')
        if ($release.Name -isnot [string] -or $release.Name -cnotmatch '\A2[1-6]H[12]\z' -or
            ($release.Build -isnot [int] -and $release.Build -isnot [long]) -or $release.Build -lt 22000 -or $release.Build -gt 99999 -or
            $releases.ContainsKey($release.Name) -or $builds.ContainsKey([string]$release.Build)) { throw 'Invalid or duplicate Windows release.' }
        $releases[$release.Name] = $release.Build; $builds[[string]$release.Build] = $true
    }
    $keys = @{}; $skus = @{}; $count = 0
    foreach ($edition in $matrix.Editions) {
        Assert-WinSecConfigurationFields $edition @('Key','Name','Sku','Releases')
        if ($edition.Key -isnot [string] -or $edition.Key -cnotmatch '\A[A-Z][A-Z0-9-]{0,39}\z' -or
            $edition.Name -isnot [string] -or [string]::IsNullOrWhiteSpace($edition.Name) -or $edition.Name.Length -gt 128 -or $edition.Name -match '[\p{C}]' -or
            ($edition.Sku -isnot [int] -and $edition.Sku -isnot [long]) -or $edition.Sku -le 0 -or $edition.Sku -gt 65535 -or
            $keys.ContainsKey($edition.Key) -or $skus.ContainsKey([string]$edition.Sku) -or
            $edition.Releases -isnot [array] -or $edition.Releases.Count -eq 0) { throw 'Invalid or duplicate Windows edition.' }
        $keys[$edition.Key] = $true; $skus[[string]$edition.Sku] = $true; $seen = @{}
        foreach ($name in $edition.Releases) {
            if ($name -isnot [string] -or -not $releases.ContainsKey($name) -or $seen.ContainsKey($name)) { throw 'Invalid edition release selection.' }
            if ($edition.Key -match 'LTSC' -and ($name -cne '24H2' -or $releases[$name] -ne 26100)) { throw 'Unreviewed Windows LTSC release.' }
            $seen[$name] = $true; $count++
        }
    }
    if ($count -gt 128) { throw 'Too many installed Defender profiles.' }
    [pscustomobject]@{Matrix=$matrix;Sha256=$hash}
}

function Get-WinSecDefenderProfileDefinitions {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectRoot)
    $snapshot = Get-WinSecDefenderProfileMatrix $ProjectRoot
    $matrix = $snapshot.Matrix
    $rows = @(foreach ($edition in $matrix.Editions) {
        foreach ($name in $edition.Releases) {
            $release = @($matrix.Releases | Where-Object Name -CEQ $name)[0]
            $profile = 'WSA-W11-{0}-{1}-DEF-BASE' -f $name,$edition.Key
            $file = switch ($profile) {
                'WSA-W11-24H2-PRO-DEF-BASE' { 'defender-win11-24h2-pro.json' }
                'WSA-W11-25H2-ENT-DEF-BASE' { 'defender-win11-25h2-enterprise.json' }
                default { $null }
            }
            [pscustomobject]@{Profile=$profile;FileName=$file;OSRelease=('Windows 11 10.0.'+$release.Build);
                Edition=('SKU:'+$edition.Sku);MatrixSha256=$snapshot.Sha256;TemplateSha256=$matrix.TemplateSha256;
                CatalogVersion=$matrix.CatalogVersion;ReviewedAtUTC=$matrix.ReviewedAtUTC;ApprovalReference=$matrix.ApprovalReference}
        }
    })
    # Keep the original two choices first, preserving existing keyboard flows.
    @($rows | Where-Object {$null -ne $_.FileName})
    @($rows | Where-Object {$null -eq $_.FileName})
}

function Get-WinSecDefenderProfileFingerprint {
    [CmdletBinding()]
    param([string]$MatrixSha256,[string]$TemplateSha256,[string]$Profile)
    if ($MatrixSha256 -cnotmatch '\A[A-F0-9]{64}\z' -or $TemplateSha256 -cnotmatch '\A[A-F0-9]{64}\z' -or
        -not (Test-WinSecTargetIdentifier $Profile)) { throw 'Invalid profile composition fingerprint.' }
    $text = "WSA-DEFENDER-MATRIX-1`n$MatrixSha256`n$TemplateSha256`n$Profile"
    $sha = [Security.Cryptography.SHA256]::Create()
    try { [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($text))).Replace('-','') }
    finally { $sha.Dispose() }
}

function Get-WinSecExpandedDefenderCatalog {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectRoot,[Parameter(Mandatory)][string]$Profile)
    $definitions = @(Get-WinSecDefenderProfileDefinitions $ProjectRoot | Where-Object Profile -CEQ $Profile)
    if ($definitions.Count -ne 1 -or $null -ne $definitions[0].FileName) { throw 'Unknown expanded Defender profile.' }
    $definition = $definitions[0]
    $template = Get-WinSecAssessmentCatalog $ProjectRoot 'WSA-SYS-001' -Profile 'WSA-W11-24H2-PRO-DEF-BASE'
    if ($template.Sha256 -cne $definition.TemplateSha256) { throw 'Defender profile template changed without review.' }
    $catalog = Copy-WinSecResultData $template.Catalog
    $catalog.CatalogId = $Profile
    $catalog.CatalogVersion = $definition.CatalogVersion
    $catalog.ApprovalReference = $definition.ApprovalReference
    foreach ($rule in $catalog.Criteria) {
        $rule.Applicability.Profile = $Profile
        $rule.Applicability.OSRelease = $definition.OSRelease
        $rule.Applicability.Edition = $definition.Edition
        $rule.Source.Version = $definition.CatalogVersion
        $rule.Verification.ReviewedAtUTC = $definition.ReviewedAtUTC
        $rule.Verification.ReviewedBy = 'Project owner; explicit Windows 11 scope extension D-045'
    }
    if (-not (Test-WinSecCriteriaCatalog $catalog).ReadyForEvaluation) { throw 'Invalid expanded Defender criteria.' }
    $path = Join-Path $ProjectRoot 'config/criteria/profiles/defender-windows11-matrix.json'
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne $definition.MatrixSha256) { throw 'Profile matrix changed while expanding.' }
    # Composition fingerprint v1: exact reviewed matrix bytes, template bytes and
    # selected profile. ASCII framing makes this stable in PowerShell 5.1 / 7.x.
    $hash = Get-WinSecDefenderProfileFingerprint $definition.MatrixSha256 $template.Sha256 $Profile
    [pscustomobject]@{Catalog=$catalog;Sha256=$hash}
}
