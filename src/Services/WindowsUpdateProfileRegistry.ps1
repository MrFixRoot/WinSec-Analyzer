# Variantes documentadas para seleccionar contexto. Sin consultas ni autorizaciones.
# Este catalogo solo presenta diferencias; nunca modifica criterios o resultados.
function Get-WinSecWindowsUpdateVariantCatalog {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectRoot)
    $path=Join-Path $ProjectRoot 'config/criteria/profiles/windows-update-variants.json'
    Assert-WinSecDeviceRemovalPath -ProjectRoot $ProjectRoot -Path $path
    $stream=$null;$sha=$null
    try {
        $current=[IO.Path]::GetFullPath($path);$leaf=$true
        while($current) {
            $item=Get-Item -LiteralPath $current -Force -ErrorAction Stop
            if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                ($leaf -and $item.PSIsContainer) -or (-not $leaf -and -not $item.PSIsContainer)){throw 'Invalid variant path.'}
            $leaf=$false;$current=[IO.Path]::GetDirectoryName($current)
        }
        $stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        if($stream.Length -lt 2 -or $stream.Length -gt 65536){throw 'Invalid variant catalog size.'}
        $bytes=New-Object byte[] ([int]$stream.Length);$offset=0
        while($offset -lt $bytes.Length) {
            $count=$stream.Read($bytes,$offset,$bytes.Length-$offset)
            if($count -le 0){throw 'Incomplete variant catalog.'};$offset+=$count
        }
        $catalog=ConvertFrom-WinSecStoredJson ((New-Object Text.UTF8Encoding($false,$true)).GetString($bytes))
        $catalog=Assert-WinSecWindowsUpdateVariantCatalog $catalog
        $sha=[Security.Cryptography.SHA256]::Create()
        $hash=[BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','')
        [pscustomobject]@{Catalog=$catalog;Sha256=$hash}
    } catch {throw 'Windows Update profile variants could not be validated.'}
    finally {if($null -ne $sha){$sha.Dispose()};if($null -ne $stream){$stream.Dispose()}}
}

function Assert-WinSecWindowsUpdateVariantCatalog {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Catalog)
    $copy=Copy-WinSecResultData $Catalog
    Assert-WinSecConfigurationFields $copy @('SchemaVersion','CatalogVersion','Purpose','ReviewedOn','Sources','EditionGroups','ReleaseGroups')
    foreach($field in @('SchemaVersion','CatalogVersion','Purpose','ReviewedOn')) {
        if($copy.$field -isnot [string]){throw 'Invalid variant catalog metadata type.'}
    }
    if($copy.SchemaVersion -cne '1.0.0' -or $copy.CatalogVersion -cne '1.0.0' -or
        $copy.Purpose -cne 'PROFILE_PRESENTATION_ONLY' -or $copy.ReviewedOn -cne '2026-10-26' -or
        $copy.Sources -isnot [array] -or $copy.Sources.Count -ne 5 -or
        $copy.EditionGroups -isnot [array] -or $copy.EditionGroups.Count -ne 5 -or
        $copy.ReleaseGroups -isnot [array] -or $copy.ReleaseGroups.Count -ne 2){throw 'Unsupported variant catalog.'}
    $sources=@('windows/deployment/update/windows-update-client-policies',
        'windows/deployment/update/configure-policies-different-device-types',
        'windows/deployment/update/wufb-compliancedeadlines',
        'windows/client-management/mdm/policy-csp-update','windows/release-health/windows11-release-information')
    for($i=0;$i -lt $sources.Count;$i++) {
        if($copy.Sources[$i] -isnot [string] -or $copy.Sources[$i] -cne ('https://learn.microsoft.com/en-us/'+$sources[$i])){throw 'Unreviewed variant source.'}
    }
    $expected=@{
        HOME=@('98,99,100,101','GAC','CONSUMER','HOME_PRO')
        PRO=@('48,49,161,162,164,165','GAC','MANAGED','HOME_PRO')
        ENTERPRISE_EDUCATION=@('4,27,121,122','GAC','MANAGED','ENTERPRISE_EDUCATION')
        ENTERPRISE_LTSC=@('125,126','LTSC','MANAGED','ENTERPRISE_LTSC')
        IOT_LTSC=@('191','LTSC','MANAGED','IOT_LTSC')
    }
    $seen=@{}
    foreach($group in $copy.EditionGroups) {
        Assert-WinSecConfigurationFields $group @('Key','Label','Skus','Channel','PolicySurface','SupportModel')
        foreach($field in @('Key','Label','Channel','PolicySurface','SupportModel')) {
            if($group.$field -isnot [string]){throw 'Invalid variant edition metadata type.'}
        }
        if($group.Key -isnot [string] -or -not $expected.ContainsKey($group.Key) -or $seen.ContainsKey($group.Key) -or
            $group.Skus -isnot [array] -or $group.Label -isnot [string] -or [string]::IsNullOrWhiteSpace($group.Label) -or
            $group.Label.Length -gt 80 -or $group.Label -match '[\p{C}]'){throw 'Invalid variant edition group.'}
        foreach($sku in $group.Skus){if(($sku -isnot [int] -and $sku -isnot [long]) -or $sku -le 0){throw 'Invalid variant SKU.'}}
        $fields=@(($group.Skus -join ','),$group.Channel,$group.PolicySurface,$group.SupportModel)
        if(($fields -join '|') -cne ($expected[$group.Key] -join '|')){throw 'Unreviewed variant edition mapping.'}
        $seen[$group.Key]=$true
    }
    $seen=@{}
    foreach($group in $copy.ReleaseGroups) {
        Assert-WinSecConfigurationFields $group @('Key','Releases','Label')
        if($group.Key -isnot [string] -or $group.Key -cnotin @('LEGACY','SPLIT') -or $seen.ContainsKey($group.Key) -or
            $group.Releases -isnot [array] -or $group.Label -isnot [string] -or [string]::IsNullOrWhiteSpace($group.Label) -or
            $group.Label.Length -gt 80 -or $group.Label -match '[\p{C}]'){throw 'Invalid variant release group.'}
        $releases=if($group.Key -ceq 'LEGACY'){'21H2'}else{'22H2|23H2|24H2|25H2|26H1|26H2'}
        foreach($name in $group.Releases){if($name -isnot [string]){throw 'Invalid variant release.'}}
        if(($group.Releases -join '|') -cne $releases){throw 'Unreviewed variant release mapping.'}
        $seen[$group.Key]=$true
    }
    return $copy
}

function Get-WinSecWindowsUpdateProfileVariant {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Catalog,[Parameter(Mandatory)][object]$Matrix,
        [Parameter(Mandatory)][object]$Policy)
    # Policy is a previously validated profile preview; the matrix is its reader's
    # validated result. No caller-provided variant or friendly label grants rights.
    $Catalog=Assert-WinSecWindowsUpdateVariantCatalog $Catalog
    $Policy=Copy-WinSecResultData $Policy
    if($Policy.CheckId -cne 'WSA-SYS-003' -or $Policy.OSFamily -cne 'Windows' -or
        $Policy.OSRelease -isnot [string] -or $Policy.OSRelease -cnotmatch '\AWindows 11 10\.0\.([0-9]+)\z') {
        throw 'Invalid Windows Update variant context.'
    }
    $build=[long]$Matches[1]
    $release=@($Matrix.Releases|Where-Object Build -EQ $build)
    $edition=@($Matrix.Editions|Where-Object {('SKU:'+$_.Sku) -ceq $Policy.Edition})
    if($release.Count -ne 1 -or $edition.Count -ne 1 -or $edition[0].Releases -cnotcontains $release[0].Name){throw 'Unknown Windows Update context.'}
    $group=@($Catalog.EditionGroups|Where-Object {$_.Skus -contains $edition[0].Sku})
    $model=@($Catalog.ReleaseGroups|Where-Object {$_.Releases -ccontains $release[0].Name})
    if($group.Count -ne 1 -or $model.Count -ne 1){throw 'Ambiguous Windows Update variant.'}
    $deadline=if($group[0].PolicySurface -ceq 'CONSUMER'){'Consumer policy source required'}else{$model[0].Label}
    [pscustomobject]@{Id=('WSA-WUP-'+$group[0].Key+'-'+$model[0].Key);Label=$group[0].Label;
        Channel=$group[0].Channel;PolicySurface=$group[0].PolicySurface;SupportModel=$group[0].SupportModel;DeadlineModel=$deadline}
}
