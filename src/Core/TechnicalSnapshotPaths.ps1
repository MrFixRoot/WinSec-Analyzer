# Stage 1: read-only path planning. No directories, artifacts or execution permissions are created.
. (Join-Path $PSScriptRoot 'TechnicalSnapshotContract.ps1')

function Get-WinSecSnapshotDeviceKey {
    [CmdletBinding()]param([Parameter(Mandatory)][string]$DeviceId)
    if($DeviceId -cnotmatch '\Alocal:hw1-[a-f0-9]{64}\z'){throw 'Invalid storage device identity.'}
    $sha=[Security.Cryptography.SHA256]::Create()
    try {return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($DeviceId)))).Replace('-','').ToLowerInvariant()}
    finally {$sha.Dispose()}
}

function Assert-WinSecSnapshotStoragePath {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectRoot,[Parameter(Mandatory)][string]$RelativePath)
    # Deliberately Windows-local; UNC, provider paths, drive-relative names and ADS are excluded.
    if($ProjectRoot -notmatch '\A[A-Za-z]:[\\/]' -or $ProjectRoot -match '[\p{C}]' -or
        $ProjectRoot.Substring(2) -match ':' -or $ProjectRoot -match '(?:\A|[\\/])\.{1,2}(?:[\\/]|\z)') {throw 'Invalid project root.'}
    foreach($part in $ProjectRoot.Substring(3).Split([char[]]'\/',[StringSplitOptions]::RemoveEmptyEntries)){
        if($part -match '[. ]\z|[<>"|?*]'){throw 'Ambiguous project root.'}
    }
    $root=[IO.Path]::GetFullPath($ProjectRoot).TrimEnd([char[]]'\/')
    if($root.Length -le 3 -or -not [IO.Directory]::Exists($root)){throw 'Project root must be an existing local directory.'}
    if($RelativePath -notmatch '\A[A-Za-z0-9_.-]+(?:[\\/][A-Za-z0-9_.-]+)+\z'){throw 'Invalid artifact path.'}
    foreach($part in $RelativePath.Split([char[]]'\/')){
        if($part -in @('.','..') -or $part -match '[. ]\z|\A(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|\z)'){throw 'Unsafe artifact segment.'}
    }
    $path=[IO.Path]::GetFullPath((Join-Path $root $RelativePath))
    if(-not $path.StartsWith($root+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase) -or
        $path.Length -gt (Get-WinSecSnapshotSpecification).MaxPathChars){throw 'Artifact path escapes root or exceeds budget.'}
    # Inspect all existing ancestors, including ancestors of the installation. This is a preflight,
    # not a race-free publication guarantee: the future writer must recheck on open and commit.
    $cursor=$path
    while($cursor){
        $item=$null
        try {$item=Get-Item -LiteralPath $cursor -Force -ErrorAction Stop}
        catch {if($_.CategoryInfo.Category -ne [Management.Automation.ErrorCategory]::ObjectNotFound){throw 'Cannot inspect storage path.'}}
        if($null -ne $item){
            if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Reparse point in storage path.'}
            if($cursor -ceq $path){throw 'Artifact path already exists.'}
            if(-not $item.PSIsContainer){throw 'File occupies artifact parent.'}
        }
        $parent=[IO.Path]::GetDirectoryName($cursor)
        if($parent -ceq $cursor){break};$cursor=$parent
    }
    return $path
}

function Get-WinSecTechnicalSnapshotPaths {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectRoot,[Parameter(Mandatory)][object]$Identity,
        [Parameter(Mandatory)][string]$CollectedAtUTC)
    Assert-WinSecSnapshotIdentity $Identity
    $control=Get-WinSecSnapshotControl $Identity.CheckId
    $date=ConvertTo-WinSecSnapshotUtc $CollectedAtUTC
    $key=Get-WinSecSnapshotDeviceKey $Identity.DeviceId
    $stem=$date.ToString('yyyyMMddTHHmmssfffffffZ',[Globalization.CultureInfo]::InvariantCulture)+$control.ControlName+'_'+$Identity.SnapshotId
    $relative=$key+'/'+$control.SectionKey+'/'+$stem
    [pscustomobject]@{
        LayoutVersion='1.0.0';DeviceKey=$key;SnapshotId=$Identity.SnapshotId
        JsonPath=Assert-WinSecSnapshotStoragePath $ProjectRoot ('scans/'+$relative+'.json')
        MarkdownPath=Assert-WinSecSnapshotStoragePath $ProjectRoot ('reports/'+$relative+'.md')
    }
}

function Get-WinSecSnapshotFindingsPath {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectRoot,[Parameter(Mandatory)][string]$DeviceId,
        [Parameter(Mandatory)][ValidateSet('CONTROL','SECTION')][string]$ScopeType,
        [Parameter(Mandatory)][string]$ScopeKey,[Parameter(Mandatory)][string]$AnalysisId,
        [Parameter(Mandatory)][string]$GeneratedAtUTC)
    if($AnalysisId -cnotmatch '\A[a-f0-9]{32}\z'){throw 'Invalid Findings analysis identity.'}
    if($ScopeType -ceq 'CONTROL'){$c=Get-WinSecSnapshotControl $ScopeKey;$section=$c.SectionKey;$name=$c.ControlName}
    elseif($ScopeType -ceq 'SECTION' -and $ScopeKey -cin @('SystemSecurity','NetworkSecurity','IdentityAccess','LoggingAuditing','ServicesHardening')){$section=$ScopeKey;$name=$ScopeKey}
    else {throw 'Invalid Findings scope.'}
    $key=Get-WinSecSnapshotDeviceKey $DeviceId
    $date=ConvertTo-WinSecSnapshotUtc $GeneratedAtUTC
    $stem=$date.ToString('yyyyMMddTHHmmssfffffffZ',[Globalization.CultureInfo]::InvariantCulture)+$name+'_'+$AnalysisId
    return Assert-WinSecSnapshotStoragePath $ProjectRoot ('reports/'+$key+'/'+$section+'/findings/'+$stem+'.md')
}
