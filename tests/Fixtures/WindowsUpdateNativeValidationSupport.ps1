# Helpers del validador explicito; importar no consulta Windows ni escribe datos.
function Assert-WinSecWindowsUpdateValidationPath {
    param([string]$ProjectRoot,[string]$Path)
    $root=[IO.Path]::GetFullPath($ProjectRoot).TrimEnd('\','/')
    $full=[IO.Path]::GetFullPath($Path)
    if(-not $full.StartsWith($root+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) {
        throw 'Validation path must belong to this installation.'
    }
    $current=$full
    while($current) {
        $item=Get-Item -LiteralPath $current -Force -ErrorAction Stop
        if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Linked validation paths are prohibited.'}
        $current=[IO.Path]::GetDirectoryName($current)
    }
}

function Get-WinSecWindowsUpdateValidationFiles {
    param([string]$ProjectRoot)
    $paths=New-Object 'System.Collections.Generic.List[string]'
    $directories=New-Object 'System.Collections.Generic.Queue[string]'
    foreach($name in @('src','config')){$directories.Enqueue((Join-Path $ProjectRoot $name))}
    while($directories.Count) {
        $directory=$directories.Dequeue()
        Assert-WinSecWindowsUpdateValidationPath $ProjectRoot $directory
        foreach($item in @(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop)) {
            if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Linked validation dependencies are prohibited.'}
            if($item.PSIsContainer){$directories.Enqueue($item.FullName)}
            elseif($item.Extension -cin @('.ps1','.json')) {
                $paths.Add($item.FullName.Substring($ProjectRoot.TrimEnd('\','/').Length+1).Replace('\','/'))
            } elseif($item.Name -cne '.gitkeep') {throw 'Unreviewed validation dependency type.'}
            if($directories.Count+$paths.Count -gt 512){throw 'Validation dependency set is too large.'}
        }
    }
    $paths.Add('tests/Integration/Invoke-WindowsUpdateNativeValidation.ps1')
    $paths.Add('tests/Fixtures/WindowsUpdateNativeValidationSupport.ps1')
    $paths.Add('tests/Fixtures/FrameworkNativeValidationSupport.ps1')
    $paths.Sort([StringComparer]::Ordinal)
    return ,$paths.ToArray()
}

function Get-WinSecWindowsUpdateValidationHash {
    param([string]$Text)
    $sha=[Security.Cryptography.SHA256]::Create()
    try {[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text))).Replace('-','')}
    finally {$sha.Dispose()}
}

function Open-WinSecWindowsUpdateValidationSnapshot {
    param([string]$ProjectRoot)
    $streams=New-Object 'System.Collections.Generic.List[object]'
    $records=New-Object 'System.Collections.Generic.List[object]'
    $total=0L
    try {
        foreach($relative in (Get-WinSecWindowsUpdateValidationFiles $ProjectRoot)) {
            $path=Join-Path $ProjectRoot $relative
            Assert-WinSecWindowsUpdateValidationPath $ProjectRoot $path
            $stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
            $streams.Add($stream);$total+=$stream.Length
            # Empty pending PS1 stubs are included by hash, never executed here.
            if($stream.Length -gt 4194304 -or $total -gt 16777216){throw 'Invalid dependency snapshot size.'}
            $sha=[Security.Cryptography.SHA256]::Create()
            try {$hash=[BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-','')}
            finally {$sha.Dispose()}
            $records.Add([pscustomobject][ordered]@{Path=$relative;Length=$stream.Length;Sha256=$hash})
        }
        $json=ConvertTo-Json -InputObject $records.ToArray() -Depth 4 -Compress
        return [pscustomobject]@{Streams=$streams;Files=$records.ToArray();Sha256=(Get-WinSecWindowsUpdateValidationHash $json)}
    } catch {foreach($stream in $streams){$stream.Dispose()};throw 'Validation dependencies could not be frozen.'}
}

function Assert-WinSecWindowsUpdateValidationSnapshot {
    param([string]$ProjectRoot,[object]$Snapshot)
    $current=Open-WinSecWindowsUpdateValidationSnapshot $ProjectRoot
    try {if($current.Sha256 -cne $Snapshot.Sha256){throw 'Validation dependencies changed; prepare a new request.'}}
    finally {foreach($stream in $current.Streams){$stream.Dispose()}}
}

function Get-WinSecWindowsUpdateNativeUtcNow {return [datetime]::UtcNow}

function Get-WinSecWindowsUpdateNativeElevation {
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    try {return ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)}
    finally {$identity.Dispose()}
}

function Get-WinSecWindowsUpdateNativeIssues {
    param([object]$Evidence)
    $allowed=@('OS_QUERY_FAILED','OS_TELEMETRY_INVALID','OS_VERSION_KEY_MISSING','OS_VERSION_BUILD_MISMATCH',
        'OS_VERSION_KEY_READ_FAILED','OS_VERSION_KEY_CLOSE_FAILED','UPDATE_SERVICE_QUERY_FAILED',
        'UPDATE_SERVICE_UNAVAILABLE','UPDATE_SERVICE_IDENTITY_INVALID','UPDATE_SERVICE_STATE_UNKNOWN',
        'UPDATE_SERVICE_START_MODE_UNKNOWN','UPDATE_REBOOT_TELEMETRY_INVALID','UPDATE_REBOOT_QUERY_FAILED')
    foreach($name in @('CurrentBuildNumber','UBR')) {
        foreach($suffix in @('MISSING','INVALID','READ_FAILED')){$allowed+=('OS_VERSION_'+$name+'_'+$suffix)}
    }
    foreach($area in @('AutomaticUpdates','WindowsUpdate')) {
        $allowed+=($area+'_KEY_READ_FAILED');$allowed+=($area+'_KEY_CLOSE_FAILED')
        $fields=if($area -ceq 'AutomaticUpdates'){@('NoAutoUpdate','AUOptions','UseWUServer')}else{
            @('DeferQualityUpdates','DeferQualityUpdatesPeriodInDays','SetDisableUXWUAccess',
              'DoNotConnectToWindowsUpdateInternetLocations','SetPolicyDrivenUpdateSourceForQualityUpdates',
              'ConfigureDeadlineForQualityUpdates','ConfigureDeadlineForFeatureUpdates','SetComplianceDeadline',
              'SetComplianceDeadlineForQU','SetComplianceDeadlineForFU','SetEDURestart')}
        foreach($field in $fields){foreach($suffix in @('INVALID_TYPE','INVALID_VALUE','READ_FAILED')){$allowed+=($area+'_'+$field+'_'+$suffix)}}
    }
    foreach($name in @('AllowAutoUpdate','ConfigureDeadlineForQualityUpdates','ConfigureDeadlineForFeatureUpdates',
        'IgnoreWindowsUpdateGroupPolicies','SetEDURestart')){$allowed+=('UPDATE_POLICY_'+$name+'_QUERY_FAILED')}
    foreach($issue in @($Evidence.CollectionIssues)) {
        if($issue -isnot [string] -or $issue -cnotin $allowed){throw 'Unexpected native collection diagnostic.'}
        $issue
    }
}
