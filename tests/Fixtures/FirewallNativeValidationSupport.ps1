# Helpers del validador explicito; importar no consulta Windows ni escribe datos.
function Assert-WinSecFirewallValidationPath {
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

function Get-WinSecFirewallValidationFiles {
    param([string]$ProjectRoot)
    $paths=New-Object 'System.Collections.Generic.List[string]'
    $directories=New-Object 'System.Collections.Generic.Queue[string]'
    foreach($name in @('src','config')){$directories.Enqueue((Join-Path $ProjectRoot $name))}
    while($directories.Count) {
        $directory=$directories.Dequeue()
        Assert-WinSecFirewallValidationPath $ProjectRoot $directory
        foreach($item in @(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop)) {
            if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Linked validation dependencies are prohibited.'}
            if($item.PSIsContainer){$directories.Enqueue($item.FullName)}
            elseif($item.Extension -cin @('.ps1','.json')) {
                $paths.Add($item.FullName.Substring($ProjectRoot.TrimEnd('\','/').Length+1).Replace('\','/'))
            } elseif($item.Name -cne '.gitkeep') {throw 'Unreviewed validation dependency type.'}
            if($directories.Count+$paths.Count -gt 512){throw 'Validation dependency set is too large.'}
        }
    }
    $paths.Add('tests/Integration/Invoke-FirewallNativeValidation.ps1')
    $paths.Add('tests/Fixtures/FirewallNativeValidationSupport.ps1')
    $paths.Add('tests/Fixtures/FrameworkNativeValidationSupport.ps1')
    $paths.Sort([StringComparer]::Ordinal)
    return ,$paths.ToArray()
}

function Get-WinSecFirewallValidationHash {
    param([string]$Text)
    $sha=[Security.Cryptography.SHA256]::Create()
    try {[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text))).Replace('-','')}
    finally {$sha.Dispose()}
}

function Open-WinSecFirewallValidationSnapshot {
    param([string]$ProjectRoot)
    $streams=New-Object 'System.Collections.Generic.List[object]'
    $records=New-Object 'System.Collections.Generic.List[object]'
    $total=0L
    try {
        foreach($relative in (Get-WinSecFirewallValidationFiles $ProjectRoot)) {
            $path=Join-Path $ProjectRoot $relative
            Assert-WinSecFirewallValidationPath $ProjectRoot $path
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
        return [pscustomobject]@{Streams=$streams;Files=$records.ToArray();Sha256=(Get-WinSecFirewallValidationHash $json)}
    } catch {foreach($stream in $streams){$stream.Dispose()};throw 'Validation dependencies could not be frozen.'}
}

function Assert-WinSecFirewallValidationSnapshot {
    param([string]$ProjectRoot,[object]$Snapshot)
    $current=Open-WinSecFirewallValidationSnapshot $ProjectRoot
    try {if($current.Sha256 -cne $Snapshot.Sha256){throw 'Validation dependencies changed; prepare a new request.'}}
    finally {foreach($stream in $current.Streams){$stream.Dispose()}}
}

function Get-WinSecFirewallNativeUtcNow {return [datetime]::UtcNow}

function Get-WinSecFirewallNativeElevation {
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    try {return ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)}
    finally {$identity.Dispose()}
}

# Export closed diagnostic identifiers only, never provider/exception messages.
function Get-WinSecFirewallNativeDiagnostics {
    param([Parameter(Mandatory)][object]$Control)
    $evidence=(Get-WinSecTechnicalField $Control Evidence).Value
    if($null -eq $evidence) {
        if((Get-WinSecTechnicalField $Control ObservedStatus).Value -cne 'ERROR'){throw 'Invalid missing Firewall evidence.'}
        return 'COLLECTOR_EVIDENCE_UNAVAILABLE'
    }
    $issues=(Get-WinSecTechnicalField $evidence CollectionIssues).Value
    if($issues -isnot [array]){throw 'Invalid Firewall diagnostic collection.'}
    $allowed=@(Get-WinSecFirewallIssueCodes)
    foreach($issue in $issues) {
        if($issue -isnot [string] -or $issue -cnotin $allowed){throw 'Unsafe native diagnostic.'}
        $issue
    }
}

