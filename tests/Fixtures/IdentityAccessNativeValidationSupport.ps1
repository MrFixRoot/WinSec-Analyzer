# Helpers del validador explicito; importar no consulta Windows ni escribe datos.
function Assert-WinSecIdentityAccessValidationPath {
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

function Get-WinSecIdentityAccessValidationFiles {
    param([string]$ProjectRoot)
    $paths=New-Object 'System.Collections.Generic.List[string]'
    $directories=New-Object 'System.Collections.Generic.Queue[string]'
    foreach($name in @('src','config')){$directories.Enqueue((Join-Path $ProjectRoot $name))}
    while($directories.Count) {
        $directory=$directories.Dequeue()
        Assert-WinSecIdentityAccessValidationPath $ProjectRoot $directory
        foreach($item in @(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop)) {
            if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Linked validation dependencies are prohibited.'}
            if($item.PSIsContainer){$directories.Enqueue($item.FullName)}
            elseif($item.Extension -cin @('.ps1','.json')) {
                $paths.Add($item.FullName.Substring($ProjectRoot.TrimEnd('\','/').Length+1).Replace('\','/'))
            } elseif($item.Name -cne '.gitkeep') {throw 'Unreviewed validation dependency type.'}
            if($directories.Count+$paths.Count -gt 512){throw 'Validation dependency set is too large.'}
        }
    }
    $paths.Add('tests/Integration/Invoke-IdentityAccessNativeValidation.ps1')
    $paths.Add('tests/Fixtures/IdentityAccessNativeValidationSupport.ps1')
    $paths.Add('tests/Fixtures/FrameworkNativeValidationSupport.ps1')
    $paths.Sort([StringComparer]::Ordinal)
    return ,$paths.ToArray()
}

function Get-WinSecIdentityAccessValidationHash {
    param([string]$Text)
    $sha=[Security.Cryptography.SHA256]::Create()
    try {[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text))).Replace('-','')}
    finally {$sha.Dispose()}
}

function Open-WinSecIdentityAccessValidationSnapshot {
    param([string]$ProjectRoot)
    $streams=New-Object 'System.Collections.Generic.List[object]'
    $records=New-Object 'System.Collections.Generic.List[object]'
    $total=0L
    try {
        foreach($relative in (Get-WinSecIdentityAccessValidationFiles $ProjectRoot)) {
            $path=Join-Path $ProjectRoot $relative
            Assert-WinSecIdentityAccessValidationPath $ProjectRoot $path
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
        return [pscustomobject]@{Streams=$streams;Files=$records.ToArray();Sha256=(Get-WinSecIdentityAccessValidationHash $json)}
    } catch {foreach($stream in $streams){$stream.Dispose()};throw 'Validation dependencies could not be frozen.'}
}

function Assert-WinSecIdentityAccessValidationSnapshot {
    param([string]$ProjectRoot,[object]$Snapshot)
    $current=Open-WinSecIdentityAccessValidationSnapshot $ProjectRoot
    try {if($current.Sha256 -cne $Snapshot.Sha256){throw 'Validation dependencies changed; prepare a new request.'}}
    finally {foreach($stream in $current.Streams){$stream.Dispose()}}
}

function Get-WinSecIdentityAccessNativeUtcNow {return [datetime]::UtcNow}

function Get-WinSecIdentityAccessNativeElevation {
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    try {return ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)}
    finally {$identity.Dispose()}
}

function New-WinSecIdentityAccessValidationRequest {
    param($Target,[string]$CheckId,[string]$OperationId,[string]$Runtime,[bool]$Is64Bit,[bool]$Elevated,[string]$Date,$Plan,$Snapshot)
    $roles=@(Get-WinSecIdentityRoles $CheckId)
    $control=Get-WinSecTechnicalControl $CheckId
    [pscustomobject][ordered]@{
        Operation='VALIDATE_IDENTITY_ACCESS_READ_ONLY';OperationId=$OperationId;DeviceId=$Target.DeviceId;Hostname=$Target.Hostname
        ScopeType='CONTROL';ScopeKey=$CheckId;Checks=@($control.Name+' / '+$CheckId);Providers=$roles
        Runtime=$Runtime;Is64BitProcess=$Is64Bit;ProcessElevated=$Elevated;ApprovalDateUTC=$Date
        Profile=$Plan.Preview.Profile;ProfileSha256=$Plan.Preview.Policies[0].CatalogSha256
        DependencyManifestSha256=$Snapshot.Sha256;DependencyCount=$Snapshot.Files.Count
        ReadOnly=$true;PersistPublicHistory=$false;PersistRawEvidence=$false;PersistReports=$false
        Note='Only the selected IAM control runs in an isolated registry. Local Windows metadata and reviewed local SAM data: direct Administrators member SIDs (max 256, no nested/name/domain resolution), or built-in Guest RID501 account flags, or NetUserModalsGet levels0/3 password and lockout parameters. No passwords, password hashes, users of other controls, domain/cloud queries, authentication attempts, policy writes or remediation. SID tokens only; no account names in output. Complexity/reversible storage are not collected. Technical Markdown, history roundtrip and three frameworks are checked in memory. No result persistence or production permission changes.'
    }
}

