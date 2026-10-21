# WinSec Analyzer
# Archivo: src\Services\ExportService.ps1
# Exportación explícita de resultados públicos; nunca evidencia cruda.

function Get-WinSecReportInstallation {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectRoot)
    $installation=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
    if (-not [string]::Equals($installation.TrimEnd('\','/'),[IO.Path]::GetFullPath($ProjectRoot).TrimEnd('\','/'),[StringComparison]::OrdinalIgnoreCase)) {
        throw 'Export must use the current installation.'
    }
    return $installation
}

function Get-WinSecReportTextHash {
    param([Parameter(Mandatory)][string]$Text)
    $sha=[System.Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)))).Replace('-','') }
    finally { $sha.Dispose() }
}

function ConvertFrom-WinSecMarkdownArtifact {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Text,[Parameter(Mandatory)][string]$DeviceId)
    if ([Text.Encoding]::UTF8.GetByteCount($Text) -gt 1048576 -or
        $Text -cnotmatch '\A<!-- WinSec public report\n([^\r\n]+)\n-->\n([\s\S]*)\z') { throw 'Unrecognized public report.' }
    $metadataJson=$Matches[1];$body=$Matches[2]
    $meta=ConvertFrom-WinSecStoredJson -Json $metadataJson
    $names=@($meta.PSObject.Properties.Name)
    if ($names.Count -ne 4 -or @($names | Where-Object { $_ -cnotin @('SchemaVersion','DeviceId','ScanId','ContentSha256') }).Count -ne 0 -or
        $meta.SchemaVersion -cne '1.0.0' -or $meta.DeviceId -isnot [string] -or
        -not [string]::Equals($meta.DeviceId,$DeviceId,[StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-WinSecTargetIdentifier $meta.ScanId) -or $meta.ContentSha256 -cne (Get-WinSecReportTextHash $body)) {
        throw 'Inconsistent public report ownership or content.'
    }
    return $meta
}

function Write-WinSecMarkdownArtifact {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectRoot,[Parameter(Mandatory)][object]$Report)
    $ProjectRoot=Get-WinSecReportInstallation -ProjectRoot $ProjectRoot
    $metadata=[ordered]@{SchemaVersion='1.0.0';DeviceId=$Report.DeviceId;ScanId=$Report.ScanId;ContentSha256=(Get-WinSecReportTextHash $Report.Markdown)}
    $text="<!-- WinSec public report`n" + (ConvertTo-Json -InputObject $metadata -Compress) + "`n-->`n" + $Report.Markdown
    $null=ConvertFrom-WinSecMarkdownArtifact -Text $text -DeviceId $Report.DeviceId
    $directory=Join-Path $ProjectRoot ('reports/exports/' + (Get-WinSecEvidenceHash $Report.DeviceId))
    $name='findings-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ') + '-' + [guid]::NewGuid().ToString('N') + '.md'
    $path=Join-Path $directory $name
    $temporary=Join-Path $directory ('.' + $name + '.tmp')
    Assert-WinSecDeviceRemovalPath -ProjectRoot $ProjectRoot -Path $path
    $null=[IO.Directory]::CreateDirectory($directory)
    Assert-WinSecDeviceRemovalPath -ProjectRoot $ProjectRoot -Path $path
    $ownedTemp=$false;$moved=$false
    try {
        $bytes=[Text.Encoding]::UTF8.GetBytes($text)
        $stream=[IO.File]::Open($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        $ownedTemp=$true
        try { $stream.Write($bytes,0,$bytes.Length);$stream.Flush($true) } finally { $stream.Dispose() }
        Assert-WinSecDeviceRemovalPath -ProjectRoot $ProjectRoot -Path $temporary
        if ((Get-FileHash -LiteralPath $temporary -Algorithm SHA256 -ErrorAction Stop).Hash -cne (Get-WinSecReportTextHash $text)) { throw 'Report write verification failed.' }
        Assert-WinSecDeviceRemovalPath -ProjectRoot $ProjectRoot -Path $path
        [IO.File]::Move($temporary,$path);$moved=$true
        Assert-WinSecDeviceRemovalPath -ProjectRoot $ProjectRoot -Path $path
        if ((Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash -cne (Get-WinSecReportTextHash $text)) { throw 'Report publication verification failed.' }
        return [pscustomobject]@{Path=$path;FileName=$name;RelativePath=('reports/exports/' + (Get-WinSecEvidenceHash $Report.DeviceId) + '/' + $name);DeviceId=$Report.DeviceId;ScanId=$Report.ScanId}
    }
    finally {
        if ($ownedTemp -and -not $moved) {
            Assert-WinSecDeviceRemovalPath -ProjectRoot $ProjectRoot -Path $temporary
            if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
        }
    }
}

function Export-WinSecFindingsMarkdown {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectRoot,[Parameter(Mandatory)][object]$Selection)
    $installation=Get-WinSecReportInstallation -ProjectRoot $ProjectRoot
    $report=New-WinSecFindingsMarkdown -Selection $Selection
    return Write-WinSecMarkdownArtifact -ProjectRoot $installation -Report $report
}
