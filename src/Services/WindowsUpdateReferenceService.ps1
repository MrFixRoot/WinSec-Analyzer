# Explicitly invoked, read-only loader of public servicing reference data.
# Imports define functions only; no device inventory is opened or initialized.
. (Join-Path $PSScriptRoot '../Core/DeviceInventory.ps1')
. (Join-Path $PSScriptRoot '../Core/WindowsUpdateServicing.ps1')

function Get-WinSecWindowsUpdateReferenceCatalog {
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ProjectRoot)
    $path=[IO.Path]::GetFullPath((Join-Path $ProjectRoot 'config/criteria/windows-update-servicing.json'))
    $stream=$null;$sha=$null
    try {
        # Check the file and every ancestor, including ancestors above the root.
        $current=$path;$isFile=$true
        while(-not [string]::IsNullOrEmpty($current)) {
            $item=Get-Item -LiteralPath $current -Force -ErrorAction Stop
            if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                ($isFile -and $item.PSIsContainer) -or (-not $isFile -and -not $item.PSIsContainer)) {
                throw 'Invalid Windows Update reference path.'
            }
            $isFile=$false;$current=[IO.Path]::GetDirectoryName($current)
        }
        # Deny concurrent write/delete handles while reading one bounded snapshot.
        $stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        if($stream.Length -lt 2 -or $stream.Length -gt 1048576){throw 'Invalid Windows Update reference size.'}
        $bytes=New-Object byte[] ([int]$stream.Length)
        $offset=0
        while($offset -lt $bytes.Length) {
            $count=$stream.Read($bytes,$offset,$bytes.Length-$offset)
            if($count -le 0){throw 'Incomplete Windows Update reference snapshot.'}
            $offset+=$count
        }
        $utf8=New-Object Text.UTF8Encoding($false,$true)
        $catalog=ConvertFrom-WinSecStoredJson ($utf8.GetString($bytes))
        Assert-WinSecWindowsUpdateReferenceCatalog $catalog
        $sha=[Security.Cryptography.SHA256]::Create()
        $hash=[BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','')
        return [pscustomobject]@{Catalog=$catalog;Sha256=$hash}
    } catch {
        # Provider/parser exceptions can include paths or supplied document data.
        throw 'Windows Update reference catalog could not be validated.'
    } finally {
        if($null -ne $sha){$sha.Dispose()}
        if($null -ne $stream){$stream.Dispose()}
    }
}
