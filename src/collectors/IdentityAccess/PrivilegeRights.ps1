function Get-WinSecPrivilegeRightsEvidence {
    [CmdletBinding()]
    param([switch]$Deep)
    $data=[ordered]@{}
    $warnings=New-Object 'System.Collections.Generic.List[string]'
    $tmp=Join-Path ([IO.Path]::GetTempPath()) ('winsec-rights-'+[guid]::NewGuid().ToString('N')+'.inf')
    try {
        $null=& secedit.exe /export /cfg $tmp /areas USER_RIGHTS /quiet 2>&1
        if ($LASTEXITCODE -ne 0) { throw ('secedit exit code '+$LASTEXITCODE) }
        if (-not (Test-Path -LiteralPath $tmp)) { throw 'El archivo de exportacion no fue creado.' }
        $lines=@(Get-Content -LiteralPath $tmp -ErrorAction Stop)
        $rights=[ordered]@{}
        foreach ($line in $lines) {
            if ($line -match '^(Se[A-Za-z]+Right)\s*=\s*(.*)$') { $rights[$matches[1]]=$matches[2].Trim() }
        }
        $data.userRights=$rights
    } catch { $warnings.Add('secedit: '+$_.Exception.Message) }
    finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    $state=if ($data.Count -eq 0) { 'ERROR' } else { 'COMPLETED' }
    return (New-WinSecPayload -Data $data -Sources @('secedit /export /areas USER_RIGHTS') -Warnings @($warnings.ToArray()) -Status $state)
}
