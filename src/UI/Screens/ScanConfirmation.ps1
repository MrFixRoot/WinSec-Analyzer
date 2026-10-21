# ============================================================
# WinSec Analyzer - Per-operation scan confirmation
# PowerShell 5.1 / 7.x. Rendering and keyboard input only.
# ============================================================

function Show-WinSecScanConfirmation {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Request)

    if ($Request.Operation -cne 'SCAN' -or $Request.ReadOnly -cne $true -or
        $Request.Checks -isnot [array] -or
        $Request.SelectionMode -cnotin @('ALL_EXECUTABLE', 'EXPLICIT_CHECKS')) {
        throw 'Invalid scan confirmation request.'
    }

    $scope = if ($Request.SelectionMode -ceq 'ALL_EXECUTABLE') {
        'Local device - all executable controls'
    } else { 'Explicit control selection (scope unspecified)' }
    $scopeFields = @{}
    if ($Request -is [System.Collections.IDictionary]) {
        foreach ($name in $Request.psbase.Keys) {
            if ($name -isnot [string] -or $name -notin @('ScopeType','ScopeKey','ScanAction')) { continue }
            if ($scopeFields.ContainsKey($name)) { throw 'Ambiguous scan confirmation scope.' }
            $scopeFields[$name] = $Request[$name]
        }
    }
    else {
        foreach ($name in @('ScopeType','ScopeKey','ScanAction')) {
            $property = $Request.PSObject.Properties[$name]
            if ($null -ne $property) {
                if ($property.MemberType -ne [System.Management.Automation.PSMemberTypes]::NoteProperty) {
                    throw 'Scan scope requires plain data properties.'
                }
                $scopeFields[$name] = $property.Value
            }
        }
    }
    $scanAction = 'Scan'
    if ($scopeFields.ContainsKey('ScanAction')) {
        if ($scopeFields.ScanAction -isnot [string] -or $scopeFields.ScanAction -cnotin @('Scan','Rescan')) {
            throw 'Invalid scan confirmation action.'
        }
        $scanAction = $scopeFields.ScanAction
        $scopeFields.Remove('ScanAction')
    }
    if ($scopeFields.Count -gt 0) {
        $type = $scopeFields.ScopeType
        $key = $scopeFields.ScopeKey
        if ($scopeFields.Count -ne 2 -or $type -isnot [string] -or $key -isnot [string] -or
            $type -cnotin @('DEVICE','SECTION','CONTROL')) { throw 'Invalid scan confirmation scope.' }
        switch -CaseSensitive ($type) {
            'DEVICE' {
                if ($key -cne 'ALL' -or $Request.SelectionMode -cne 'ALL_EXECUTABLE') {
                    throw 'Invalid device confirmation scope.'
                }
            }
            'SECTION' {
                if ($key -cnotin @('SystemSecurity','NetworkSecurity','IdentityAccess','LoggingAuditing','ServicesHardening') -or
                    $Request.SelectionMode -cne 'EXPLICIT_CHECKS' -or
                    @($Request.Checks | Where-Object { $_.SectionKey -isnot [string] -or $_.SectionKey -cne $key }).Count -gt 0) {
                    throw 'Invalid section confirmation scope.'
                }
                $scope = 'Section: ' + $key + ' - executable controls only'
            }
            'CONTROL' {
                if ($key -cnotmatch '\A[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\z' -or
                    $Request.SelectionMode -cne 'EXPLICIT_CHECKS' -or $Request.Checks.Count -ne 1 -or
                    $Request.Checks[0].CheckId -isnot [string] -or $Request.Checks[0].CheckId -cne $key) {
                    throw 'Invalid control confirmation scope.'
                }
                $scope = 'Control: ' + $key
            }
        }
    }

    $profileLines = @()
    $profileValue = $null
    $profileCount = 0
    if ($Request -is [System.Collections.IDictionary]) {
        foreach ($name in $Request.psbase.Keys) {
            if ($name -is [string] -and [string]::Equals($name, 'EvaluationProfile', [StringComparison]::OrdinalIgnoreCase)) {
                $profileCount++
                $profileValue = $Request[$name]
            }
        }
    }
    else {
        $property = $Request.PSObject.Properties['EvaluationProfile']
        if ($null -ne $property) {
            if ($property.MemberType -ne [System.Management.Automation.PSMemberTypes]::NoteProperty) {
                throw 'Profile confirmation requires plain data.'
            }
            $profileCount = 1
            $profileValue = $property.Value
        }
    }
    if ($profileCount -gt 1) { throw 'Ambiguous assessment profile confirmation.' }
    if ($profileCount -eq 1) {
        $profile = Assert-WinSecAssessmentProfilePreview $profileValue
        $profileLines += 'Evaluation profile: ' + $profile.Profile
        foreach ($policy in $profile.Policies) {
            if (@($Request.Checks|Where-Object {$_.CheckId -ceq $policy.CheckId}).Count -ne 1) {
                throw 'Profile policy lies outside the confirmed control selection.'
            }
            $profileLines += 'Criteria: {0} | {1} / {2}' -f $policy.CheckId,$policy.CatalogId,$policy.CatalogVersion
            $profileLines += 'Criteria SHA256: ' + $policy.CatalogSha256
            $profileLines += 'Applies to: {0} / {1} / {2}' -f $policy.OSFamily,$policy.OSRelease,$policy.Edition
        }
        $profileLines += 'Applicability checked during scan. Score: NOT_SCORED.'
    }

    $display = [pscustomobject]@{ CanConfirm = $false }
    $render = {
        param($UnusedState)
        $display.CanConfirm = $false
        $terminal = Get-WinSecTerminalSize
        Clear-WinSecScreen
        $width = [Math]::Max(1, [int]$terminal.ContentWidth)
        $lines = @(
            ('WINSEC ANALYZER - CONFIRM ' + $scanAction.ToUpperInvariant())
            ('Device: {0}' -f $Request.Hostname)
            ('DeviceId: {0}' -f $Request.DeviceId)
            ('Scope: {0}' -f $scope)
            'Mode: READ ONLY - no Windows configuration changes'
            'Raw evidence storage: NOT REQUESTED'
            ('Executable controls: {0}' -f @($Request.Checks).Count)
        )
        $lines += $profileLines
        foreach ($check in $Request.Checks) {
            $lines += '{0} | {1} | {2}' -f $check.CheckId, $check.SectionKey, $check.Name
        }
        $hasChecks = @($Request.Checks).Count -gt 0
        if (-not $hasChecks) {
            $lines += 'NO_EXECUTABLE_CHECKS - no audit will be started. NOT_SCORED.'
        }
        $lines += if ($hasChecks) {
            '[Y / Enter] Confirm this operation | [N / Esc] Cancel'
        }
        else {
            '[N / Esc] Back'
        }

        # Wrap every field completely; do not approve truncated requests.
        $wrapped = @(
            foreach ($line in $lines) {
                for ($offset = 0; $offset -lt $line.Length; $offset += $width) {
                    $line.Substring($offset, [Math]::Min($width, $line.Length - $offset))
                }
            }
        )
        if ($terminal.Width -lt 40 -or $terminal.Height -lt ($wrapped.Count + 1)) {
            Write-WinSecText -Text 'Resize to view the complete scan request.' -Color Yellow
            Write-WinSecText -Text ('Required height at this width: {0}' -f ($wrapped.Count + 1))
            Write-WinSecText -Text '[N / Esc] Cancel'
            return
        }
        foreach ($line in $wrapped) { Write-WinSecText -Text $line }
        $display.CanConfirm = $hasChecks
    }

    $resizeState = New-WinSecResizeState
    $null = & $render $null
    while ($true) {
        $key = Read-WinSecResizeAwareKey -ResizeState $resizeState -RenderAction $render
        $null = Invoke-WinSecResizeHandler -ResizeState $resizeState -RenderAction $render
        if ($null -eq $key -or $key.KeyDown -ceq $false -or
            ([int]$key.ControlKeyState -band 0x0F) -ne 0) { continue }
        if ($key.VirtualKeyCode -eq 27 -or [string]$key.Character -ieq 'N') {
            return $false
        }
        if ($display.CanConfirm -and ($key.VirtualKeyCode -eq 13 -or [string]$key.Character -ieq 'Y')) {
            return $true
        }
    }
}
