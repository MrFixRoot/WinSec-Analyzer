# ============================================================
# WinSec Analyzer - Per-operation scan confirmation
# PowerShell 5.1 / 7.x. Rendering and keyboard input only.
# ============================================================

function Show-WinSecScanConfirmation {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Request)
    $Request=Copy-WinSecResultData $Request

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
        $profileLines += 'Applicability checked during scan. Overall score: NOT_SCORED.'
    }
    if ($null -ne $Request.ConfigurationScoring) {
        if ($profileCount -ne 1) {throw 'Configuration scoring requires a confirmed evaluation profile.'}
        $policy=$Request.ConfigurationScoring
        Assert-WinSecConfigurationFields $policy @('MethodologyId','MethodologyVersion','PolicySha256')
        if ($policy.MethodologyId -cne 'WSA_CONTROL_CRITERIA_MEAN' -or $policy.MethodologyVersion -cne '1.0.0' -or
            $policy.PolicySha256 -isnot [string] -or $policy.PolicySha256 -cnotmatch '\A[A-F0-9]{64}\z') { throw 'Invalid configuration scoring preview.' }
        $profileLines+='Control scoring: verified criteria percentage; sections: equal control mean.'
        $profileLines+='Method: ' + $policy.MethodologyId + ' / ' + $policy.MethodologyVersion
        $profileLines+='Scoring policy SHA256: ' + $policy.PolicySha256
    }

    $display = [pscustomobject]@{ CanConfirm = $false; Choice = 0 }
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
            @('  [ Accept ]','  [ Cancel ]','[Arrows] Choose | [Enter] Select | [Y] Accept | [N / Esc] Cancel')
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
            $hints = @('Resize to view the complete scan request.',
                ('Required height at this width: {0}' -f ($wrapped.Count + 1)),'[N / Esc] Cancel')
            foreach ($hint in @($hints | Select-Object -First ([Math]::Max(0,[int]$terminal.Height-1)))) {
                Write-WinSecText -Text $hint.Substring(0,[Math]::Min($width,$hint.Length)) -Color Yellow
            }
            return
        }
        foreach ($line in $wrapped) {
            $color = 'Gray'
            if (($line -ceq '  [ Accept ]' -and $display.Choice -eq 0) -or
                ($line -ceq '  [ Cancel ]' -and $display.Choice -eq 1)) {
                $line = '> ' + $line.Substring(2);$color = 'Cyan'
            }
            Write-WinSecText -Text $line -Color $color
        }
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
        if ($key.VirtualKeyCode -in @(37,38,39,40)) {
            $display.Choice = 1 - $display.Choice
            $null = & $render $null
            continue
        }
        if ($key.VirtualKeyCode -eq 13 -and $display.Choice -eq 1) { return $false }
        if ($display.CanConfirm -and ($key.VirtualKeyCode -eq 13 -or [string]$key.Character -ieq 'Y')) {
            return $true
        }
    }
}
