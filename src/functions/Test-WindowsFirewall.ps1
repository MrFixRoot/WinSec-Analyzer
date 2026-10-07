function Test-WindowsFirewall {
    [CmdletBinding()]
    param()

    try {
        $Profiles = Get-NetFirewallProfile -ErrorAction Stop

        $DisabledProfiles = @(
            $Profiles | Where-Object {
                $_.Enabled -eq $false
            }
        )

        if ($DisabledProfiles.Count -gt 0) {

            return [PSCustomObject]@{
                Control        = 'Windows Firewall'
                Category       = 'Network Security'
                Status         = 'FAIL'
                Severity       = 'High'
                Score          = 0
                MaxScore       = 10
                Evidence       = "Disabled profiles: $($DisabledProfiles.Name -join ', ')"
                Recommendation = 'Enable Windows Firewall on all applicable profiles.'
            }
        }

        return [PSCustomObject]@{
            Control        = 'Windows Firewall'
            Category       = 'Network Security'
            Status         = 'PASS'
            Severity       = 'High'
            Score          = 10
            MaxScore       = 10
            Evidence       = 'All Windows Firewall profiles are enabled.'
            Recommendation = 'No action required.'
        }
    }
    catch {

        return [PSCustomObject]@{
            Control        = 'Windows Firewall'
            Category       = 'Network Security'
            Status         = 'ERROR'
            Severity       = 'Unknown'
            Score          = 0
            MaxScore       = 0
            Evidence       = $_.Exception.Message
            Recommendation = 'Verify privileges and Windows Firewall availability.'
        }
    }
}