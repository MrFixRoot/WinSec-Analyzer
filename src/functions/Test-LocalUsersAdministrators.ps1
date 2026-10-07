function Test-LocalUsersAdministrators {
    [CmdletBinding()]
    param()

    $Results = @()
    $LocalUsers = @()
    $AdminMembers = @()

    # ========================================================
    # COLLECT LOCAL USERS
    # ========================================================

    try {

        if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {

            $LocalUsers = @(
                Get-LocalUser -ErrorAction Stop |
                    ForEach-Object {

                        [PSCustomObject]@{
                            Name                 = $_.Name
                            SID                  = $_.SID.Value
                            Enabled              = $_.Enabled
                            PasswordRequired     = $_.PasswordRequired
                            PasswordNeverExpires = ($null -eq $_.PasswordExpires)
                            LastLogon            = $_.LastLogon
                        }
                    }
            )
        }
        else {

            $LocalUsers = @(
                Get-CimInstance Win32_UserAccount `
                    -Filter "LocalAccount=True" `
                    -ErrorAction Stop |
                    ForEach-Object {

                        [PSCustomObject]@{
                            Name                 = $_.Name
                            SID                  = $_.SID
                            Enabled              = (-not $_.Disabled)
                            PasswordRequired     = $_.PasswordRequired
                            PasswordNeverExpires = (-not $_.PasswordExpires)
                            LastLogon            = $null
                        }
                    }
            )
        }
    }
    catch {

        $Results += [PSCustomObject]@{
            Control        = 'Local User Enumeration'
            Category       = 'Identity & Access'
            Status         = 'ERROR'
            Severity       = 'Unknown'
            Score          = 0
            MaxScore       = 0
            Evidence       = $_.Exception.Message
            Recommendation = 'Verify permissions and local account management availability.'
        }

        return $Results
    }

    # ========================================================
    # COLLECT LOCAL ADMINISTRATORS
    # Uses SID so it works on localized Windows installations
    # S-1-5-32-544 = Built-in Administrators group
    # ========================================================

    try {

        if (
            (Get-Command Get-LocalGroup -ErrorAction SilentlyContinue) -and
            (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue)
        ) {

            $AdminGroup = Get-LocalGroup -ErrorAction Stop |
                Where-Object {
                    $_.SID.Value -eq 'S-1-5-32-544'
                } |
                Select-Object -First 1

            if ($null -ne $AdminGroup) {

                $AdminMembers = @(
                    Get-LocalGroupMember `
                        -Group $AdminGroup `
                        -ErrorAction Stop
                )
            }
        }
    }
    catch {

        $Results += [PSCustomObject]@{
            Control        = 'Local Administrators Enumeration'
            Category       = 'Identity & Access'
            Status         = 'ERROR'
            Severity       = 'Unknown'
            Score          = 0
            MaxScore       = 0
            Evidence       = $_.Exception.Message
            Recommendation = 'Run WinSec Analyzer with sufficient privileges and review the local Administrators group manually.'
        }
    }

    # ========================================================
    # 1. BUILT-IN ADMINISTRATOR ACCOUNT
    # SID ending in -500
    # 20 points
    # ========================================================

    $BuiltInAdministrator = $LocalUsers |
        Where-Object {
            $_.SID -match '-500$'
        } |
        Select-Object -First 1

    if ($null -eq $BuiltInAdministrator) {

        $Results += [PSCustomObject]@{
            Control        = 'Built-in Administrator Account'
            Category       = 'Identity & Access'
            Status         = 'INFO'
            Severity       = 'Info'
            Score          = 0
            MaxScore       = 0
            Evidence       = 'The built-in Administrator account could not be identified.'
            Recommendation = 'Review the built-in Administrator account manually.'
        }
    }
    elseif ($BuiltInAdministrator.Enabled -eq $false) {

        $Results += [PSCustomObject]@{
            Control        = 'Built-in Administrator Account'
            Category       = 'Identity & Access'
            Status         = 'PASS'
            Severity       = 'High'
            Score          = 20
            MaxScore       = 20
            Evidence       = "Account '$($BuiltInAdministrator.Name)' is disabled."
            Recommendation = 'No action required.'
        }
    }
    else {

        $Results += [PSCustomObject]@{
            Control        = 'Built-in Administrator Account'
            Category       = 'Identity & Access'
            Status         = 'WARNING'
            Severity       = 'High'
            Score          = 5
            MaxScore       = 20
            Evidence       = "Built-in Administrator account '$($BuiltInAdministrator.Name)' is enabled."
            Recommendation = 'Review whether the built-in Administrator account must remain enabled.'
        }
    }

    # ========================================================
    # 2. BUILT-IN GUEST ACCOUNT
    # SID ending in -501
    # 15 points
    # ========================================================

    $GuestAccount = $LocalUsers |
        Where-Object {
            $_.SID -match '-501$'
        } |
        Select-Object -First 1

    if ($null -eq $GuestAccount) {

        $Results += [PSCustomObject]@{
            Control        = 'Guest Account'
            Category       = 'Identity & Access'
            Status         = 'INFO'
            Severity       = 'Info'
            Score          = 0
            MaxScore       = 0
            Evidence       = 'The built-in Guest account could not be identified.'
            Recommendation = 'Review the Guest account manually.'
        }
    }
    elseif ($GuestAccount.Enabled -eq $false) {

        $Results += [PSCustomObject]@{
            Control        = 'Guest Account'
            Category       = 'Identity & Access'
            Status         = 'PASS'
            Severity       = 'High'
            Score          = 15
            MaxScore       = 15
            Evidence       = "Guest account '$($GuestAccount.Name)' is disabled."
            Recommendation = 'No action required.'
        }
    }
    else {

        $Results += [PSCustomObject]@{
            Control        = 'Guest Account'
            Category       = 'Identity & Access'
            Status         = 'FAIL'
            Severity       = 'High'
            Score          = 0
            MaxScore       = 15
            Evidence       = "Guest account '$($GuestAccount.Name)' is enabled."
            Recommendation = 'Disable the built-in Guest account unless explicitly required.'
        }
    }

    # ========================================================
    # 3. PASSWORD REQUIREMENT FOR ENABLED LOCAL USERS
    # 20 points
    # ========================================================

    $EnabledUsersWithoutPasswordRequirement = @(
        $LocalUsers |
            Where-Object {
                $_.Enabled -eq $true -and
                $_.PasswordRequired -eq $false
            }
    )

    if ($EnabledUsersWithoutPasswordRequirement.Count -eq 0) {

        $Results += [PSCustomObject]@{
            Control        = 'Local Account Password Requirement'
            Category       = 'Identity & Access'
            Status         = 'PASS'
            Severity       = 'High'
            Score          = 20
            MaxScore       = 20
            Evidence       = 'All enabled local user accounts require a password.'
            Recommendation = 'No action required.'
        }
    }
    else {

        $AccountNames = (
            $EnabledUsersWithoutPasswordRequirement.Name -join ', '
        )

        $Results += [PSCustomObject]@{
            Control        = 'Local Account Password Requirement'
            Category       = 'Identity & Access'
            Status         = 'FAIL'
            Severity       = 'High'
            Score          = 0
            MaxScore       = 20
            Evidence       = "Enabled accounts without a password requirement: $AccountNames"
            Recommendation = 'Require passwords for all enabled interactive local accounts.'
        }
    }

    # ========================================================
    # 4. PASSWORD NEVER EXPIRES - LOCAL USERS
    # 15 points
    # ========================================================

    $EnabledUsersNeverExpire = @(
        $LocalUsers |
            Where-Object {
                $_.Enabled -eq $true -and
                $_.PasswordNeverExpires -eq $true
            }
    )

    if ($EnabledUsersNeverExpire.Count -eq 0) {

        $Results += [PSCustomObject]@{
            Control        = 'Local User Password Expiration'
            Category       = 'Identity & Access'
            Status         = 'PASS'
            Severity       = 'Medium'
            Score          = 15
            MaxScore       = 15
            Evidence       = 'No enabled local accounts with non-expiring passwords were detected.'
            Recommendation = 'No action required.'
        }
    }
    else {

        $AccountNames = (
            $EnabledUsersNeverExpire.Name -join ', '
        )

        $Results += [PSCustomObject]@{
            Control        = 'Local User Password Expiration'
            Category       = 'Identity & Access'
            Status         = 'WARNING'
            Severity       = 'Medium'
            Score          = 5
            MaxScore       = 15
            Evidence       = "Enabled accounts with passwords that do not expire: $AccountNames"
            Recommendation = 'Review whether non-expiring passwords are necessary for these accounts.'
        }
    }

    # ========================================================
    # BUILD LOCAL ADMIN SID LIST
    # ========================================================

    $AdminSIDs = @(
        $AdminMembers |
            ForEach-Object {
                if ($null -ne $_.SID) {
                    $_.SID.Value
                }
            }
    )

    $LocalAdministratorUsers = @(
        $LocalUsers |
            Where-Object {
                $AdminSIDs -contains $_.SID
            }
    )

    # ========================================================
    # 5. LOCAL ADMINISTRATORS REQUIRE PASSWORDS
    # 15 points
    # ========================================================

    if ($AdminMembers.Count -eq 0) {

        $Results += [PSCustomObject]@{
            Control        = 'Local Administrator Password Requirement'
            Category       = 'Identity & Access'
            Status         = 'INFO'
            Severity       = 'Info'
            Score          = 0
            MaxScore       = 0
            Evidence       = 'Local Administrator members could not be evaluated.'
            Recommendation = 'Review local administrator accounts manually.'
        }
    }
    else {

        $RiskyAdministrators = @(
            $LocalAdministratorUsers |
                Where-Object {
                    $_.Enabled -eq $true -and
                    $_.PasswordRequired -eq $false
                }
        )

        if ($RiskyAdministrators.Count -eq 0) {

            $Results += [PSCustomObject]@{
                Control        = 'Local Administrator Password Requirement'
                Category       = 'Identity & Access'
                Status         = 'PASS'
                Severity       = 'High'
                Score          = 15
                MaxScore       = 15
                Evidence       = 'No enabled local administrator accounts without a password requirement were detected.'
                Recommendation = 'No action required.'
            }
        }
        else {

            $AccountNames = (
                $RiskyAdministrators.Name -join ', '
            )

            $Results += [PSCustomObject]@{
                Control        = 'Local Administrator Password Requirement'
                Category       = 'Identity & Access'
                Status         = 'FAIL'
                Severity       = 'High'
                Score          = 0
                MaxScore       = 15
                Evidence       = "Local administrator accounts without a password requirement: $AccountNames"
                Recommendation = 'Require strong passwords for all enabled local administrator accounts.'
            }
        }
    }

    # ========================================================
    # 6. LOCAL ADMIN PASSWORD EXPIRATION
    # 15 points
    # ========================================================

    if ($AdminMembers.Count -gt 0) {

        $AdminNeverExpires = @(
            $LocalAdministratorUsers |
                Where-Object {
                    $_.Enabled -eq $true -and
                    $_.PasswordNeverExpires -eq $true
                }
        )

        if ($AdminNeverExpires.Count -eq 0) {

            $Results += [PSCustomObject]@{
                Control        = 'Local Administrator Password Expiration'
                Category       = 'Identity & Access'
                Status         = 'PASS'
                Severity       = 'High'
                Score          = 15
                MaxScore       = 15
                Evidence       = 'No enabled local administrator accounts with non-expiring passwords were detected.'
                Recommendation = 'No action required.'
            }
        }
        else {

            $AccountNames = (
                $AdminNeverExpires.Name -join ', '
            )

            $Results += [PSCustomObject]@{
                Control        = 'Local Administrator Password Expiration'
                Category       = 'Identity & Access'
                Status         = 'WARNING'
                Severity       = 'High'
                Score          = 5
                MaxScore       = 15
                Evidence       = "Local administrator accounts with non-expiring passwords: $AccountNames"
                Recommendation = 'Review password expiration requirements for local administrator accounts.'
            }
        }
    }

    # ========================================================
    # INFORMATIONAL - ENABLED USERS
    # ========================================================

    $EnabledUsers = @(
        $LocalUsers |
            Where-Object {
                $_.Enabled -eq $true
            }
    )

    $EnabledUserNames = if ($EnabledUsers.Count -gt 0) {
        $EnabledUsers.Name -join ', '
    }
    else {
        'None'
    }

    $Results += [PSCustomObject]@{
        Control        = 'Enabled Local Users'
        Category       = 'Identity & Access'
        Status         = 'INFO'
        Severity       = 'Info'
        Score          = 0
        MaxScore       = 0
        Evidence       = "Enabled local users: $EnabledUserNames"
        Recommendation = 'Review enabled accounts and confirm that each account is required.'
    }

    # ========================================================
    # INFORMATIONAL - ADMINISTRATORS GROUP
    # ========================================================

    if ($AdminMembers.Count -gt 0) {

        $AdministratorNames = (
            $AdminMembers.Name -join ', '
        )

        $Results += [PSCustomObject]@{
            Control        = 'Local Administrators Membership'
            Category       = 'Identity & Access'
            Status         = 'INFO'
            Severity       = 'Info'
            Score          = 0
            MaxScore       = 0
            Evidence       = "Administrators group members: $AdministratorNames"
            Recommendation = 'Review administrator membership and remove unnecessary privileged accounts.'
        }
    }

    return $Results
}
