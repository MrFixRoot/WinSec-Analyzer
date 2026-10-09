function Test-LocalUsersAdministrators {
    [CmdletBinding()]
    param(
        [ValidateRange(1, 3650)]
        [int]$InactiveAdminDays = 90
    )

    $Results = @()
    $LocalUsers = @()
    $AdminMembers = @()

    # ========================================================
    # Helper - standardized WinSec result
    # ========================================================

    function New-IdentityResult {
        param(
            [Parameter(Mandatory, Position = 0)]
            [hashtable]$Data
        )

        [PSCustomObject]@{
            Control        = $Data.Control
            Category       = 'Identity & Access'
            Status         = $Data.Status
            Severity       = $Data.Severity
            Score          = $Data.Score
            MaxScore       = $Data.MaxScore
            Evidence       = $Data.Evidence
            Recommendation = $Data.Recommendation
        }
    }

    # ========================================================
    # Helper - classify administrator principal source
    # ========================================================

    function Get-PrincipalSourceName {
        param(
            [string]$Name,
            $PrincipalSource
        )

        if ($null -ne $PrincipalSource) {
            $SourceText = [string]$PrincipalSource

            if (-not [string]::IsNullOrWhiteSpace($SourceText)) {
                return $SourceText
            }
        }

        if ($Name -like "$env:COMPUTERNAME\*") {
            return 'Local'
        }

        if ($Name -like 'AzureAD\*') {
            return 'AzureAD'
        }

        if ($Name -like 'MicrosoftAccount\*') {
            return 'MicrosoftAccount'
        }

        return 'DomainOrOther'
    }

    # ========================================================
    # Collect additional CIM account information
    # ========================================================

    $CimUsersBySid = @{}

    try {
        $CimUsers = @(
            Get-CimInstance Win32_UserAccount `
                -Filter "LocalAccount=True" `
                -ErrorAction Stop
        )

        foreach ($CimUser in $CimUsers) {
            if (-not [string]::IsNullOrWhiteSpace([string]$CimUser.SID)) {
                $CimUsersBySid[[string]$CimUser.SID] = $CimUser
            }
        }
    }
    catch {
        # CIM information is supplementary.
    }

    # ========================================================
    # Collect local users
    # ========================================================

    try {

        if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {

            $RawUsers = @(
                Get-LocalUser -ErrorAction Stop
            )

            foreach ($User in $RawUsers) {

                $Sid = [string]$User.SID.Value
                $LockedOut = $null

                if ($CimUsersBySid.ContainsKey($Sid)) {
                    $LockedOut = [bool]$CimUsersBySid[$Sid].Lockout
                }

                $PrincipalSource = 'Local'

                if (
                    $User.PSObject.Properties.Name -contains
                    'PrincipalSource'
                ) {
                    $PrincipalSource = [string]$User.PrincipalSource
                }

                $PasswordNeverExpires = $false

                if (
                    $User.Enabled -eq $true -and
                    $null -eq $User.PasswordExpires
                ) {
                    $PasswordNeverExpires = $true
                }

                $LocalUsers += [PSCustomObject]@{
                    Name                 = [string]$User.Name
                    SID                  = $Sid
                    Enabled              = [bool]$User.Enabled
                    PasswordRequired     = [bool]$User.PasswordRequired
                    PasswordNeverExpires = $PasswordNeverExpires
                    PasswordExpires      = $User.PasswordExpires
                    PasswordLastSet      = $User.PasswordLastSet
                    LastLogon            = $User.LastLogon
                    AccountExpires       = $User.AccountExpires
                    PrincipalSource      = $PrincipalSource
                    LockedOut            = $LockedOut
                }
            }
        }
        else {

            foreach ($CimUser in $CimUsersBySid.Values) {

                $LocalUsers += [PSCustomObject]@{
                    Name                 = [string]$CimUser.Name
                    SID                  = [string]$CimUser.SID
                    Enabled              = (-not [bool]$CimUser.Disabled)
                    PasswordRequired     = [bool]$CimUser.PasswordRequired
                    PasswordNeverExpires = (-not [bool]$CimUser.PasswordExpires)
                    PasswordExpires      = $null
                    PasswordLastSet      = $null
                    LastLogon            = $null
                    AccountExpires       = $null
                    PrincipalSource      = 'Local'
                    LockedOut            = [bool]$CimUser.Lockout
                }
            }
        }
    }
    catch {

        $Results += New-IdentityResult @{
            Control        = 'Local User Enumeration'
            Status         = 'ERROR'
            Severity       = 'Unknown'
            Score          = 0
            MaxScore       = 0
            Evidence       = $_.Exception.Message
            Recommendation = 'Verify local account management availability and run WinSec Analyzer with sufficient privileges.'
        }

        return $Results
    }

    # ========================================================
    # Locate Administrators group using SID
    #
    # S-1-5-32-544 = BUILTIN\Administrators
    #
    # This avoids depending on the Windows display language.
    # ========================================================

    $AdminGroup = $null

    try {
        $AdminGroup = Get-LocalGroup -ErrorAction Stop |
            Where-Object {
                [string]$_.SID.Value -eq 'S-1-5-32-544'
            } |
            Select-Object -First 1
    }
    catch {
        $AdminGroup = $null
    }

    # ========================================================
    # Enumerate Administrators group
    # ========================================================

    if ($null -ne $AdminGroup) {

        try {

            $RawAdminMembers = @(
                Get-LocalGroupMember `
                    -Group $AdminGroup `
                    -ErrorAction Stop
            )

            foreach ($Member in $RawAdminMembers) {

                $MemberSid = $null

                if ($null -ne $Member.SID) {
                    $MemberSid = [string]$Member.SID.Value
                }

                $MemberName = [string]$Member.Name

                $Source = Get-PrincipalSourceName `
                    -Name $MemberName `
                    -PrincipalSource $Member.PrincipalSource

                $Resolved = $true

                if (
                    [string]::IsNullOrWhiteSpace($MemberName) -or
                    $MemberName -match '^S-\d-\d+'
                ) {
                    $Resolved = $false
                }

                $AdminMembers += [PSCustomObject]@{
                    Name            = $MemberName
                    SID             = $MemberSid
                    ObjectClass     = [string]$Member.ObjectClass
                    PrincipalSource = $Source
                    Resolved        = $Resolved
                }
            }
        }
        catch {

            # ------------------------------------------------
            # Fallback using WinNT ADSI provider
            # ------------------------------------------------

            try {

                $AdsiGroup = [ADSI](
                    "WinNT://$env:COMPUTERNAME/$($AdminGroup.Name),group"
                )

                $AdsiMembers = @(
                    $AdsiGroup.psbase.Invoke('Members')
                )

                foreach ($Member in $AdsiMembers) {

                    $MemberType = $Member.GetType()

                    $Name = [string]$MemberType.InvokeMember(
                        'Name',
                        'GetProperty',
                        $null,
                        $Member,
                        $null
                    )

                    $Class = [string]$MemberType.InvokeMember(
                        'Class',
                        'GetProperty',
                        $null,
                        $Member,
                        $null
                    )

                    $AdsPath = [string]$MemberType.InvokeMember(
                        'ADsPath',
                        'GetProperty',
                        $null,
                        $Member,
                        $null
                    )

                    $Sid = $null

                    try {
                        $SidBytes = $MemberType.InvokeMember(
                            'objectSid',
                            'GetProperty',
                            $null,
                            $Member,
                            $null
                        )

                        if ($null -ne $SidBytes) {
                            $SidObject = New-Object `
                                System.Security.Principal.SecurityIdentifier(
                                    $SidBytes,
                                    0
                                )

                            $Sid = $SidObject.Value
                        }
                    }
                    catch {
                        $Sid = $null
                    }

                    $DisplayName = $Name
                    $Source = 'DomainOrOther'

                    if ($AdsPath -match '^WinNT://([^/]+)/(.+)$') {

                        $Authority = $Matches[1]
                        $AccountName = $Matches[2]

                        $DisplayName = "$Authority\$AccountName"

                        if ($Authority -eq $env:COMPUTERNAME) {
                            $Source = 'Local'
                        }
                        elseif ($Authority -eq 'AzureAD') {
                            $Source = 'AzureAD'
                        }
                        elseif ($Authority -eq 'MicrosoftAccount') {
                            $Source = 'MicrosoftAccount'
                        }
                    }

                    $AdminMembers += [PSCustomObject]@{
                        Name            = $DisplayName
                        SID             = $Sid
                        ObjectClass     = $Class
                        PrincipalSource = $Source
                        Resolved        = (-not [string]::IsNullOrWhiteSpace($Name))
                    }
                }
            }
            catch {

                $Results += New-IdentityResult @{
                    Control        = 'Local Administrators Enumeration'
                    Status         = 'ERROR'
                    Severity       = 'Unknown'
                    Score          = 0
                    MaxScore       = 0
                    Evidence       = $_.Exception.Message
                    Recommendation = 'Review the local Administrators group manually.'
                }
            }
        }
    }
    else {

        $Results += New-IdentityResult @{
            Control        = 'Local Administrators Enumeration'
            Status         = 'ERROR'
            Severity       = 'Unknown'
            Score          = 0
            MaxScore       = 0
            Evidence       = 'The built-in Administrators group could not be identified.'
            Recommendation = 'Review the local Administrators group manually.'
        }
    }

    # ========================================================
    # Direct local administrator accounts
    # ========================================================

    $AdminSids = @(
        $AdminMembers |
            Where-Object {
                -not [string]::IsNullOrWhiteSpace($_.SID)
            } |
            ForEach-Object {
                $_.SID
            }
    )

    $LocalAdministratorUsers = @(
        $LocalUsers |
            Where-Object {
                $AdminSids -contains $_.SID
            }
    )

    # ========================================================
    # 1. BUILT-IN ADMINISTRATOR
    #
    # RID 500
    # 20 points
    # ========================================================

    $BuiltInAdministrator = $LocalUsers |
        Where-Object {
            $_.SID -match '-500$'
        } |
        Select-Object -First 1

    if ($null -eq $BuiltInAdministrator) {

        $Results += New-IdentityResult @{
            Control        = 'Built-in Administrator Account'
            Status         = 'INFO'
            Severity       = 'Info'
            Score          = 0
            MaxScore       = 0
            Evidence       = 'The built-in Administrator account could not be identified.'
            Recommendation = 'Review the built-in Administrator account manually.'
        }
    }
    elseif ($BuiltInAdministrator.Enabled -eq $false) {

        $Results += New-IdentityResult @{
            Control        = 'Built-in Administrator Account'
            Status         = 'PASS'
            Severity       = 'High'
            Score          = 20
            MaxScore       = 20
            Evidence       = "Built-in account '$($BuiltInAdministrator.Name)' is disabled."
            Recommendation = 'No action required.'
        }
    }
    else {

        $Results += New-IdentityResult @{
            Control        = 'Built-in Administrator Account'
            Status         = 'WARNING'
            Severity       = 'High'
            Score          = 5
            MaxScore       = 20
            Evidence       = "Built-in account '$($BuiltInAdministrator.Name)' is enabled."
            Recommendation = 'Review whether the built-in Administrator account must remain enabled. Prefer a separately managed administrative account when appropriate.'
        }
    }

    # ========================================================
    # 2. BUILT-IN GUEST
    #
    # RID 501
    # 15 points
    # ========================================================

    $GuestAccount = $LocalUsers |
        Where-Object {
            $_.SID -match '-501$'
        } |
        Select-Object -First 1

    if ($null -eq $GuestAccount) {

        $Results += New-IdentityResult @{
            Control        = 'Guest Account'
            Status         = 'INFO'
            Severity       = 'Info'
            Score          = 0
            MaxScore       = 0
            Evidence       = 'The built-in Guest account could not be identified.'
            Recommendation = 'Review the Guest account manually.'
        }
    }
    elseif ($GuestAccount.Enabled -eq $false) {

        $Results += New-IdentityResult @{
            Control        = 'Guest Account'
            Status         = 'PASS'
            Severity       = 'High'
            Score          = 15
            MaxScore       = 15
            Evidence       = "Built-in Guest account '$($GuestAccount.Name)' is disabled."
            Recommendation = 'No action required.'
        }
    }
    else {

        $Results += New-IdentityResult @{
            Control        = 'Guest Account'
            Status         = 'FAIL'
            Severity       = 'High'
            Score          = 0
            MaxScore       = 15
            Evidence       = "Built-in Guest account '$($GuestAccount.Name)' is enabled."
            Recommendation = 'Disable the built-in Guest account unless there is an explicit and documented requirement.'
        }
    }

    # ========================================================
    # 3. ENABLED LOCAL USERS REQUIRE PASSWORDS
    # 25 points
    # ========================================================

    $EnabledUsersWithoutPasswordRequirement = @(
        $LocalUsers |
            Where-Object {
                $_.Enabled -eq $true -and
                $_.PasswordRequired -eq $false -and
                $_.SID -notmatch '-501$'
            }
    )

    if ($EnabledUsersWithoutPasswordRequirement.Count -eq 0) {

        $Results += New-IdentityResult @{
            Control        = 'Non-Guest Local Accounts Require Password'
            Status         = 'PASS'
            Severity       = 'High'
            Score          = 25
            MaxScore       = 25
            Evidence       = 'All enabled local user accounts are configured to require a password.'
            Recommendation = 'No action required.'
        }
    }
    else {

        $Names = (
            $EnabledUsersWithoutPasswordRequirement.Name -join ', '
        )

        $Results += New-IdentityResult @{
            Control        = 'Non-Guest Local Accounts Require Password'
            Status         = 'FAIL'
            Severity       = 'High'
            Score          = 0
            MaxScore       = 25
            Evidence       = "Enabled non-Guest local accounts without a password requirement: $Names"
            Recommendation = 'Require passwords for all enabled non-Guest local accounts unless a documented exception exists.'
        }
    }

    # ========================================================
    # 4. DIRECT LOCAL ADMINISTRATORS REQUIRE PASSWORDS
    # 25 points
    # ========================================================

    if ($AdminMembers.Count -eq 0) {

        $Results += New-IdentityResult @{
            Control        = 'Local Administrators Require Password'
            Status         = 'ERROR'
            Severity       = 'Unknown'
            Score          = 0
            MaxScore       = 0
            Evidence       = 'Administrator membership could not be evaluated.'
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

            $Results += New-IdentityResult @{
                Control        = 'Local Administrators Require Password'
                Status         = 'PASS'
                Severity       = 'High'
                Score          = 25
                MaxScore       = 25
                Evidence       = 'No enabled direct local administrator account without a password requirement was detected.'
                Recommendation = 'No action required.'
            }
        }
        else {

            $Names = (
                $RiskyAdministrators.Name -join ', '
            )

            $Results += New-IdentityResult @{
                Control        = 'Local Administrators Require Password'
                Status         = 'FAIL'
                Severity       = 'High'
                Score          = 0
                MaxScore       = 25
                Evidence       = "Enabled local administrator accounts without a password requirement: $Names"
                Recommendation = 'Require strong authentication for every enabled local administrator account.'
            }
        }
    }

    # ========================================================
    # 5. ADMINISTRATOR MEMBERSHIP INTEGRITY
    # 15 points
    # ========================================================

    if ($AdminMembers.Count -eq 0) {

        $Results += New-IdentityResult @{
            Control        = 'Administrator Membership Integrity'
            Status         = 'ERROR'
            Severity       = 'Unknown'
            Score          = 0
            MaxScore       = 0
            Evidence       = 'Administrator group membership could not be evaluated.'
            Recommendation = 'Review the local Administrators group manually.'
        }
    }
    else {

        $UnresolvedMembers = @(
            $AdminMembers |
                Where-Object {
                    $_.Resolved -eq $false -or
                    [string]::IsNullOrWhiteSpace($_.SID)
                }
        )

        if ($UnresolvedMembers.Count -eq 0) {

            $Results += New-IdentityResult @{
                Control        = 'Administrator Membership Integrity'
                Status         = 'PASS'
                Severity       = 'Medium'
                Score          = 15
                MaxScore       = 15
                Evidence       = 'All detected Administrators group members were resolved to identifiable security principals.'
                Recommendation = 'No action required.'
            }
        }
        else {

            $Names = (
                $UnresolvedMembers.Name -join ', '
            )

            $Results += New-IdentityResult @{
                Control        = 'Administrator Membership Integrity'
                Status         = 'WARNING'
                Severity       = 'Medium'
                Score          = 5
                MaxScore       = 15
                Evidence       = "Unresolved or incomplete administrator principals detected: $Names"
                Recommendation = 'Review stale, unresolved, or orphaned entries in the local Administrators group.'
            }
        }
    }

    # ========================================================
    # NON-SCORED CHECK:
    # ENABLED ADMINISTRATORS WITH NON-EXPIRING PASSWORDS
    #
    # This is deliberately NOT scored.
    # Non-expiring passwords may be expected when an approved
    # rotation mechanism such as Windows LAPS is in use.
    # ========================================================

    $AdminsNeverExpire = @(
        $LocalAdministratorUsers |
            Where-Object {
                $_.Enabled -eq $true -and
                $_.PasswordNeverExpires -eq $true
            }
    )

    if ($AdminsNeverExpire.Count -gt 0) {

        $Names = (
            $AdminsNeverExpire.Name -join ', '
        )

        $Results += New-IdentityResult @{
            Control        = 'Administrator Password Expiration Review'
            Status         = 'WARNING'
            Severity       = 'Medium'
            Score          = 0
            MaxScore       = 0
            Evidence       = "Enabled local administrators with no password expiration date: $Names"
            Recommendation = 'Review whether these accounts are managed by Windows LAPS or another approved password rotation mechanism. Do not rely on arbitrary password expiration alone as a security control.'
        }
    }
    else {

        $Results += New-IdentityResult @{
            Control        = 'Administrator Password Expiration Review'
            Status         = 'INFO'
            Severity       = 'Info'
            Score          = 0
            MaxScore       = 0
            Evidence       = 'No enabled direct local administrator accounts with an indefinite password expiration state were detected.'
            Recommendation = 'No action required.'
        }
    }

    # ========================================================
    # NON-SCORED CHECK:
    # INACTIVE PRIVILEGED LOCAL ACCOUNTS
    # ========================================================

    $InactiveAdmins = @()
    $UnknownActivityAdmins = @()

    $CutoffDate = (Get-Date).AddDays(-$InactiveAdminDays)

    foreach ($AdminUser in $LocalAdministratorUsers) {

        if ($AdminUser.Enabled -ne $true) {
            continue
        }

        if ($null -eq $AdminUser.LastLogon) {

            $UnknownActivityAdmins += $AdminUser
            continue
        }

        if ($AdminUser.LastLogon -lt $CutoffDate) {
            $InactiveAdmins += $AdminUser
        }
    }

    if ($InactiveAdmins.Count -gt 0) {

        $InactiveEvidence = @(
            $InactiveAdmins |
                ForEach-Object {
                    "$($_.Name) (LastLogon=$($_.LastLogon))"
                }
        ) -join '; '

        $Results += New-IdentityResult @{
            Control        = 'Administrator Last Logon Review'
            Status         = 'INFO'
            Severity       = 'Info'
            Score          = 0
            MaxScore       = 0
            Evidence       = "Administrators with recorded LastLogon older than $InactiveAdminDays days: $InactiveEvidence"
            Recommendation = 'The recorded LastLogon value does not conclusively prove inactivity. Verify account activity using Windows security events before disabling or removing accounts.'
        }
    }
    elseif ($LocalAdministratorUsers.Count -gt 0) {

        $Results += New-IdentityResult @{
            Control        = 'Inactive Local Administrator Accounts'
            Status         = 'INFO'
            Severity       = 'Info'
            Score          = 0
            MaxScore       = 0
            Evidence       = "No enabled direct local administrator with a known LastLogon older than $InactiveAdminDays days was detected."
            Recommendation = 'Continue reviewing privileged account activity periodically.'
        }
    }

    if ($UnknownActivityAdmins.Count -gt 0) {

        $Names = (
            $UnknownActivityAdmins.Name -join ', '
        )

        $Results += New-IdentityResult @{
            Control        = 'Administrator Last Logon Visibility'
            Status         = 'INFO'
            Severity       = 'Info'
            Score          = 0
            MaxScore       = 0
            Evidence       = "LastLogon could not be determined for: $Names"
            Recommendation = 'Review account activity using Windows event logs or centralized identity telemetry when required.'
        }
    }

    # ========================================================
    # INFORMATIONAL INVENTORY:
    # LOCAL USERS
    # ========================================================

    foreach ($User in $LocalUsers | Sort-Object Name) {

        $LastLogonText = if ($null -eq $User.LastLogon) {
            'Unknown/Never'
        }
        else {
            [string]$User.LastLogon
        }

        $PasswordLastSetText = if ($null -eq $User.PasswordLastSet) {
            'Unknown/Never'
        }
        else {
            [string]$User.PasswordLastSet
        }

        $Results += New-IdentityResult @{
            Control        = "Local User: $($User.Name)"
            Status         = 'INFO'
            Severity       = 'Info'
            Score          = 0
            MaxScore       = 0
            Evidence       = "Enabled=$($User.Enabled); SID=$($User.SID); PasswordRequired=$($User.PasswordRequired); PasswordLastSet=$PasswordLastSetText; LastLogon=$LastLogonText; PrincipalSource=$($User.PrincipalSource)"
            Recommendation = 'Confirm that this local account is required and appropriately managed.'
        }
    }

    # ========================================================
    # INFORMATIONAL INVENTORY:
    # ADMINISTRATORS GROUP MEMBERS
    # ========================================================

    foreach ($Member in $AdminMembers | Sort-Object Name) {

        $SidText = if ([string]::IsNullOrWhiteSpace($Member.SID)) {
            'Unknown'
        }
        else {
            $Member.SID
        }

        $Results += New-IdentityResult @{
            Control        = "Administrator Member: $($Member.Name)"
            Status         = 'INFO'
            Severity       = 'Info'
            Score          = 0
            MaxScore       = 0
            Evidence       = "SID=$SidText; Type=$($Member.ObjectClass); Source=$($Member.PrincipalSource); Resolved=$($Member.Resolved)"
            Recommendation = 'Confirm that this principal requires local administrative privileges.'
        }
    }

    return $Results
}