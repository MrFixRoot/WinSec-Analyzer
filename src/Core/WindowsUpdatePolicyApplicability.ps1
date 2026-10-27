# Pure applicability proof; no provider reads or inferred defaults.
function Test-WinSecWindowsUpdateLegacyPolicyPlatform {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Platform)
    # Microsoft introduces IgnoreWindowsUpdateGroupPolicies in 24H2 + KB5101684.
    # https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-update#ignorewindowsupdategrouppolicies
    # Restrict the exclusion to known Windows 11 client branches predating 24H2.
    return ($Platform.State -is [string] -and $Platform.State -ceq 'OBSERVED' -and ($Platform.ProductType -is [int] -or
        $Platform.ProductType -is [uint32] -or $Platform.ProductType -is [long]) -and
        $Platform.ProductType -eq 1 -and $Platform.BuildNumber -is [string] -and
        $Platform.BuildNumber -cin @('22000','22621','22631') -and
        $Platform.Version -is [string] -and $Platform.Version -ceq ('10.0.'+$Platform.BuildNumber))
}
