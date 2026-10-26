# Real validator/coordinator/collector/public pipeline; all native IO is mocked.
# The shared fixture runs integration scenarios only; never a native audit.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
& (Join-Path $PSScriptRoot '../Unit/WindowsUpdateNativeValidation.Test.ps1') -Integration
