# Definitions only: no Windows providers, authorization, file I/O or retry.
# Call only after the caller's independent approval, preflight and attempt receipt.
function Get-WinSecValidationDiagnostic {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('VALIDATOR_EXECUTION','SUMMARY_DECODING','SUMMARY_VALIDATION','SUMMARY_ENCODING','ATTEMPT_DISPATCH')][string]$Phase,
        [Parameter(Mandatory)][System.Management.Automation.ErrorRecord]$Failure
    )
    $components=@{VALIDATOR_EXECUTION='VALIDATION_HELPER';SUMMARY_DECODING='JSON_DECODER';
        SUMMARY_VALIDATION='SUMMARY_CONTRACT';SUMMARY_ENCODING='JSON_ENCODER';ATTEMPT_DISPATCH='ACCEPTANCE_RUNNER'}
    $category='UNKNOWN_ERROR'
    $exception=$Failure.Exception
    # Inspect only known exception types, never messages, targets, paths, IDs or stacks.
    for($depth=0;$null -ne $exception -and $depth -lt 8;$depth++) {
        if($exception -is [UnauthorizedAccessException] -or $exception -is [Security.SecurityException]){$category='ACCESS_DENIED';break}
        if($exception -is [TimeoutException]){$category='TIMEOUT';break}
        if($exception -is [OperationCanceledException] -or $exception -is [Management.Automation.PipelineStoppedException]){$category='CANCELLED';break}
        if($exception -is [IO.InvalidDataException]){$category='INVALID_DATA';break}
        if($exception -is [FormatException]){$category='FORMAT_ERROR';break}
        if($exception -is [IO.IOException]){$category='IO_ERROR';break}
        if($exception -is [Management.Automation.CommandNotFoundException]){$category='COMMAND_UNAVAILABLE';break}
        if($exception -is [NotSupportedException]){$category='NOT_SUPPORTED';break}
        $exception=$exception.InnerException
    }
    if($category -ceq 'UNKNOWN_ERROR' -and $Phase -ceq 'SUMMARY_DECODING'){$category='INVALID_JSON'}
    [pscustomobject][ordered]@{SchemaVersion='WinSec.ValidationDiagnostic1.0';Phase=$Phase;
        Component=$components[$Phase];Category=$category;AttemptConsumed=$true}
}

function Assert-WinSecValidationSummary {
    # The existing fourteen-field Defender acceptance summary, not a general report.
    [CmdletBinding()]
    param([object]$Summary,[string]$ExpectedOperationId,[string]$ExpectedRuntime)
    $fields=@('OperationId','Runtime','ExecutionStatus','CollectedControls','ObservedStatus','PublicFindings',
        'AssessmentMode','ReadingCount','PublicHistoryRoundtripValidated','InMemoryReports','ApplicabilityDiagnostics',
        'RawEvidencePersisted','PublicHistoryPersisted','WindowsChanges')
    if($null -eq $Summary -or $Summary -isnot [pscustomobject]){throw [IO.InvalidDataException]::new('Invalid validation summary.')}
    $properties=@($Summary.PSObject.Properties)
    if($properties.Count -ne $fields.Count){throw [IO.InvalidDataException]::new('Invalid validation summary.')}
    foreach($property in $properties){
        if($property.MemberType -ne 'NoteProperty' -or $property.Name -cnotin $fields){throw [IO.InvalidDataException]::new('Invalid validation summary.')}
    }
    foreach($field in @('RawEvidencePersisted','PublicHistoryPersisted','WindowsChanges','PublicHistoryRoundtripValidated')){
        if($Summary.$field -isnot [bool]){throw [IO.InvalidDataException]::new('Invalid validation summary.')}
    }
    if($Summary.OperationId -cne $ExpectedOperationId -or $Summary.Runtime -cne $ExpectedRuntime -or
        $Summary.RawEvidencePersisted -cne $false -or $Summary.PublicHistoryPersisted -cne $false -or
        $Summary.WindowsChanges -cne $false -or $Summary.PublicHistoryRoundtripValidated -cne $true -or
        $Summary.AssessmentMode -cne 'FRAMEWORK_REVIEW' -or $Summary.CollectedControls -ne 1 -or $Summary.InMemoryReports -ne 3 -or
        $Summary.ExecutionStatus -cnotin @('COMPLETED','COMPLETED_WITH_ERRORS') -or
        $Summary.ObservedStatus -cnotin @('INFORMATIONAL','UNKNOWN','PASS','FAIL','WARNING','NOT_APPLICABLE')){
        throw [IO.InvalidDataException]::new('Invalid validation summary.')
    }
    foreach($field in @('CollectedControls','PublicFindings','ReadingCount','InMemoryReports')){
        $value=$Summary.$field
        if(($value -isnot [int] -and $value -isnot [long]) -or $value -lt 0 -or $value -gt [int]::MaxValue){throw [IO.InvalidDataException]::new('Invalid validation summary.')}
    }
    $allowed=@('WINDOWS_SCOPE_MISMATCH','CRITERION_NOT_VERIFIED','DEPENDENCIES_NOT_DECLARED','PREREQUISITES_NOT_CONFIRMED')
    if($Summary.ApplicabilityDiagnostics -isnot [array]){throw [IO.InvalidDataException]::new('Invalid validation summary.')}
    foreach($item in $Summary.ApplicabilityDiagnostics){if($item -isnot [string] -or $item -cnotin $allowed){throw [IO.InvalidDataException]::new('Invalid validation summary.')}}
}

function Invoke-WinSecValidationDiagnosticAttempt {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][scriptblock]$ValidatorAction,
        [Parameter(Mandatory)][ValidatePattern('\A[a-f0-9]{32}\z')][string]$ExpectedOperationId,
        [Parameter(Mandatory)][ValidatePattern('\A[0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?\z')][string]$ExpectedRuntime,
        [Parameter(Mandatory)][psobject]$AttemptState
    )
    $ErrorActionPreference='Stop'
    $AttemptState.Diagnostic=$null
    $phase='VALIDATOR_EXECUTION';$streamFailure=$null
    try {
        # Capture all redirectable streams; unexpected output is never printed raw.
        $output=@(& $ValidatorAction *>&1)
        foreach($item in $output){if($item -is [Management.Automation.ErrorRecord]){$streamFailure=$item;throw [IO.InvalidDataException]::new('Validator emitted an error.')}}
        $phase='SUMMARY_DECODING'
        if($output.Count -ne 1 -or $output[0] -isnot [string] -or [Text.Encoding]::UTF8.GetByteCount($output[0]) -gt 65536){
            throw [IO.InvalidDataException]::new('Invalid validation output.')
        }
        $summary=ConvertFrom-Json -InputObject $output[0] -ErrorAction Stop
        $phase='SUMMARY_VALIDATION'
        Assert-WinSecValidationSummary $summary $ExpectedOperationId $ExpectedRuntime
        $phase='SUMMARY_ENCODING'
        ConvertTo-Json -InputObject $summary -Depth 6 -ErrorAction Stop
    } catch {
        $failure=if($null -ne $streamFailure){$streamFailure}else{$_}
        $diagnostic=Get-WinSecValidationDiagnostic -Phase $phase -Failure $failure
        $AttemptState.Diagnostic=$diagnostic
        $message='Validation failed. Phase={0}; Component={1}; Category={2}; attempt consumed; no retry.' -f $diagnostic.Phase,$diagnostic.Component,$diagnostic.Category
        $safeException=[InvalidOperationException]::new($message)
        $safeError=[Management.Automation.ErrorRecord]::new($safeException,
            ('WINSEC_VALIDATION_'+$diagnostic.Phase+'_'+$diagnostic.Category),[Management.Automation.ErrorCategory]::InvalidResult,$null)
        $PSCmdlet.ThrowTerminatingError($safeError)
    }
}
