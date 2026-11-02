# Definitions only: no Windows providers, authorization, file I/O or retry.
# Call only after the caller's independent approval, preflight and attempt receipt.
function Get-WinSecValidationDiagnostic {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Phase,
        [Parameter(Mandatory)][System.Management.Automation.ErrorRecord]$Failure,
        [string]$Reason='UNCLASSIFIED'
    )
    $components=@{VALIDATOR_EXECUTION='VALIDATION_HELPER';SUMMARY_DECODING='JSON_DECODER';
        SUMMARY_VALIDATION='SUMMARY_CONTRACT';SUMMARY_ENCODING='JSON_ENCODER';ATTEMPT_DISPATCH='ACCEPTANCE_RUNNER'}
    $nativeComponents=Get-WinSecNativeValidationComponents
    $reasons=Get-WinSecNativeValidationReasons
    if($Phase -cnotin @($components.Keys) -and $Phase -cnotin @($nativeComponents.Keys)){throw 'Unknown diagnostic phase.'}
    if($Reason -cne 'UNCLASSIFIED' -and $Reason -cnotin @($reasons.Keys)){throw 'Unknown diagnostic reason.'}
    if($Reason -cne 'UNCLASSIFIED' -and $Phase -cne (Get-WinSecNativeValidationReasonPhases)[$Reason]){throw 'Diagnostic reason does not match phase.'}
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
        if($exception -is [Management.Automation.ParameterBindingException]){$category='PARAMETER_BINDING';break}
        if($exception -is [InvalidCastException] -or $exception -is [Management.Automation.PSInvalidCastException]){$category='TYPE_CONVERSION';break}
        $exception=$exception.InnerException
    }
    if($category -ceq 'UNKNOWN_ERROR' -and $Phase -ceq 'SUMMARY_DECODING'){$category='INVALID_JSON'}
    if($nativeComponents.ContainsKey($Phase)){
        if($Reason -cne 'UNCLASSIFIED'){$category=$reasons[$Reason]}
        return [pscustomobject][ordered]@{SchemaVersion='WinSec.ValidationDiagnostic1.1';Phase=$Phase;
            Component=$nativeComponents[$Phase];Category=$category;AttemptConsumed=$true;Reason=$Reason}
    }
    [pscustomobject][ordered]@{SchemaVersion='WinSec.ValidationDiagnostic1.0';Phase=$Phase;Component=$components[$Phase];Category=$category;AttemptConsumed=$true}
}

function Get-WinSecNativeValidationComponents {
    @{NATIVE_BOOTSTRAP='VALIDATION_BOOTSTRAP';NATIVE_IDENTITY='LOCAL_IDENTITY_PROVIDER';NATIVE_REQUEST='REQUEST_BUILDER';
        NATIVE_APPROVAL='AUTHORIZATION';NATIVE_INVENTORY='INVENTORY_AUTHORIZATION';NATIVE_REGISTRY='ISOLATED_REGISTRY';
        NATIVE_COORDINATOR='SCAN_COORDINATOR';NATIVE_SCAN='SCAN_EXECUTION';NATIVE_STATUS_PROVIDER='DEFENDER_STATUS_PROVIDER';
        NATIVE_NORMALIZATION='AUDIT_NORMALIZER';NATIVE_CHECK_EXECUTION='CHECK_EXECUTION';NATIVE_CONTROL_VALIDATION='CONTROL_RESULT_CONTRACT';
        NATIVE_HISTORY_WRITE='PUBLIC_HISTORY_ENCODER';NATIVE_HISTORY_READ='PUBLIC_HISTORY_DECODER';
        NATIVE_HISTORY_VALIDATION='PUBLIC_HISTORY_CONTRACT';NATIVE_TECHNICAL_PROJECTION='TECHNICAL_NORMALIZER';
        NATIVE_NIST_ANALYSIS='NIST_ANALYSIS';NATIVE_CIS_ANALYSIS='CIS_ANALYSIS';NATIVE_MITRE_ANALYSIS='MITRE_ANALYSIS';
        NATIVE_NIST_MARKDOWN='NIST_MARKDOWN';NATIVE_CIS_MARKDOWN='CIS_MARKDOWN';NATIVE_MITRE_MARKDOWN='MITRE_MARKDOWN';
        NATIVE_FRAMEWORK_VALIDATION='FRAMEWORK_RESULT_CONTRACT';NATIVE_SUMMARY='SUMMARY_BUILDER';NATIVE_SERIALIZATION='SUMMARY_SERIALIZER'}
}
function Get-WinSecNativeValidationReasons {
    @{APPROVAL_REJECTED='AUTHORIZATION_REJECTED';TARGET_REMOVED='AUTHORIZATION_REVOKED';PERSISTENCE_ENABLED='POLICY_REJECTED';
        CONTROL_RESULT_REJECTED='CONTROL_RESULT_REJECTED';STATUS_UNAVAILABLE='PROVIDER_UNAVAILABLE';STATUS_UNUSABLE='TELEMETRY_UNUSABLE';
        NORMALIZATION_REJECTED='NORMALIZATION_REJECTED';CHECK_EXECUTION_FAILED='EXECUTION_REJECTED';RATING_PRESENT='POLICY_REJECTED';HISTORY_MISMATCH='INTEGRITY_REJECTED';FRAMEWORK_MISMATCH='INTEGRITY_REJECTED'}
}
function Get-WinSecNativeValidationReasonPhases {
    @{APPROVAL_REJECTED='NATIVE_APPROVAL';TARGET_REMOVED='NATIVE_INVENTORY';PERSISTENCE_ENABLED='NATIVE_COORDINATOR';
        CONTROL_RESULT_REJECTED='NATIVE_CONTROL_VALIDATION';STATUS_UNAVAILABLE='NATIVE_STATUS_PROVIDER';STATUS_UNUSABLE='NATIVE_STATUS_PROVIDER';
        NORMALIZATION_REJECTED='NATIVE_NORMALIZATION';CHECK_EXECUTION_FAILED='NATIVE_CHECK_EXECUTION';RATING_PRESENT='NATIVE_CONTROL_VALIDATION';HISTORY_MISMATCH='NATIVE_HISTORY_VALIDATION';FRAMEWORK_MISMATCH='NATIVE_FRAMEWORK_VALIDATION'}
}
function Copy-WinSecNativeValidationDiagnostic {
    param([AllowNull()][object]$Diagnostic)
    if($null -eq $Diagnostic -or $Diagnostic -isnot [pscustomobject]){return $null}
    $fields=@('SchemaVersion','Phase','Component','Category','AttemptConsumed','Reason')
    $properties=@($Diagnostic.PSObject.Properties)
    if($properties.Count -ne 6){return $null}
    foreach($p in $properties){if($p.MemberType -ne 'NoteProperty' -or $p.Name -cnotin $fields){return $null}}
    foreach($name in @('SchemaVersion','Phase','Component','Category','Reason')){if($Diagnostic.$name -isnot [string]){return $null}}
    $components=Get-WinSecNativeValidationComponents;$reasons=Get-WinSecNativeValidationReasons
    if($Diagnostic.SchemaVersion -cne 'WinSec.ValidationDiagnostic1.1' -or $Diagnostic.Phase -isnot [string] -or
        $Diagnostic.Phase -cnotin @($components.Keys) -or $Diagnostic.Component -cne $components[$Diagnostic.Phase] -or
        $Diagnostic.AttemptConsumed -isnot [bool] -or $Diagnostic.AttemptConsumed -cne $true -or $Diagnostic.Reason -isnot [string]){return $null}
    $categories=@('UNKNOWN_ERROR','ACCESS_DENIED','TIMEOUT','CANCELLED','INVALID_DATA','FORMAT_ERROR','IO_ERROR','COMMAND_UNAVAILABLE','NOT_SUPPORTED','PARAMETER_BINDING','TYPE_CONVERSION')
    if($Diagnostic.Reason -ceq 'UNCLASSIFIED'){if($Diagnostic.Category -cnotin $categories){return $null}}
    elseif($Diagnostic.Reason -cnotin @($reasons.Keys) -or $Diagnostic.Category -cne $reasons[$Diagnostic.Reason] -or
        $Diagnostic.Phase -cne (Get-WinSecNativeValidationReasonPhases)[$Diagnostic.Reason]){return $null}
    [pscustomobject][ordered]@{SchemaVersion='WinSec.ValidationDiagnostic1.1';Phase=$Diagnostic.Phase;Component=$Diagnostic.Component;
        Category=$Diagnostic.Category;AttemptConsumed=$true;Reason=$Diagnostic.Reason}
}
function Get-WinSecNativeDiagnosticField {
    param([object]$InputObject,[string]$Name)
    if($null -eq $InputObject){return $null}
    $property=$InputObject.PSObject.Properties[$Name]
    if($null -ne $property -and $property.MemberType -eq 'NoteProperty'){return ,$property.Value}
    return $null
}
function Set-WinSecNativeValidationFailure {
    param([psobject]$State,[string]$Phase,[string]$Reason='UNCLASSIFIED',[Management.Automation.ErrorRecord]$Failure)
    if($null -ne $State.Diagnostic){return}
    if($null -eq $Failure){$Failure=[Management.Automation.ErrorRecord]::new([IO.InvalidDataException]::new('Validation rejected.'),'VALIDATION_REJECTED',[Management.Automation.ErrorCategory]::InvalidData,$null)}
    $State.Diagnostic=Get-WinSecValidationDiagnostic -Phase $Phase -Reason $Reason -Failure $Failure
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
        $diagnostic=Copy-WinSecNativeValidationDiagnostic $AttemptState.Diagnostic
        if($null -eq $diagnostic){$diagnostic=Get-WinSecValidationDiagnostic -Phase $phase -Failure $failure}
        $AttemptState.Diagnostic=$diagnostic
        $message='Validation failed. Phase={0}; Component={1}; Category={2}; attempt consumed; no retry.' -f $diagnostic.Phase,$diagnostic.Component,$diagnostic.Category
        $safeException=[InvalidOperationException]::new($message)
        $safeError=[Management.Automation.ErrorRecord]::new($safeException,
            ('WINSEC_VALIDATION_'+$diagnostic.Phase+'_'+$diagnostic.Category),[Management.Automation.ErrorCategory]::InvalidResult,$null)
        $PSCmdlet.ThrowTerminatingError($safeError)
    }
}
