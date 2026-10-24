# Pure criterion metadata validation. Importing this file never queries Windows.
function Get-WinSecCriterionWeight {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Criterion,[switch]$Required)
    $present=$false;$value=$null
    if($Criterion -is [System.Collections.IDictionary]) {
        $present=$Criterion.Contains('Weight')
        if($present){$value=$Criterion['Weight']}
    } else {
        $property=$Criterion.PSObject.Properties['Weight']
        $present=($null -ne $property)
        if($present) {
            if($property.MemberType -notin @('Property','NoteProperty')){throw 'Criterion weight must be data, not a getter.'}
            $value=$property.Value
        }
    }
    if(-not $present) {
        if($Required){throw 'A weighted public criterion must record its weight.'}
        return 1
    }
    if(($value -isnot [byte] -and $value -isnot [sbyte] -and $value -isnot [int16] -and $value -isnot [uint16] -and
        $value -isnot [int] -and $value -isnot [uint32] -and $value -isnot [long] -and $value -isnot [uint64]) -or
        [decimal]$value -lt 1 -or [decimal]$value -gt 100){throw 'Criterion weight must be an integer from 1 through 100.'}
    return [int]$value
}
