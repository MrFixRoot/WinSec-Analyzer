# Verified platform exclusions are criterion metadata, never inferred from missing telemetry.
function Get-WinSecCriterionPlatformExclusion {
    [CmdletBinding()]
    param([object]$Criterion,[AllowNull()][object]$TargetContext=$null)
    $property=$Criterion.PSObject.Properties['NotApplicableTargets']
    if($Criterion -is [System.Collections.IDictionary]) {
        if(-not $Criterion.Contains('NotApplicableTargets')){return}
        $entries=$Criterion['NotApplicableTargets']
    } else {
        if($null -eq $property){return}
        if($property.MemberType -ne 'NoteProperty'){throw 'Invalid platform exclusion property.'}
        $entries=$property.Value
    }
    if($entries -isnot [array] -or $entries.Count -eq 0 -or $entries.Count -gt 128){throw 'Invalid platform exclusion list.'}
    $seen=@{};$match=$null
    foreach($entry in $entries) {
        if($entry -isnot [pscustomobject]){throw 'Invalid platform exclusion entry.'}
        $fields=@('OSRelease','Edition','Reason','SourceUrl')
        if(@($entry.PSObject.Properties).Count -ne $fields.Count){throw 'Invalid platform exclusion fields.'}
        foreach($p in $entry.PSObject.Properties) {
            $limit=if($p.Name -ceq 'SourceUrl'){1024}else{256}
            if($p.MemberType -ne 'NoteProperty' -or $p.Name -cnotin $fields -or $p.Value -isnot [string] -or
                [string]::IsNullOrWhiteSpace($p.Value) -or $p.Value.Length -gt $limit -or $p.Value -match '[\p{C}]') {
                throw 'Invalid platform exclusion value.'
            }
        }
        $uri=$null
        if($entry.OSRelease -cnotmatch '\AWindows 11 10\.0\.\d{5}\z' -or $entry.Edition -cnotmatch '\ASKU:\d{1,3}\z' -or
            -not [Uri]::TryCreate($entry.SourceUrl,[UriKind]::Absolute,[ref]$uri) -or $uri.Scheme -cne 'https' -or
            $uri.UserInfo -or $uri.Query -or $uri.Fragment){throw 'Platform exclusion requires an exact Windows build/SKU and safe source.'}
        $key=$entry.OSRelease+'|'+$entry.Edition
        if($seen.ContainsKey($key)){throw 'Duplicate platform exclusion.'};$seen[$key]=$true
        if($null -ne $TargetContext -and $TargetContext.OSFamily -eq 'Windows' -and
            $TargetContext.OSRelease -eq $entry.OSRelease -and $TargetContext.Edition -eq $entry.Edition){$match=$entry}
    }
    if($null -ne $match){return $match}
}
