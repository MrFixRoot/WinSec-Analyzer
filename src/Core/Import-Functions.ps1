# ============================================================
# WINSEC ANALYZER
# Function Loader
# ============================================================

$SrcPath = Split-Path -Parent $PSScriptRoot

# ============================================================
# FUNCTION DIRECTORIES
# ============================================================

$FunctionDirectories = @(
    'functions'
    'UI'
    'Checks'
)

# ============================================================
# IMPORT FUNCTIONS
# ============================================================

foreach ($Directory in $FunctionDirectories) {

    $DirectoryPath = Join-Path $SrcPath $Directory

    if (-not (Test-Path -LiteralPath $DirectoryPath -PathType Container)) {
        throw "Required directory not found: $DirectoryPath"
    }

    $ScriptFiles = Get-ChildItem `
        -LiteralPath $DirectoryPath `
        -Filter '*.ps1' `
        -File `
        -Recurse |
        Sort-Object FullName

    foreach ($ScriptFile in $ScriptFiles) {

        try {
            . $ScriptFile.FullName
        }
        catch {
            throw "Failed to import script '$($ScriptFile.Name)': $($_.Exception.Message)"
        }

    }

}
