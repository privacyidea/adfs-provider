<#
.SYNOPSIS
    Fails if the AuthPage.html script cannot run in Internet Explorer 11.

.DESCRIPTION
    The AD FS login page (AuthPage.html) runs inside whatever engine the client uses. Office sign-in
    windows on older systems embed the Internet Explorer 11 engine or the legacy Edge engine (EdgeHTML 18).
    Internet Explorer 11 supports only ES5. Both engines compile the whole <script> block at once, so one
    unsupported token is a syntax error that disables every function on the page. The page then shows all
    login options, push does not poll, and a remembered device does not sign in.

    This check runs in two parts:

    1. Syntax. It compiles the page script with the Internet Explorer script engine (jscript9.dll) through
       cscript.exe. The script is wrapped in a function that is never called, so it is compiled but not run.
       From the command line this engine is stricter than Internet Explorer 11 in standards mode: it also
       rejects let, const and trailing commas in object literals. So code that passes this check also
       parses in Internet Explorer 11.

    2. Browser functions. A regular-expression scan finds browser functions that Internet Explorer 11 does
       not have. Calling one of them in the main login path is a runtime error that stops the rest of the
       script. Code that needs a newer function must check for it first and is then listed as allowed below.

.NOTES
    Run from the repository root on Windows:
        pwsh tools/Check-AuthPageEcmaScript.ps1
    Exit code 0 means clean. Exit code 1 means a problem was found. Exit code 2 means the check could
    not run.
#>
[CmdletBinding()]
param(
    [string]$Path = (Join-Path $PSScriptRoot '..\privacyIDEAADFSProvider\AuthPage.html')
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $Path)) {
    Write-Error "Not found: $Path"
    exit 2
}

$lines = Get-Content -LiteralPath $Path
$start = -1
$end = -1
for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($start -lt 0 -and $lines[$i] -match '<script>') { $start = $i }
    elseif ($start -ge 0 -and $lines[$i] -match '</script>') { $end = $i; break }
}
if ($start -lt 0 -or $end -lt 0) {
    Write-Host "No <script> block found in $Path." -ForegroundColor Red
    exit 2
}
# Page line (1-based) of the first script line.
$firstScriptLine = $start + 2
$script = $lines[($start + 1)..($end - 1)]

$failed = $false

# --- 1. Syntax: compile with the Internet Explorer script engine ------------------------------------------
# {16d51579-a30b-4c8b-a276-0ff4dc41e755} is the CLSID of the Internet Explorer 9-11 script engine (jscript9).
$engine = '//E:{16d51579-a30b-4c8b-a276-0ff4dc41e755}'
$temp = Join-Path ([System.IO.Path]::GetTempPath()) ("authpage-check-" + [guid]::NewGuid().ToString('N') + '.js')
try {
    $wrapped = @('function __piCompileCheck() {') + $script + @('}')
    Set-Content -LiteralPath $temp -Value $wrapped -Encoding UTF8
    $output = & cscript.exe //nologo $engine $temp 2>&1 | Out-String
    $exit = $LASTEXITCODE
}
finally {
    Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
}

if ($output -match 'compilation error') {
    $failed = $true
    $location = [regex]::Match($output, '\((\d+),\s*(\d+)\)')
    if ($location.Success) {
        # The wrapper adds one line before the script.
        $pageLine = [int]$location.Groups[1].Value - 2 + $firstScriptLine
        $column = $location.Groups[2].Value
        Write-Host "AuthPage.html line $pageLine, column ${column}: Internet Explorer cannot compile the script." -ForegroundColor Red
        Write-Host ("    " + $lines[$pageLine - 1].Trim()) -ForegroundColor DarkGray
    }
    Write-Host ("    Engine output: " + $output.Trim()) -ForegroundColor DarkGray
}
elseif ($exit -ne 0 -or $output.Trim().Length -gt 0) {
    Write-Host "Could not run the Internet Explorer script engine through cscript.exe:" -ForegroundColor Red
    Write-Host ("    " + $output.Trim()) -ForegroundColor DarkGray
    exit 2
}

# --- 2. Browser functions that Internet Explorer 11 does not have ------------------------------------------
$rules = @(
    @{ Label = 'Number.isFinite (use isFinite)';                          Pattern = 'Number\.isFinite' }
    @{ Label = 'Element.remove() (use parentNode.removeChild)';           Pattern = '\.remove\(\s*\)' }
    @{ Label = 'includes() (use indexOf)';                                Pattern = '\.includes\(' }
    @{ Label = 'Array.from (use a for loop)';                             Pattern = '\bArray\.from\b' }
    @{ Label = 'padStart / padEnd';                                       Pattern = '\.(padStart|padEnd)\(' }
    @{ Label = 'String.fromCodePoint (use String.fromCharCode)';          Pattern = 'String\.fromCodePoint' }
    @{ Label = 'Object.assign';                                           Pattern = 'Object\.assign' }
    @{ Label = 'Element.closest';                                         Pattern = '\.closest\(' }
    @{ Label = 'Array.flat / flatMap';                                    Pattern = '\.(flat|flatMap)\s*\(' }
    @{ Label = 'Object.fromEntries';                                      Pattern = 'Object\.fromEntries' }
    @{ Label = 'String.trimStart / trimEnd / matchAll / replaceAll';      Pattern = '\.(trimStart|trimEnd|matchAll|replaceAll)\s*\(' }
    @{ Label = 'Promise.allSettled / Promise.any';                        Pattern = 'Promise\.(allSettled|any)' }
    @{ Label = 'globalThis / BigInt / WeakRef';                           Pattern = '\b(globalThis|BigInt|WeakRef)\b' }
    @{ Label = 'Object.hasOwn';                                           Pattern = 'Object\.hasOwn' }
)

for ($i = 0; $i -lt $script.Count; $i++) {
    # Ignore the text after "//" so that comments do not trigger a rule.
    $code = $script[$i] -replace '//.*$', ''
    foreach ($rule in $rules) {
        if ($code -match $rule.Pattern) {
            $failed = $true
            $pageLine = $firstScriptLine + $i
            Write-Host "AuthPage.html line ${pageLine}: $($rule.Label) does not exist in Internet Explorer 11." -ForegroundColor Red
            Write-Host ("    " + $script[$i].Trim()) -ForegroundColor DarkGray
        }
    }
}

if ($failed) {
    Write-Host ""
    Write-Host "Keep the AuthPage.html script at ES5, and check for newer browser functions before you call them." -ForegroundColor Yellow
    exit 1
}

Write-Host "AuthPage.html: the script compiles in Internet Explorer and uses no function that Internet Explorer 11 lacks." -ForegroundColor Green
exit 0
