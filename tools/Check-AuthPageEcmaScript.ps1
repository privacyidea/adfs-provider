<#
.SYNOPSIS
    Fails if AuthPage.html uses JavaScript syntax that EdgeHTML 18 cannot parse.

.DESCRIPTION
    The AD FS login page (AuthPage.html) runs inside whatever engine the relying
    party uses. Office's legacy sign-in WebView uses EdgeHTML 18, whose script
    engine supports ECMAScript up to ES2017 (with some ES2018). It does not
    support ES2019 or later.

    EdgeHTML 18 compiles the whole <script> block at once. One unsupported token
    is a SyntaxError that discards the entire block, so no function is defined and
    the page renders every button unhidden (see issue about optional chaining).

    This check scans AuthPage.html for a denylist of post-ES2017 operators and
    built-in methods. It is a fast regex gate, not a full parser. Keep the login
    page at ES2017 so EdgeHTML 18 runs it.

.NOTES
    Run from the repository root:
        pwsh tools/Check-AuthPageEcmaScript.ps1
    Exit code 0 means clean. Exit code 1 means a forbidden feature was found.
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

# Each rule is a label and a regular expression. The expressions target tokens
# that are distinctive in JavaScript, so false positives are rare.
$rules = @(
    @{ Label = 'optional chaining (?.)  [ES2020]';        Pattern = '\?\.' }
    @{ Label = 'nullish coalescing (??)  [ES2020]';       Pattern = '\?\?' }
    @{ Label = 'logical assignment (||= &&= ??=)  [ES2021]'; Pattern = '(\|\|=|&&=|\?\?=)' }
    @{ Label = 'numeric separator (1_000)  [ES2021]';     Pattern = '\d_\d' }
    @{ Label = 'Array.flat / flatMap  [ES2019]';          Pattern = '\.(flat|flatMap)\s*\(' }
    @{ Label = 'Object.fromEntries  [ES2019]';            Pattern = 'Object\.fromEntries' }
    @{ Label = 'String.trimStart / trimEnd  [ES2019]';    Pattern = '\.(trimStart|trimEnd)\s*\(' }
    @{ Label = 'String.matchAll  [ES2020]';               Pattern = '\.matchAll\s*\(' }
    @{ Label = 'Promise.allSettled / any  [ES2020/2021]'; Pattern = 'Promise\.(allSettled|any)' }
    @{ Label = 'String.replaceAll  [ES2021]';             Pattern = '\.replaceAll\s*\(' }
    @{ Label = 'globalThis  [ES2020]';                    Pattern = '\bglobalThis\b' }
    @{ Label = 'BigInt  [ES2020]';                        Pattern = '\bBigInt\b' }
    @{ Label = 'WeakRef  [ES2021]';                       Pattern = '\bWeakRef\b' }
    @{ Label = 'Object.hasOwn  [ES2022]';                 Pattern = 'Object\.hasOwn' }
    @{ Label = '.at( index  [ES2022]';                    Pattern = '\.at\s*\(' }
)

$lines = Get-Content -LiteralPath $Path
$findings = @()
for ($i = 0; $i -lt $lines.Count; $i++) {
    $line = $lines[$i]
    foreach ($rule in $rules) {
        if ($line -match $rule.Pattern) {
            $findings += [pscustomobject]@{ Line = $i + 1; Label = $rule.Label; Text = $line.Trim() }
        }
    }
}

if ($findings.Count -gt 0) {
    Write-Host "AuthPage.html uses JavaScript that EdgeHTML 18 cannot parse:" -ForegroundColor Red
    foreach ($f in $findings) {
        Write-Host ("  line {0}: {1}" -f $f.Line, $f.Label)
        Write-Host ("    {0}" -f $f.Text) -ForegroundColor DarkGray
    }
    Write-Host ""
    Write-Host "Rewrite these to ES2017. One unsupported token disables the whole login script." -ForegroundColor Yellow
    exit 1
}

Write-Host "AuthPage.html: no post-ES2017 JavaScript found." -ForegroundColor Green
exit 0
