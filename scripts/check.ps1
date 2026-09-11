# Runs the same checks as CI, locally, before pushing.
#
#   .\scripts\check.ps1
#
# Stops at the first failure. Green here does not guarantee green in CI, but it
# catches almost everything, and far faster than waiting for a run.

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

function Step($name, $block) {
    Write-Host ""
    Write-Host "=== $name " -ForegroundColor Cyan -NoNewline
    Write-Host ("=" * [Math]::Max(0, 60 - $name.Length)) -ForegroundColor Cyan
    & $block
    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        Write-Host "FAILED: $name" -ForegroundColor Red
        exit 1
    }
}

Step "Rule syntax" { sigma check rules/ }

Step "Go vet" { go vet ./... }

# RASTRO_REQUIRE_TOOLS mirrors CI: a missing dataset or binary becomes a failure
# instead of a silently skipped test.
Step "Rule tests" {
    $env:RASTRO_REQUIRE_TOOLS = "1"
    go test ./... -v
}

Write-Host ""
Write-Host "=== About to commit " -ForegroundColor Cyan -NoNewline
Write-Host ("=" * 44) -ForegroundColor Cyan
git status --short

# Files that should never reach the repository, regardless of .gitignore.
$staged = git diff --cached --name-only
$suspect = $staged | Where-Object {
    $_ -match '\.exe$' -or $_ -match '\.csv$' -or $_ -match 'datasets/' -or $_ -match 'tools/'
}
if ($suspect) {
    Write-Host ""
    Write-Host "WARNING: these staged paths look like build output or external data:" -ForegroundColor Yellow
    $suspect | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
    Write-Host "Unstage them with: git restore --staged <path>" -ForegroundColor Yellow
    exit 1
}

Write-Host ""
Write-Host "All checks passed." -ForegroundColor Green
