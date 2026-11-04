<#
    Fetches the Linux evidence listed in tests/linux-samples.txt into
    datasets-linux/. Safe to run again: existing files are left alone unless
    -Force is given.
#>
[CmdletBinding()]
param([switch]$Force)

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$list = Join-Path $root 'tests\linux-samples.txt'
$dest = Join-Path $root 'datasets-linux'

$lines  = Get-Content $list
$commit = ($lines | Where-Object { $_ -match '^commit\s+(\S+)' } | Select-Object -First 1) -replace '^commit\s+', ''
if (-not $commit) { throw "no commit pinned in $list" }

New-Item -ItemType Directory -Force -Path $dest | Out-Null
Write-Host "Fetching Linux samples at $commit"

$fetched = 0
foreach ($line in $lines) {
    $path = $line.Trim()
    if (-not $path -or $path.StartsWith('#') -or $path.StartsWith('commit ')) { continue }

    $name = Split-Path -Leaf $path
    $out  = Join-Path $dest $name
    if ((Test-Path $out) -and -not $Force) { continue }

    $url = "https://media.githubusercontent.com/media/splunk/attack_data/$commit/$path"
    Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing

    # A Git LFS pointer is a small text file starting with a version line.
    # Getting one back means the media endpoint served the pointer instead of
    # the content, and a rule run against it would quietly find nothing.
    $head = Get-Content $out -TotalCount 1
    if ($head -match 'git-lfs\.github\.com') {
        Remove-Item $out
        throw "got an LFS pointer instead of the sample: $name"
    }
    $fetched++
}

$total = (Get-ChildItem $dest -Filter *.log).Count
Write-Host "$fetched new file(s); $total in $dest"
