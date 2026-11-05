<#
    Fetches the paired host and network evidence listed in
    tests/compound-samples.txt into datasets-compound/. Safe to run again:
    a campaign that is already unpacked is left alone unless -Force is given.
#>
[CmdletBinding()]
param([switch]$Force)

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$list = Join-Path $root 'tests\compound-samples.txt'
$dest = Join-Path $root 'datasets-compound'

$lines  = Get-Content $list
$commit = ($lines | Where-Object { $_ -match '^commit\s+(\S+)' } | Select-Object -First 1) -replace '^commit\s+', ''
if (-not $commit) { throw "no commit pinned in $list" }

# Zeek's own operational logs. They say what the sensor was doing rather than
# what happened on the wire, so they are evidence of nothing and are dropped
# here instead of being counted as records that could not be read.
$notEvidence = @('analyzer.log', 'packet_filter.log', 'loaded_scripts.log', 'reporter.log', 'stats.log')

New-Item -ItemType Directory -Force -Path $dest | Out-Null
Write-Host "Fetching compound evidence at $commit"

$staging = Join-Path ([System.IO.Path]::GetTempPath()) ("rastro-compound-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $staging | Out-Null

$fetched = 0
try {
    foreach ($line in $lines) {
        $path = $line.Trim()
        if (-not $path -or $path.StartsWith('#') -or $path.StartsWith('commit ')) { continue }

        $campaign = Split-Path -Leaf (Split-Path -Parent $path)
        $name     = Split-Path -Leaf $path
        $isZeek   = $name.EndsWith('_zeek_logs.zip')

        $into = Join-Path $dest $campaign
        New-Item -ItemType Directory -Force -Path $into | Out-Null

        # What this half of the campaign produces, used to decide whether the
        # work has already been done.
        $marker = if ($isZeek) { Join-Path $into 'conn.log' } else { Join-Path $into 'host.json' }
        if ((Test-Path $marker) -and -not $Force) { continue }

        $zip = Join-Path $staging $name
        $url = "https://raw.githubusercontent.com/OTRF/Security-Datasets/$commit/$path"
        Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing

        # An error page is served with a 200 often enough to be worth checking
        # for, and an archive that is really HTML fails later and further away.
        $magic = New-Object byte[] 2
        $stream = [System.IO.File]::OpenRead($zip)
        try { $null = $stream.Read($magic, 0, 2) } finally { $stream.Dispose() }
        if ($magic[0] -ne 0x50 -or $magic[1] -ne 0x4B) {
            throw "what came back for $name is not an archive"
        }

        $unpacked = Join-Path $staging ($name -replace '\.zip$', '')
        Expand-Archive -Path $zip -DestinationPath $unpacked -Force

        if ($isZeek) {
            foreach ($log in Get-ChildItem $unpacked -Filter *.log) {
                if ($notEvidence -contains $log.Name) { continue }
                Copy-Item $log.FullName (Join-Path $into $log.Name) -Force
            }
        } else {
            # One JSON file per archive, named after the simulation. It is
            # renamed, because the campaign is already the directory and the
            # tool decides what a file is by its extension.
            $json = Get-ChildItem $unpacked -Filter *.json | Select-Object -First 1
            if (-not $json) { throw "no host events in $name" }
            Copy-Item $json.FullName (Join-Path $into 'host.json') -Force
        }

        Remove-Item $zip -Force
        Remove-Item $unpacked -Recurse -Force
        $fetched++
    }
} finally {
    if (Test-Path $staging) { Remove-Item $staging -Recurse -Force }
}

$campaigns = (Get-ChildItem $dest -Directory).Count
Write-Host "$fetched archive(s) unpacked; $campaigns campaign(s) in $dest"
