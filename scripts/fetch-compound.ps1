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
        $marker = if ($isZeek) { Join-Path $into 'conn.log' } else { Join-Path $into 'host.json.gz' }
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

        if ($isZeek) {
            $unpacked = Join-Path $staging ($name -replace '\.zip$', '')
            Expand-Archive -Path $zip -DestinationPath $unpacked -Force
            foreach ($log in Get-ChildItem $unpacked -Filter *.log) {
                if ($notEvidence -contains $log.Name) { continue }
                Copy-Item $log.FullName (Join-Path $into $log.Name) -Force
            }
            Remove-Item $unpacked -Recurse -Force
        } else {
            # One JSON file per archive, named after the simulation. It is
            # renamed, because the campaign is already the directory and the
            # tool decides what a file is by its extension.
            #
            # And it is recompressed rather than left as it comes out. These
            # files are around a hundred megabytes each of which the great
            # majority is one Sysmon event — thirty thousand ProcessAccess
            # records in the first campaign — and seven campaigns unpacked come
            # to 687 MB to leave lying in a working directory. Gzipped they are
            # 25 MB, and the reader takes them either way.
            #
            # The entry is read straight out of the archive into gzip, so the
            # uncompressed file never lands on disk at all.
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            $archive = [System.IO.Compression.ZipFile]::OpenRead($zip)
            try {
                $entry = $archive.Entries | Where-Object { $_.Name -like '*.json' } | Select-Object -First 1
                if (-not $entry) { throw "no host events in $name" }

                $out  = Join-Path $into 'host.json.gz'
                $src  = $entry.Open()
                $dst  = [System.IO.File]::Create($out)
                $gzip = New-Object System.IO.Compression.GZipStream($dst, [System.IO.Compression.CompressionLevel]::Optimal)
                try { $src.CopyTo($gzip) } finally {
                    $gzip.Dispose(); $dst.Dispose(); $src.Dispose()
                }
            } finally {
                $archive.Dispose()
            }
        }

        Remove-Item $zip -Force
        $fetched++
    }
} finally {
    if (Test-Path $staging) { Remove-Item $staging -Recurse -Force }
}

$campaigns = (Get-ChildItem $dest -Directory).Count
Write-Host "$fetched archive(s) unpacked; $campaigns campaign(s) in $dest"
