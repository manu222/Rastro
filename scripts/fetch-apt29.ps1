<#
    Fetches the two days of the APT29 evaluation listed in
    tests/apt29-samples.txt into datasets-apt29/. Safe to run again: a
    directory that already holds its evidence is left alone unless -Force is
    given.
#>
[CmdletBinding()]
param([switch]$Force)

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$list = Join-Path $root 'tests\apt29-samples.txt'
$dest = Join-Path $root 'datasets-apt29'

$lines  = Get-Content $list
$commit = ($lines | Where-Object { $_ -match '^commit\s+(\S+)' } | Select-Object -First 1) -replace '^commit\s+', ''
if (-not $commit) { throw "no commit pinned in $list" }

New-Item -ItemType Directory -Force -Path $dest | Out-Null
Write-Host "Fetching the APT29 evaluation at $commit"

$staging = Join-Path ([System.IO.Path]::GetTempPath()) ("rastro-apt29-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $staging | Out-Null
Add-Type -AssemblyName System.IO.Compression.FileSystem

$fetched = 0
try {
    foreach ($line in $lines) {
        $text = $line.Trim()
        if (-not $text -or $text.StartsWith('#') -or $text.StartsWith('commit ')) { continue }
        $parts = $text -split '\s+'
        if ($parts.Count -lt 2) { throw "no destination for $text in $list" }
        $path, $sub = $parts[0], $parts[1]

        $name   = Split-Path -Leaf $path
        $isZeek = $name.EndsWith('zeek_logs.zip')
        $into   = Join-Path $dest $sub
        $marker = if ($isZeek) { Join-Path $into 'conn.log' } else { Join-Path $into 'host.json.gz' }
        if ((Test-Path $marker) -and -not $Force) { continue }
        New-Item -ItemType Directory -Force -Path $into | Out-Null

        $zip = Join-Path $staging $name
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/OTRF/Security-Datasets/$commit/$path" -OutFile $zip -UseBasicParsing

        $magic = New-Object byte[] 2
        $stream = [System.IO.File]::OpenRead($zip)
        try { $null = $stream.Read($magic, 0, 2) } finally { $stream.Dispose() }
        if ($magic[0] -ne 0x50 -or $magic[1] -ne 0x4B) { throw "what came back for $name is not an archive" }

        $archive = [System.IO.Compression.ZipFile]::OpenRead($zip)
        try {
            if ($isZeek) {
                foreach ($entry in $archive.Entries | Where-Object { $_.Name -like '*.log' }) {
                    [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, (Join-Path $into $entry.Name), $true)
                }
            } else {
                # Straight from the archive into gzip, so the several hundred
                # megabytes of JSON never land on disk uncompressed.
                $entry = $archive.Entries | Where-Object { $_.Name -like '*.json' } | Select-Object -First 1
                if (-not $entry) { throw "no host events in $name" }
                $src  = $entry.Open()
                $dst  = [System.IO.File]::Create((Join-Path $into 'host.json.gz'))
                $gzip = New-Object System.IO.Compression.GZipStream($dst, [System.IO.Compression.CompressionLevel]::Optimal)
                try { $src.CopyTo($gzip) } finally { $gzip.Dispose(); $dst.Dispose(); $src.Dispose() }
            }
        } finally {
            $archive.Dispose()
        }
        Remove-Item $zip -Force
        $fetched++
    }
} finally {
    if (Test-Path $staging) { Remove-Item $staging -Recurse -Force }
}

Write-Host "$fetched archive(s) unpacked into $dest"
