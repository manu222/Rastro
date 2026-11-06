# Exports the event templates of the providers the normalise tables describe:
# one row per field of every event, with the outType the provider declares.
# internal/normalise/manifest.go was generated from this output on Windows 10
# Pro 10.0.19045. Read-only: it queries the installed manifests and writes CSV
# files to the directory given, the current one by default.
#
#   powershell -ExecutionPolicy Bypass -File scripts\manifest-forms.ps1 [-Out dir]
#
# A field that is win:HexInt32 or win:HexInt64 in at least one event goes into
# manifest.go; its default form is the one most of its events declare, and an
# event that declares otherwise is an exception. A provider that is not
# installed is reported and skipped.
param([string]$Out = '.')
foreach ($p in 'Microsoft-Windows-Security-Auditing','Microsoft-Windows-Eventlog','Microsoft-Windows-Sysmon') {
  try {
    $prov = Get-WinEvent -ListProvider $p -ErrorAction Stop
  } catch {
    "$p : not installed on this machine"
    continue
  }
  $rows = foreach ($e in $prov.Events) {
    if (-not $e.Template) { continue }
    ([xml]$e.Template).template.data | ForEach-Object {
      [pscustomobject]@{ id = $e.Id; version = $e.Version; field = $_.name; inType = $_.inType; outType = $_.outType }
    }
  }
  $rows | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $Out ($p + '.csv'))
  "$p : $(@($rows).Count) fields in $(@($prov.Events).Count) events"
}
