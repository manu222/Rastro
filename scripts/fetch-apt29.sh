#!/usr/bin/env bash
# Fetches the two days of the APT29 evaluation listed in tests/apt29-samples.txt
# into datasets-apt29/. Safe to run again: a directory that already holds its
# evidence is left alone unless --force is given.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
list="$root/tests/apt29-samples.txt"
dest="$root/datasets-apt29"
force="${1:-}"

commit="$(awk '/^commit /{print $2; exit}' "$list")"
if [[ -z "$commit" ]]; then
  echo "no commit pinned in $list" >&2
  exit 1
fi

mkdir -p "$dest"
echo "Fetching the APT29 evaluation at $commit"

staging="$(mktemp -d)"
trap 'rm -rf "$staging"' EXIT

fetched=0
while read -r path into; do
  [[ -z "$path" || "$path" == \#* || "$path" == commit ]] && continue
  if [[ -z "${into:-}" ]]; then
    echo "no destination for $path in $list" >&2
    exit 1
  fi

  name="$(basename "$path")"
  into="$dest/$into"
  if [[ "$name" == *zeek_logs.zip ]]; then marker="$into/conn.log"; else marker="$into/host.json.gz"; fi
  if [[ -f "$marker" && "$force" != "--force" ]]; then
    continue
  fi
  mkdir -p "$into"

  zip="$staging/$name"
  curl -sSL --fail --max-time 600 -o "$zip" \
    "https://raw.githubusercontent.com/OTRF/Security-Datasets/$commit/$path"
  if [[ "$(head -c 2 "$zip")" != "PK" ]]; then
    echo "what came back for $name is not an archive" >&2
    exit 1
  fi

  if [[ "$name" == *zeek_logs.zip ]]; then
    unzip -q -o -j "$zip" '*.log' -d "$into"
  else
    # One JSON file of several hundred megabytes, piped straight into gzip so
    # the uncompressed file never lands on disk. The reader takes it either way.
    if ! unzip -p "$zip" '*.json' | gzip -9 > "$into/host.json.gz" || [[ ! -s "$into/host.json.gz" ]]; then
      echo "no host events in $name" >&2
      rm -f "$into/host.json.gz"
      exit 1
    fi
  fi
  rm -f "$zip"
  fetched=$((fetched + 1))
done < "$list"

echo "$fetched archive(s) unpacked into $dest"
