#!/usr/bin/env bash
# Fetches the paired host and network evidence listed in
# tests/compound-samples.txt into datasets-compound/. Safe to run again: a
# campaign that is already unpacked is left alone unless --force is given.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
list="$root/tests/compound-samples.txt"
dest="$root/datasets-compound"
force="${1:-}"

commit="$(awk '/^commit /{print $2; exit}' "$list")"
if [[ -z "$commit" ]]; then
  echo "no commit pinned in $list" >&2
  exit 1
fi

# Zeek's own operational logs. They say what the sensor was doing rather than
# what happened on the wire, so they are evidence of nothing and are dropped
# here instead of being counted as records that could not be read.
not_evidence="analyzer.log packet_filter.log loaded_scripts.log reporter.log stats.log"

mkdir -p "$dest"
echo "Fetching compound evidence at $commit"

staging="$(mktemp -d)"
trap 'rm -rf "$staging"' EXIT

fetched=0
while read -r path; do
  [[ -z "$path" || "$path" == \#* || "$path" == commit\ * ]] && continue

  campaign="$(basename "$(dirname "$path")")"
  name="$(basename "$path")"
  into="$dest/$campaign"
  mkdir -p "$into"

  # What this half of the campaign produces, used to decide whether the work
  # has already been done.
  if [[ "$name" == *_zeek_logs.zip ]]; then
    marker="$into/conn.log"
  else
    marker="$into/host.json.gz"
  fi
  if [[ -f "$marker" && "$force" != "--force" ]]; then
    continue
  fi

  zip="$staging/$name"
  url="https://raw.githubusercontent.com/OTRF/Security-Datasets/$commit/$path"
  curl -sSL --fail --max-time 300 -o "$zip" "$url"

  # An error page is served with a 200 often enough to be worth checking for,
  # and an archive that is really HTML fails later and further away.
  if [[ "$(head -c 2 "$zip")" != "PK" ]]; then
    echo "what came back for $name is not an archive" >&2
    exit 1
  fi

  if [[ "$name" == *_zeek_logs.zip ]]; then
    unpacked="$staging/${name%.zip}"
    rm -rf "$unpacked"
    unzip -q -o "$zip" -d "$unpacked"
    for log in "$unpacked"/*.log; do
      base="$(basename "$log")"
      case " $not_evidence " in *" $base "*) continue ;; esac
      cp -f "$log" "$into/$base"
    done
    rm -rf "$unpacked"
  else
    # One JSON file per archive, named after the simulation. It is renamed,
    # because the campaign is already the directory and the tool decides what a
    # file is by its extension.
    #
    # And it is recompressed rather than left as it comes out. These files are
    # around a hundred megabytes each of which the great majority is one Sysmon
    # event — thirty thousand ProcessAccess records in the first campaign — and
    # seven campaigns unpacked come to 687 MB to leave lying in a working
    # directory. Gzipped they are 25 MB, and the reader takes them either way.
    #
    # The entry is piped straight from the archive into gzip, so the uncompressed
    # file never lands on disk at all.
    if ! unzip -p "$zip" '*.json' | gzip -9 > "$into/host.json.gz"; then
      echo "no host events in $name" >&2
      rm -f "$into/host.json.gz"
      exit 1
    fi
    if [[ ! -s "$into/host.json.gz" ]]; then
      echo "no host events in $name" >&2
      rm -f "$into/host.json.gz"
      exit 1
    fi
  fi

  rm -f "$zip"
  fetched=$((fetched + 1))
done < "$list"

echo "$fetched archive(s) unpacked; $(find "$dest" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ') campaign(s) in $dest"
