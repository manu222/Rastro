#!/usr/bin/env bash
# Fetches the Linux evidence listed in tests/linux-samples.txt into
# datasets-linux/. Safe to run again: existing files are left alone unless
# --force is given.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
list="$root/tests/linux-samples.txt"
dest="$root/datasets-linux"
force="${1:-}"

commit="$(awk '/^commit /{print $2; exit}' "$list")"
if [[ -z "$commit" ]]; then
  echo "no commit pinned in $list" >&2
  exit 1
fi

mkdir -p "$dest"
echo "Fetching Linux samples at $commit"

fetched=0
while read -r path; do
  [[ -z "$path" || "$path" == \#* || "$path" == commit\ * ]] && continue
  name="$(basename "$path")"
  out="$dest/$name"
  if [[ -f "$out" && "$force" != "--force" ]]; then
    continue
  fi
  url="https://media.githubusercontent.com/media/splunk/attack_data/$commit/$path"
  curl -sSL --fail --max-time 60 -o "$out" "$url"
  # A Git LFS pointer is a small text file starting with a version line. Getting
  # one back means the media endpoint served the pointer instead of the content,
  # and a rule run against it would quietly find nothing.
  if head -c 40 "$out" | grep -q "git-lfs.github.com"; then
    echo "got an LFS pointer instead of the sample: $name" >&2
    rm -f "$out"
    exit 1
  fi
  fetched=$((fetched + 1))
done < "$list"

echo "$fetched new file(s); $(find "$dest" -name '*.log' | wc -l | tr -d ' ') in $dest"
