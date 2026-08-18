#!/bin/sh
# Download official ClamAV CVD files into a directory.
set -eu
DEST="${1:-/var/lib/defender/db}"
UA="${DEFENDER_USER_AGENT:-ClamAV/1.4.2 (defender; rust-http)}"
MIRRORS="${DEFENDER_MIRRORS:-https://database.clamav.net,https://packages.microsoft.com/clamav}"
DBS="${DEFENDER_DATABASES:-main,daily}"
mkdir -p "$DEST"

download_one() {
  name="$1"
  IFS=','; set -- $MIRRORS; unset IFS
  for mirror in "$@"; do
    mirror=$(echo "$mirror" | tr -d ' ' | sed 's:/*$::')
    url="$mirror/${name}.cvd"
    echo "GET $url"
    if curl -fL --retry 4 --retry-delay 2 -A "$UA" -o "$DEST/${name}.cvd.tmp" "$url"; then
      mv "$DEST/${name}.cvd.tmp" "$DEST/${name}.cvd"
      return 0
    fi
  done
  return 1
}

ok=0
fail=0
IFS=','; set -- $DBS; unset IFS
for db in "$@"; do
  db=$(echo "$db" | tr -d ' ')
  if download_one "$db"; then
    ls -lh "$DEST/${db}.cvd"
    ok=$((ok + 1))
  else
    echo "WARN: failed to download ${db}.cvd" >&2
    fail=$((fail + 1))
  fi
done

if [ "$ok" -eq 0 ]; then
  echo "ERROR: downloaded no virus databases" >&2
  exit 1
fi
echo "downloaded $ok database(s) ($fail failed) into $DEST"
