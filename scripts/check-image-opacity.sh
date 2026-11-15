#!/usr/bin/env bash
# Prove an image carries no plaintext application source.
#
#   scripts/check-image-opacity.sh IMAGE STRING [STRING...]
#
# Streams `docker save IMAGE` into a throwaway container, unpacks every layer
# blob (plain tar or gzip; legacy `<id>/layer.tar` and OCI `blobs/sha256/*`
# layouts) into its own directory, and fails if any STRING appears anywhere:
# in a layer's files or in the image metadata. Grepping the save output without
# unpacking each layer would miss source inside compressed layers, so a blob
# that cannot be unpacked (including a zstd layer) is an error, never a pass.
# As a positive control the unpacked layers must contain
# /cryptship/payload.enc, so an empty scan cannot pass.
#
# Needs only docker: the unpacking runs in a Linux container, so host tar
# quirks (e.g. a case-insensitive filesystem) do not matter.
set -euo pipefail

[ "$#" -ge 2 ] || { echo "usage: $0 IMAGE STRING..." >&2; exit 2; }
IMAGE="$1"
shift
SCANNER=${SCANNER_IMAGE:-python:3.12-slim}

# shellcheck disable=SC2016 # expanded inside the scanner container
SCAN='
set -euo pipefail
S=/scan/save L=/scan/layers
mkdir -p "$S" "$L"
tar -xf - -C "$S"
n=0
while IFS= read -r -d "" blob; do
  case "$(basename "$blob")" in VERSION|oci-layout|repositories) continue ;; esac
  magic="$(head -c 4 "$blob" | od -An -tx1 | tr -d " \n")"
  case "$magic" in
    7b*|5b*) continue ;;                       # JSON: manifest, config, index
  esac
  dest="$L/$n"; mkdir -p "$dest"
  case "$magic" in
    1f8b*)    ok=0; gzip -dc "$blob" | tar -xf - -C "$dest" 2>/tmp/err || ok=$? ;;
    28b52ffd) echo "!! ${blob#"$S"/} is a zstd layer, which this check cannot unpack" >&2; exit 1 ;;
    *)        ok=0; tar -xf "$blob" -C "$dest" 2>/tmp/err || ok=$? ;;
  esac
  if [ "$ok" -ne 0 ]; then
    echo "!! could not unpack layer blob ${blob#"$S"/}:" >&2; sed "s/^/   /" /tmp/err >&2; exit 1
  fi
  n=$((n + 1))
done < <(find "$S" -type f -size +0 -print0)

if ! find "$L" -path "*/cryptship/payload.enc" | grep -q .; then
  echo "!! unpacked $n layer(s) but found no /cryptship/payload.enc; the scan would prove nothing" >&2
  exit 1
fi
args=()
for s in "$@"; do args+=(-e "$s"); done
if grep -rlaF "${args[@]}" "$L" "$S" >/tmp/leaks; then
  echo "!! LEAK: plaintext application source found in the image:"
  sed "s#^/scan/#   #" /tmp/leaks
  exit 1
fi
echo "OK: unpacked $n layer(s); none of the $# marker string(s) appears in any layer or in the image metadata."
'

docker save "$IMAGE" | docker run --rm -i --network none "$SCANNER" bash -c "$SCAN" scan "$@"
