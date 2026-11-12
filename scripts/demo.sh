#!/usr/bin/env bash
# cryptship end-to-end demo. Requires a working `docker` (colima is fine).
# Nothing but the container runtime is needed on the host — the CLI and loader
# are compiled inside a Go container.
#
#   1. build the vendor CLI + loader in a Go container
#   2. vendor steps: keygen, pack (encrypt app), issue (sign license)
#   3. build the runtime image (loader + encrypted payload + public key only)
#   4. PROVE the shipped image carries no plaintext source (docker save + grep)
#   5. RUN it (decrypts into tmpfs, app works)
#   6. NEGATIVE: tamper the license -> loader refuses to run
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO="$ROOT/examples/demo-python"
WORK="$DEMO/_work"
GO=golang:1.24
SECRET="the-answer-is-42-do-not-leak"
MARKER="proprietary_algorithm"

rm -rf "$WORK"; mkdir -p "$WORK"

echo "== 1/2. build cryptship CLI in a container, then run vendor steps =="
docker run --rm -v "$ROOT":/src -w /src "$GO" bash -c '
  set -e
  go build -o /tmp/cryptship ./cmd/cryptship
  cd examples/demo-python
  /tmp/cryptship keygen  --out-priv _work/vendor.key --out-pub _work/vendor.pub
  /tmp/cryptship pack    --in app --out _work/payload.enc --key-out _work/content.key --meta-out _work/payload.json
  /tmp/cryptship issue   --priv _work/vendor.key --content-key _work/content.key --meta _work/payload.json \
                         --customer demo-co --product widget --edition enterprise --days 30 \
                         --binding none --out _work/license.json
  echo "---- inspect ----"
  /tmp/cryptship inspect --pub _work/vendor.pub _work/license.json
  chmod -R a+rwX _work
'

echo
echo "== 3. build the runtime image =="
docker build -q -f "$DEMO/Dockerfile" -t cryptship-demo "$ROOT"

echo
echo "== 4. PROVE opacity: docker save, then search every layer for the secret =="
docker save cryptship-demo -o "$WORK/image.tar"
rm -rf "$WORK/extracted"; mkdir -p "$WORK/extracted"
tar -xf "$WORK/image.tar" -C "$WORK/extracted"
if grep -rai -e "$SECRET" -e "$MARKER" "$WORK/extracted" >/dev/null 2>&1; then
  echo "!! LEAK: plaintext application source found in the shipped image"
  grep -rail -e "$SECRET" -e "$MARKER" "$WORK/extracted"
  exit 1
fi
echo "OK: neither the secret string nor the source marker appears anywhere in the image."
echo "    The app ships only as ciphertext in payload.enc."

echo
echo "== 5. RUN it (valid license, decrypt into tmpfs) =="
docker run --rm --tmpfs /run/cryptship cryptship-demo

echo
echo "== 6. NEGATIVE: flip one signature byte, loader must refuse =="
cp "$WORK/license.json" "$WORK/license.bad.json"
python3 - "$WORK/license.bad.json" <<'PY'
import json, sys, base64
p = sys.argv[1]
d = json.load(open(p))
sig = bytearray(base64.b64decode(d["sig"]))
sig[0] ^= 0x01
d["sig"] = base64.b64encode(bytes(sig)).decode()
json.dump(d, open(p, "w"))
PY
if docker run --rm --tmpfs /run/cryptship \
     -v "$WORK/license.bad.json":/cryptship/license.json:ro \
     cryptship-demo >/dev/null 2>"$WORK/err.txt"; then
  echo "!! loader ran a tampered license — that is a bug"
  exit 1
fi
echo "   loader refused it:"
sed 's/^/   > /' "$WORK/err.txt"

echo
echo "Demo complete."
