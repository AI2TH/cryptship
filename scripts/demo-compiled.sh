#!/usr/bin/env bash
# Demonstrates the compile seam: the shipped payload holds Python BYTECODE, so
# even someone who decrypts/extracts the running container gets app.pyc, not
# app.py. Requires docker (colima is fine).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO="$ROOT/examples/demo-python"
WORK="$DEMO/_work_compiled"
GO=golang:1.24
PY=python:3.12-slim
SECRET="the-answer-is-42-do-not-leak"

rm -rf "$WORK"; mkdir -p "$WORK/bin"

echo "== 1. build cryptship CLI (static) =="
docker run --rm -v "$ROOT":/src -w /src "$GO" \
  sh -c 'CGO_ENABLED=0 go build -o /src/examples/demo-python/_work_compiled/bin/cryptship ./cmd/cryptship'

echo "== 2. vendor steps in a python image (so the compile transform has python3) =="
docker run --rm -v "$ROOT":/src -w /src/examples/demo-python "$PY" bash -c '
  set -e
  BIN=_work_compiled/bin/cryptship
  $BIN keygen --out-priv _work_compiled/vendor.key --out-pub _work_compiled/vendor.pub
  $BIN pack   --in app --out _work_compiled/payload.enc --key-out _work_compiled/content.key \
              --meta-out _work_compiled/payload.json \
              --transform-cmd "sh /src/scripts/compile-python.sh"
  $BIN issue  --priv _work_compiled/vendor.key --content-key _work_compiled/content.key \
              --meta _work_compiled/payload.json --customer demo-co --product widget \
              --edition enterprise --days 30 --binding none --out _work_compiled/license.json
  chmod -R a+rwX _work_compiled
'

echo
echo "== 3. build compiled image (entrypoint runs app.pyc) =="
docker build -q -f "$DEMO/Dockerfile.compiled" -t cryptship-demo-compiled "$ROOT"

echo
echo "== 4. image opacity (payload is ciphertext) =="
docker save cryptship-demo-compiled -o "$WORK/image.tar"
rm -rf "$WORK/extracted"; mkdir -p "$WORK/extracted"; tar -xf "$WORK/image.tar" -C "$WORK/extracted"
if grep -rai -e "$SECRET" "$WORK/extracted" >/dev/null 2>&1; then
  echo "!! LEAK: plaintext in image"; exit 1
fi
echo "OK: no plaintext secret in the shipped image."

echo
echo "== 5. run it (compiled bytecode executes normally) =="
docker run --rm --tmpfs /run/cryptship cryptship-demo-compiled

echo
echo "== 6. PROVE the decrypted runtime tree is COMPILED, not source =="
docker run --rm --tmpfs /run/cryptship cryptship-demo-compiled -- sh -c '
  echo "files the running container actually has:"; ls -1;
  echo; echo "attempt to read the Python source app.py:"; cat app.py 2>&1 | head -1'

echo
echo "Done: a dump of this container yields app.pyc (bytecode) + a .cryptship-manifest.json"
echo "watermark naming the licensee — not your app.py source."
