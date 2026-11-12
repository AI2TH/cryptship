#!/usr/bin/env bash
# Online binding end-to-end: a license server container holds the master secret;
# the app container fetches its binding secret over the network at run time. The
# license file itself carries no secret, so revocation is real (the server just
# declines). Requires docker (colima is fine).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO="$ROOT/examples/demo-python"
WORK="$DEMO/_work_online"
NET=cryptship-net
GO=golang:1.24

cleanup() {
  docker rm -f cryptship-server >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
rm -rf "$WORK"; mkdir -p "$WORK/bin"

echo "== 1. build cryptship CLI + server (static) =="
docker run --rm -v "$ROOT":/src -w /src "$GO" sh -c '
  CGO_ENABLED=0 go build -o /src/examples/demo-python/_work_online/bin/cryptship ./cmd/cryptship &&
  CGO_ENABLED=0 go build -o /src/examples/demo-python/_work_online/bin/cryptship-server ./cmd/cryptship-server'

echo "== 2. vendor steps: keys, master secret, pack, issue an ONLINE license =="
docker run --rm -v "$ROOT":/src -w /src/examples/demo-python "$GO" bash -c '
  set -e
  BIN=_work_online/bin/cryptship
  $BIN keygen     --out-priv _work_online/vendor.key --out-pub _work_online/vendor.pub
  $BIN master-key --out _work_online/master.key
  $BIN pack       --in app --out _work_online/payload.enc --key-out _work_online/content.key --meta-out _work_online/payload.json
  $BIN issue      --priv _work_online/vendor.key --content-key _work_online/content.key --meta _work_online/payload.json \
                  --customer demo-co --product widget --days 30 \
                  --binding online --server http://cryptship-server:8080 --server-master-key _work_online/master.key \
                  --out _work_online/license.json
  $BIN inspect    --pub _work_online/vendor.pub _work_online/license.json
  chmod -R a+rwX _work_online
'

echo
echo "== 3. build app image (online-bound license, carries NO secret) =="
docker build -q -f "$DEMO/Dockerfile.online" -t cryptship-online-app "$ROOT"

echo
echo "== 4. start network + license server =="
docker network create "$NET" >/dev/null
docker run -d --name cryptship-server --network "$NET" -v "$WORK":/work -w /work alpine:3.20 \
  /work/bin/cryptship-server --master master.key --sign vendor.key --key-id v1 --addr :8080 >/dev/null
sleep 1

echo "== 5. RUN app: loader fetches the key from the server, verifies, runs =="
docker run --rm --network "$NET" --tmpfs /run/cryptship cryptship-online-app

echo
echo "== 6. REVOCATION: restart the server with the license revoked; app must refuse =="
LICID=$(grep -o 'lic_[a-f0-9]*' "$WORK/license.json" | head -1)
docker rm -f cryptship-server >/dev/null
docker run -d --name cryptship-server --network "$NET" -v "$WORK":/work -w /work alpine:3.20 \
  /work/bin/cryptship-server --master master.key --sign vendor.key --key-id v1 --addr :8080 --revoke "$LICID" >/dev/null
sleep 1
if docker run --rm --network "$NET" --tmpfs /run/cryptship cryptship-online-app >/dev/null 2>"$WORK/err.txt"; then
  echo "!! app ran despite revocation — bug"; exit 1
fi
echo "   server declined the revoked license $LICID:"
sed 's/^/   > /' "$WORK/err.txt"

echo
echo "Online demo complete: the image holds no key; the server gates every start, so revocation is immediate."
