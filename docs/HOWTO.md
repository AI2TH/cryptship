# cryptship how-to

A practical, copy-pasteable guide to protecting an app with cryptship. For the
design and threat model, see [ARCHITECTURE.md](ARCHITECTURE.md); for hardened
deployment, see [../deploy/README.md](../deploy/README.md).

Vocabulary: **you (the vendor)** build and encrypt the app and issue licenses;
**the customer** runs the image. The image on disk is always ciphertext.

---

## 0. Build the tools

You need a container runtime (Docker, or [colima](https://github.com/abiosoft/colima)
on macOS). You do **not** need Go on your host — build the binaries in a Go
container:

```bash
docker run --rm -v "$PWD":/src -w /src golang:1.24 sh -c '
  CGO_ENABLED=0 go build -o bin/cryptship        ./cmd/cryptship &&
  CGO_ENABLED=0 go build -o bin/cryptship-server ./cmd/cryptship-server'
```

`bin/cryptship` and `bin/cryptship-server` are static Linux binaries — run them
inside a Linux container (as the demo scripts do). If you have Go installed, you
can instead `go build -o cryptship ./cmd/cryptship` natively for your OS.

The fastest way to see everything working is the demos:

```bash
bash scripts/demo.sh           # baseline: encrypt, run, prove opacity, reject tampering
bash scripts/demo-compiled.sh  # ship compiled bytecode instead of source
bash scripts/demo-online.sh    # server-gated key + live revocation
```

Below, `cryptship` means "the cryptship CLI" however you run it.

---

## 1. Quickstart — protect and run an app

Say your app is in `./app` (e.g. `app/app.py`).

```bash
# a) one-time: a signing keypair. vendor.key is SECRET; vendor.pub ships.
cryptship keygen --out-priv vendor.key --out-pub vendor.pub

# b) encrypt the app. This emits payload.enc, content.key (SECRET), payload.json.
cryptship pack --in app --out payload.enc --key-out content.key --meta-out payload.json

# c) issue a license (unbound: decrypts anywhere a valid license is present).
cryptship issue \
  --priv vendor.key --content-key content.key --meta payload.json \
  --customer acme --product widget --days 30 \
  --binding none --out license.json

# d) inspect / verify it
cryptship inspect --pub vendor.pub license.json
```

Build the runtime image — it contains only the loader, the ciphertext, the
license, and your **public** key:

```dockerfile
FROM golang:1.24 AS build
WORKDIR /src
COPY go.mod ./
COPY pkg ./pkg
COPY cmd ./cmd
RUN CGO_ENABLED=0 go build -trimpath -o /loader ./cmd/cryptship-loader

FROM python:3.12-slim            # or any base your app needs
COPY --from=build /loader /cryptship-loader
COPY payload.enc  /cryptship/payload.enc
COPY license.json /cryptship/license.json
COPY vendor.pub   /cryptship/vendor.pub
ENTRYPOINT ["/cryptship-loader", "--", "python", "app.py"]
```

Everything after `--` is the command to run after decryption (the loader `cd`s
into the extracted app dir first). Run it with the decrypt dir on tmpfs:

```bash
docker run --rm --tmpfs /run/cryptship your-image
```

`docker save your-image | tar xO ... | grep <your source>` finds nothing — the
app ships only as `payload.enc`.

---

## 2. Binding modes

Binding decides *where* a license can decrypt. Set it with `--binding`.

### none — unbound
Decrypts on any machine that has the (signed) license. Lowest assurance; good
for trials or low-value code.
```bash
cryptship issue ... --binding none ...
```

### strict — one machine
The content key is wrapped to a single machine fingerprint; the license only
decrypts there. The customer sends you their fingerprint:
```bash
# on the customer's machine:
cryptship fingerprint            # prints e.g. 8af75d...   (--all shows every source)
```
```bash
# you issue, binding to that value:
cryptship issue ... --binding strict --fingerprint 8af75d... ...
```
In a container, bind-mount a stable id so the fingerprint is readable and
constant: `-v /etc/machine-id:/etc/machine-id:ro`.

### pool — a set of machines
Wrap to several fingerprints; any one of them decrypts. For clusters with known
nodes.
```bash
cryptship issue ... --binding pool \
  --fingerprint <fpA> --fingerprint <fpB> --fingerprint <fpC> ...
```

### online — server holds the secret (real revocation)
The license carries **no** secret, only your server URL. At start the loader
fetches the binding secret from your server, which can decline (revocation is
immediate). See §5 for running the server.
```bash
cryptship master-key --out master.key          # the server's master secret (SECRET)
cryptship issue ... --binding online \
  --server https://lic.example.com --server-master-key master.key ...
```

### attested — confidential computing
Like online, but the key broker releases the secret only after verifying TEE
attestation (AMD SEV-SNP / Intel TDX). This is the only mode where host root
can't read the memory — **and only when you control the guest** (a locked image
it can't root into). Needs CC hardware; built behind an `Attester` interface with
a mock for testing (see ARCHITECTURE.md → roadmap).
```bash
cryptship issue ... --binding attested \
  --server https://kbs.example.com --server-master-key master.key ...
```

---

## 3. Ship compiled code, not source (anti-extraction)

Once the app runs, its plaintext is in memory, and a root-capable customer can
dump it. Compiling before sealing means a dump yields compiled artifacts, not
clean source. Use `--transform-cmd`, which runs over a copy of `--in` (with
`$CRYPTSHIP_SRC` set) before encryption:

```bash
# Python → bytecode (recipe shipped in scripts/compile-python.sh)
cryptship pack --in app --out payload.enc --key-out content.key --meta-out payload.json \
  --transform-cmd "sh scripts/compile-python.sh"

# stronger: Python → native module via Nuitka
cryptship pack ... --transform-cmd "python3 -m nuitka --module app.py && rm app.py"

# Node → V8 bytecode, Go/Rust → already compiled, etc.
```
The transform runs where `cryptship pack` runs, so that environment needs the
toolchain (`scripts/demo-compiled.sh` runs `pack` inside a `python:3.12-slim`
container for exactly this reason). Update your image's `ENTRYPOINT` to run the
compiled artifact (e.g. `python app.pyc`).

---

## 4. Harden the runtime

Run the container so an in-container attacker can't ptrace or dump the app:

```bash
docker run --rm \
  --read-only --tmpfs /run/cryptship:rw,mode=0700 \
  --cap-drop=ALL --security-opt=no-new-privileges \
  --security-opt seccomp=deploy/seccomp.json \
  -e CRYPTSHIP_REQUIRE_TMPFS=1 \
  your-image
```
`CRYPTSHIP_REQUIRE_TMPFS=1` makes the loader refuse to run if the decrypt dir
isn't memory-backed. Full docker + Kubernetes settings are in
[../deploy/README.md](../deploy/README.md). This stops a non-root attacker — not
host root (that needs the `attested` mode).

The loader also exposes the license identity to your app for watermarking:
`CRYPTSHIP_LICENSE_ID`, `CRYPTSHIP_CUSTOMER`, `CRYPTSHIP_PAYLOAD_ID`, and drops a
`.cryptship-manifest.json` into the extracted tree.

---

## 5. Run the license server (online / attested)

`cryptship-server` is a stateless key broker: it derives each per-license secret
from the master secret on demand, signs responses with your vendor key (its
public half is in `vendor.pub`, so the loader trusts it), and enforces a denylist.

```bash
cryptship-server \
  --master master.key --sign vendor.key --key-id v1 \
  --addr :8080 --ttl 24h
```
- Revoke a license immediately: add `--revoke lic_abc,lic_def` (restart) — bound
  apps then refuse to start.
- `--require-attestation` turns on the (placeholder) attestation check for the
  `attested` mode; plug a real SEV-SNP/TDX verifier in here (e.g. front it with
  Confidential Containers Trustee).

The loader's revocation behaviour on a *network failure* is the operator's
choice via `CRYPTSHIP_REVOCATION`: `open` (default — run), `closed` (refuse),
`grace:<dur>` (run if the last good check is younger than `<dur>`).

---

## 6. Rotate signing keys

`vendor.pub` can be a **key ring** — one `"<key_id> <base64>"` per line — so you
can roll keys without breaking already-issued licenses:

```
# vendor.pub (ring form)
v1 MCowBQYDK2Vw...oldkey...
v2 MCowBQYDK2Vw...newkey...
```
Issue new licenses with `--key-id v2`; the loader verifies each license with the
key named by its `signing_key_id`. A single plain base64 key still works (matches
any license).

---

## 7. Reference

### Loader environment variables
| Var | Default | Meaning |
|---|---|---|
| `CRYPTSHIP_LICENSE` | `/cryptship/license.json` | license path |
| `CRYPTSHIP_PAYLOAD` | `/cryptship/payload.enc` | ciphertext path |
| `CRYPTSHIP_PUBKEY` | `/cryptship/vendor.pub` | public key / ring |
| `CRYPTSHIP_EXTRACT` | `/run/cryptship/app` | decrypt dir (put on tmpfs) |
| `CRYPTSHIP_REQUIRE_TMPFS` | unset | `1` = refuse if not tmpfs |
| `CRYPTSHIP_REVOCATION` | `open` | `open` / `closed` / `grace:<dur>` |
| `CRYPTSHIP_STATE_DIR` | `/var/lib/cryptship` | where grace state is cached |

### CLI commands
| Command | Purpose |
|---|---|
| `cryptship keygen` | generate the vendor signing keypair |
| `cryptship master-key` | generate a server master secret (online/attested) |
| `cryptship fingerprint [--all]` | print this machine's fingerprint(s) |
| `cryptship pack` | (optionally compile, then) encrypt an app dir |
| `cryptship issue` | issue a signed license for a binding mode |
| `cryptship inspect [--pub ...]` | print claims and verify the signature |
| `cryptship-server` | reference license / key-broker server |

### Keep secret vs. ship
- **Secret (never commit / never put in the image):** `vendor.key`, `content.key`,
  `master.key`, and any `license.json` you consider sensitive.
- **Ships in the image:** `cryptship-loader`, `payload.enc`, `license.json`,
  `vendor.pub`.
