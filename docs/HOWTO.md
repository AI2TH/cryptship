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
into the extracted app dir first). If you omit `-- <command>`, the loader runs
`./entrypoint` from the extracted tree and, if there is none, exits with
`locate command "./entrypoint": ... not found` — so always pass your command.
Run it with the decrypt dir on tmpfs:

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

> **Note:** `cryptship fingerprint` reads **Linux** identifiers (`/etc/machine-id`,
> DMI) — it is meant to run on the (Linux) deploy host, and returns an error on
> macOS/Windows. To exercise strict/pool **locally without real machine ids**,
> build the loader with the dev tag and set `CRYPTSHIP_FINGERPRINT`:
> `go build -tags cryptship_devfp ./cmd/cryptship-loader` then run it with
> `-e CRYPTSHIP_FINGERPRINT=machineA`. This override is **compiled out of
> production builds**, so it can't be used to defeat binding on a real deployment.

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
  --server https://lic.example.com --server-master-key master.key \
  --max-machines 5 ...                         # optional seat limit (server --enforce-seats)
```
New online/attested licenses carry `binding.secret_v: 2`: the server secret is
derived per binding policy, so an online server can never release an attested
license's secret. Loaders from before this field reject such licenses
(`unknown field "secret_v"`); until they are updated, issue with
`--server-secret-version 0` (the old derivation).

### attested — confidential computing
Like online, but the key broker releases the secret only after verifying TEE
attestation (AMD SEV-SNP / Intel TDX). This is the only mode where host root
can't read the memory — **and only when you control the guest** (a locked image
it can't root into). Needs CC hardware and a verifier on the server; today the
loader side is an `Attester` interface and the server side an `attest.Verifier`
interface, with test-only implementations in `pkg/attest/attesttest` (see
ARCHITECTURE.md → roadmap). The wire protocol is done: the loader fetches a
single-use challenge, the evidence's REPORT_DATA commits to
`online.AttestationBinding(license_id, challenge, ephemeral public key)`, and the
server returns the secret encrypted to that ephemeral key, so neither a captured
request nor a captured answer can be reused.
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

Three optional extras (details and a `docker run` recipe in
[../deploy/README.md](../deploy/README.md)):

- **The app cannot change its own code:** start the loader as root with
  `CRYPTSHIP_APP_USER=65532:65532`. It extracts, gives the tree to root (or
  `CRYPTSHIP_EXTRACT_OWNER`) and the app's group (0750/0640), and drops to
  65532 before exec. It needs `CAP_CHOWN`, `CAP_SETUID` and `CAP_SETGID`.
- **No decrypted file at all, for a single binary:**
  `CRYPTSHIP_EXEC_MEMFD=bin/server` runs that ELF entry of the payload from a
  sealed memfd (`cryptship-loader -- server --flag` sets argv). Scripts and
  interpreters with many files cannot use this.
- **Make the app non-dumpable again:** execve resets the loader's
  `PR_SET_DUMPABLE`. Call `harden.NonDumpable()` (`github.com/AI2TH/cryptship/pkg/harden`)
  at the top of a Go `main`, or ship `helpers/python/cryptship_harden.py` with a
  Python app and call `cryptship_harden.set_non_dumpable()` first.

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
- Revoke a license immediately: add `--revoke lic_abc,lic_def` (static, applied
  at start), or `--revoke-file deny.txt` for a **live denylist** — one license id
  per line; edit the file and the next request sees it, **no restart needed**.
  Bound apps then refuse to start.
- `--require-attestation` makes the server refuse to start: no SEV-SNP/TDX
  verifier is built in yet, and accepting evidence it cannot verify would give
  no protection. To use `attested` today, implement `attest.Verifier` (signature
  chain, `online.AttestationBinding` in REPORT_DATA, measurement allow-list) and
  set `licenseserver.Server.Verifier`, or front the key broker with a verifier
  such as Confidential Containers Trustee.
- Attested secrets are safe on a non-verifying server for licenses with
  `binding.secret_v: 2` (the default): their secret is derived per policy and
  only released through the attested protocol. Licenses issued without it
  (`--server-secret-version 0`, or before the field existed) use the old
  derivation, which a non-verifying server *will* release for an attested
  license. Reissue them, then start the server with `--no-legacy-secrets`; until
  then, give attested licenses their own master key.
- Seats: `--enforce-seats` limits each license to its `binding.max` distinct
  machines (`issue --max-machines N`; 0 = no limit). A machine keeps its seat
  for `--seat-lease` (default `720h`) after its last start; `--seats-file`
  persists seats across restarts, and `--license-keys` names the key ring that
  signs licenses if it is not the `--sign` key. Loaders report their machine
  fingerprint, so mount `/etc/machine-id`; a modified loader can lie, so treat
  seats as a limit for honest customers.

A separate revocation check (`revocation_url` in the license) is **signed**: the
loader sends a nonce and verifies the server's signed answer against the key
ring, so a captive portal or on-path attacker cannot forge "not revoked".
`CRYPTSHIP_REVOCATION=closed` additionally rejects any *unsigned* "active" answer.
The loader's behaviour when the check fails is the operator's choice:
`open` (default — run), `closed` (refuse), `grace:<dur>` (run if the last
*signed* "not revoked" is younger than `<dur>`). The grace record is sealed
under a key derived from the license's binding material, so editing or copying
it does not extend grace.

For the **online** binding itself, set `CRYPTSHIP_ONLINE_GRACE=<dur>` (e.g. `12h`)
to let a cached, machine-sealed content key ride out a license-server **outage** (no
answer, or 502/503/504 from a proxy) for that long. It is off by default (every
start needs the server); it never bypasses revocation (a reachable server that
says revoked still wins) and never applies to `attested` (which must always
re-attest). Anyone who can block the server can use the window, so keep it
short.

---

## 6. Rotate signing keys

`vendor.pub` can be a **key ring** — one `"<key_id> <base64>"` per line — so you
can roll keys without breaking already-issued licenses:

```
# vendor.pub (ring form)
v1 <old vendor.pub contents: base64 of the raw 32-byte key, as written by keygen>
v2 <new vendor.pub contents>
```
Issue new licenses with `--key-id v2`; the loader verifies each license with the
key named by its `signing_key_id`. A single plain base64 key still works (matches
any license).

### License format version

`cryptship issue` writes format v2 licenses, which bind every claim into the
KEK. Loaders from before v2 refuse them with `unsupported version 2`. Until all
deployed loaders are updated, issue with `--license-version 1`; the new loader
accepts both versions.

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
| `CRYPTSHIP_REVOCATION` | `open` | `open` / `closed` / `grace:<dur>` (revocation-URL failure policy) |
| `CRYPTSHIP_ONLINE_GRACE` | unset | `<dur>` (e.g. `12h`): ride out an online license-server outage (no answer, or 502/503/504) using a machine-sealed cached content key; off by default |
| `CRYPTSHIP_STATE_DIR` | `/var/lib/cryptship` | revocation-grace, online-grace, and clock-rollback state (best effort: if it is not writable those checks degrade with a warning) |
| `CRYPTSHIP_APP_USER` | unset | `uid[:gid]`: loader starts as root, extracts as another owner, drops to this user before exec (error if not root) |
| `CRYPTSHIP_EXTRACT_OWNER` | `0` | with `CRYPTSHIP_APP_USER`: owner uid of the extracted tree (must differ from the app uid) |
| `CRYPTSHIP_EXEC_MEMFD` | unset | `<path in payload>`: run that single ELF binary from a memfd; nothing is extracted |

### CLI commands
| Command | Purpose |
|---|---|
| `cryptship keygen` | generate the vendor signing keypair |
| `cryptship master-key` | generate a server master secret (online/attested) |
| `cryptship fingerprint [--all]` | print this machine's fingerprint(s) |
| `cryptship pack` | (optionally compile, then) encrypt an app dir |
| `cryptship issue` | issue a signed license for a binding mode |
| `cryptship inspect [--pub ...]` | print claims and verify the signature |
| `cryptship-server` | reference license / key-broker server (`--revoke-file`, `--enforce-seats`, `--no-legacy-secrets`) |

`cryptship issue --expires 2027-03-31` ends the license at 00:00:00 UTC on that
date; add `--expires-end-of-day` to keep it valid through 23:59:59 UTC. `--days N`
counts from now.

### Keep secret vs. ship
- **Secret (never commit / never put in the image):** `vendor.key`, `content.key`,
  `master.key`, and any `license.json` you consider sensitive.
- **Ships in the image:** `cryptship-loader`, `payload.enc`, `license.json`,
  `vendor.pub`.
