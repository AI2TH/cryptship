# cryptship architecture

## Goals and non-goals

**Goal:** ship closed-source application code inside a container image such that
(a) the image contains no plaintext source, and (b) it only decrypts and runs
with a valid license — across air-gapped, on-prem, and cloud deployments, with
one loader and one license format.

**Non-goal:** perfect, unbreakable protection. Code running on customer-owned
hardware can always be extracted by someone with enough privilege and effort
(memory dump, patched loader, hypervisor introspection). cryptship raises the
cost; it does not eliminate the risk.

## Threat model

| Adversary | What they do | cryptship's answer |
|---|---|---|
| Casual customer | `docker save`, unpack layers, read source | **Defeated** — layers contain only ciphertext |
| Curious customer | grep the image, inspect the loader binary | **Defeated** — no key in the image; loader logic is public but useless without license material |
| Licensee sharing a license | copy `license.json` to another machine | **Defeated for bound licenses** — content key is wrapped to a machine fingerprint |
| Code running as the app's uid | read or patch the extracted files | **Read: not defeated. Patch: defeated** with `CRYPTSHIP_APP_USER` (the tree belongs to another uid, group-readable only) |
| Root on the deploy box | dump tmpfs / `/proc/<pid>` at runtime | **Not defeated** without a confidential-compute backend. Documented honestly. |
| Funded reverse-engineer | debugger, instrument the loader, dump memory | **Not defeated** — goal is only to make this cost more than a license |

The design decision that follows: defend rows 1–3 completely and cheaply; treat
rows 4–5 as out of scope until a confidential-compute provider lands.

## Components

```
pkg/crypto      AES-256-GCM (Seal/Open), HKDF-SHA256 KEK derivation, key wrap
pkg/license     signed claims + Ed25519 sign/verify, canonical encoding
pkg/machine     software machine fingerprint (stable host identifiers -> hash)
pkg/archive     tar pack + traversal-safe untar
pkg/keyprovider Provider interface; `offline`, `online` and `attested` providers
pkg/attest      attestation Verifier interface; attesttest = test-only attester/verifier
pkg/online, pkg/licenseserver  online/attested key protocol, signed revocation
                answers, seats, and the reference key server
pkg/harden      PR_SET_DUMPABLE helper for Go apps (helpers/python for Python)
cmd/cryptship   vendor CLI: keygen, master-key, fingerprint, pack, issue, inspect
cmd/cryptship-loader  image ENTRYPOINT: verify -> get key -> decrypt -> exec
cmd/cryptship-server  reference key server for the `online` provider
```

## Key hierarchy

```
vendor Ed25519 signing key  (secret, vendor-only)  -> signs licenses
content key (random, per build)                     -> encrypts payload.enc
KEK = HKDF(binding_material, salt = license_id,
           info = SHA-256(binding context))         -> wraps the content key
   binding_material = machine fingerprint   (strict / pool)
                    = per-license secret     (none)
                    = server secret          (online / attested)
state key = HKDF(binding_material, salt = license_id,
           info = "cryptship/state-key/v1" ‖ SHA-256(binding context))
                                                    -> seals the loader's local state
server secret (binding.secret_v):
   2 (default) = HKDF(master, info = "cryptship/server-secret/v2" ‖ policy ‖ license_id)
   0 (legacy)  = HKDF(master, salt = license_id, info = "cryptship/online-secret/v1")
```

- The **server secret** of a `secret_v` 2 license depends on the binding policy,
  so the `online` and `attested` secrets of a license differ. The plain
  `/v1/key` path only ever derives the `online` one; the `attested` one is only
  released through the attested protocol. A server without a verifier that
  shares the master key therefore cannot release an attested secret. Legacy
  (`secret_v` absent) licenses keep the old derivation and still work;
  `cryptship-server --no-legacy-secrets` refuses them once all are reissued.
- The **state key** seals the clock-rollback and revocation-grace records. It
  comes from the binding material, so a record is tied to this license and this
  binding (machine, server secret), not to the build's content key.

- The **content key** encrypts the payload once per build. The same content key
  is wrapped differently into each customer's license.
- The **KEK** never leaves the machine and is never stored; it is re-derived at
  load time from live binding material.
- **Binding == decryptability:** because the wrapped key lives in the license
  and the KEK comes from binding material plus the bound claims, the wrong machine
  or an edited bound claim ⇒ AEAD tag failure ⇒ no plaintext. The signature and
  expiry are separate loader checks; `online` enforces expiry server-side.

### Binding context (`claims.v`)

The license version selects which claims the KEK is bound to. Any other value
of `v` is refused; there is no fallback.

| `v` | Context | Bound claims |
|---|---|---|
| 1 | `cryptship/kek-ctx/v1` NUL, then version, license id, customer id, product, payload id and policy (each NUL-terminated), issued_at and not_after (big-endian uint64) | that subset only; the rest is protected by the signature alone |
| 2 (default) | `cryptship/kek-ctx/v2` NUL, then SHA-256 of the canonical claims | every claim except `wrapped_keys` and `unbound_secret` |

The canonical claims for v2 are the Go `encoding/json` encoding of
`license.Claims` (fields in declaration order) with `wrapped_keys` set to `null`
and `unbound_secret` omitted. The loader recomputes it from the parsed claims,
so editing `edition`, `entitlements`, `revocation_url`, `binding.server`,
`binding.max`, `binding.fingerprint_hashes`, `signing_key_id`, or `v` itself
breaks the unwrap. A golden vector in `pkg/license/context_test.go` locks the
encoding. Because `v` is inside both contexts, rewriting a v2 license as v1
(a downgrade to the weaker context) also fails the unwrap.

`cryptship issue` writes v2 unless `--license-version 1` is given. Loaders built
before v2 reject v2 licenses (`unsupported version`), so keep issuing v1 until
every deployed loader is updated.

## License format

Signed claims (`pkg/license.Claims`), canonically JSON-encoded, plus a detached
Ed25519 signature:

```jsonc
{
  "claims": {
    "v": 2,                            // selects the KEK binding context
    "license_id": "lic_ab12cd34",
    "customer_id": "acme-corp",
    "product": "widget-server",
    "edition": "enterprise",
    "payload_id": "f3a9…",            // binds the license to one build
    "entitlements": ["module.reporting"],
    "issued_at": 1762905600,
    "not_after": 1765497600,          // expiry drives offline revocation
    "binding": { "policy": "strict", "max": 1, "fingerprint_hashes": ["…"] },
    "wrapped_keys": ["base64…"],       // one per bound machine (pool), else one
    "unbound_secret": "base64…",       // only for policy "none"
    "revocation_url": "https://…",     // optional online check
    "signing_key_id": "v1"             // key rotation
  },
  "sig_alg": "ed25519",
  "sig": "base64…"
}
```

Field order in `Claims` is the canonical signing order and is append-only. A
field added later must be `omitempty`, or the v2 context of every existing
license changes and none of them unwrap.

## Build-time flow (vendor)

```
keygen ──> vendor.key (secret), vendor.pub (ship)
pack   ──> payload.enc (AES-256-GCM of tar(app)), content.key (secret), payload_id
issue  ──> license.json  (wraps content.key per binding, signs with vendor.key)
image  ──> loader + payload.enc + license.json + vendor.pub   (no source, no content key)
```

## Run-time flow (loader)

```
1. read vendor.pub, license.json
2. verify Ed25519 signature            -> fail closed
3. check not_after / issued_at window  -> fail closed
4. provider.Unlock(license) -> content key + state key:
      offline:  derive KEK from machine fingerprint (or unbound secret),
                unwrap one of wrapped_keys                -> fail closed on no match
      online:   fetch the per-license binding secret from the key server
                (signed, nonce-bound reply)                -> fail closed if unreachable,
                unless CRYPTSHIP_ONLINE_GRACE covers an outage
      attested: challenge -> evidence over (challenge, ephemeral key) ->
                secret sealed to the ephemeral key (no production verifier
                yet; the server refuses --require-attestation)
5. (optional) revocation_url check: a signed, nonce-bound answer. Revoked =
   refuse. Otherwise CRYPTSHIP_REVOCATION decides: open (run, default; also
   accepts an unsigned 200), closed (refuse unless a signed "not revoked"),
   grace:<duration> (run if the last signed "not revoked", sealed under the
   state key, is younger)
6. clock-rollback check (licenses with not_after): refuse if now is more than
   24h behind the latest start recorded in CRYPTSHIP_STATE_DIR. The record is
   sealed under the state key; deleting it resets the check, so it is best
   effort
7. OpenPayload(content_key, payload.enc, payload_id)      -> AEAD; fail closed
8. CRYPTSHIP_EXEC_MEMFD set: copy that one ELF entry into a sealed memfd and
   exec it from there (nothing on disk); skip 9
9. untar into CRYPTSHIP_EXTRACT (should be tmpfs; only an empty dir or one an
   earlier run marked is emptied first); with CRYPTSHIP_APP_USER (loader runs
   as root), give the tree to CRYPTSHIP_EXTRACT_OWNER:app-gid, 0750/0640
10. with CRYPTSHIP_APP_USER, drop to the app uid/gid (no supplementary groups);
   exec the app (args after `--`), app becomes PID 1
```

The revocation check runs after key acquisition (step 4) only so that its grace
record can be sealed under the state key; nothing is decrypted before it.

Runtime config (env): `CRYPTSHIP_LICENSE`, `CRYPTSHIP_PAYLOAD`,
`CRYPTSHIP_PUBKEY`, `CRYPTSHIP_EXTRACT`, `CRYPTSHIP_REVOCATION`
(open | closed | grace:<duration>), `CRYPTSHIP_STATE_DIR` (revocation, online
grace and clock state), `CRYPTSHIP_ONLINE_GRACE` (online outage cache),
`CRYPTSHIP_APP_USER` / `CRYPTSHIP_EXTRACT_OWNER` (separate-uid extraction and
privilege drop), `CRYPTSHIP_EXEC_MEMFD` (run one ELF binary from memory) and
`CRYPTSHIP_REQUIRE_TMPFS` (refuse to run if the extract dir is not tmpfs). Put the extract dir on tmpfs:
`docker run --tmpfs /run/cryptship` or k8s `emptyDir { medium: Memory }`.

## Binding policies

- **none** — content key recoverable from the signed license alone. The license
  file works on any machine. Lowest assurance (trials, low-value IP).
- **strict** — content key wrapped to exactly one machine fingerprint. Decrypts
  only on that machine. Air-gapped-safe.
- **pool** — content key wrapped to each of up to N fingerprints; any one bound
  machine can decrypt. For clusters with known nodes.
- **online** — the license carries no secret, only `binding.server`. At run time
  the loader POSTs a nonce; the server returns the per-license secret (derived
  from a master secret via HKDF) signed with the vendor key and echoing the
  nonce. The loader verifies and unwraps. Revocation is immediate — the server
  declines (410 revoked; 403 refused; 409 seat limit). With
  `issue --max-machines N` and `cryptship-server --enforce-seats`, at most N
  distinct machines hold a seat at once (a seat lapses after `--seat-lease`,
  30 days by default). Seats count the fingerprints loaders report, so a
  modified loader can evade them: they limit honest over-deployment, not a
  determined customer. Reference server: `cmd/cryptship-server`; demo:
  `scripts/demo-online.sh`.
- **attested** — like online, but the key broker releases the secret only after
  verifying TEE attestation evidence the loader attaches (via an `Attester`).
  Defends against host root **when the guest is vendor-controlled**; needs
  confidential-compute hardware. The protocol follows the Trustee / KBS
  pattern:
  1. the loader gets a challenge from `POST /v1/challenge` (single use, MACed
     by the server, valid for 2 minutes);
  2. it makes an ephemeral X25519 key pair and asks the attester for evidence
     whose REPORT_DATA holds `online.AttestationBinding(license_id, challenge,
     ephemeral public key)` (SHA-256, length-prefixed fields);
  3. the server spends the challenge, verifies the evidence against that
     binding, and returns the secret encrypted to the ephemeral key (X25519,
     HKDF-SHA256, AES-256-GCM), signed with the vendor key.

  A captured request cannot be replayed (the challenge is spent), and a
  captured answer is useless without the ephemeral private key, which never
  leaves the TEE. A server with a verifier refuses plain requests for attested
  secrets; one without a verifier refuses the attested protocol, and under
  `secret_v` 2 cannot derive attested secrets at all. Built behind the
  `Attester` (loader) and `attest.Verifier` (server) interfaces, with test-only
  implementations; a real SEV-SNP/TDX attester and verifier (signature chain,
  REPORT_DATA check, measurement allow-list) need the hardware and are the
  roadmap item. Until then `cryptship-server --require-attestation` refuses to
  start. The challenge's single use is tracked in memory, so after a server
  restart a challenge can be reused until it expires; the answer is still
  sealed to the original ephemeral key.

The software fingerprint (`pkg/machine`) derives one independent fingerprint per
readable host identifier (`/etc/machine-id`, DMI UUID/serial); the loader tries
each, so a binding survives a source appearing or disappearing. The hostname is
deliberately excluded — in a container it is the container ID and changes every
run. **Operators should bind-mount `/etc/machine-id:ro`** into the container so a
stable, non-root-readable id is present; otherwise strict binding may be
unusable (nothing readable) rather than secure. The fingerprint stops copying
but is spoofable by root. `CRYPTSHIP_FINGERPRINT` is honoured only in test
builds (`go build -tags cryptship_devfp`); production loaders ignore it. Pool
binding is the mechanism for migrations. Strong binding (TPM seal, cloud
instance identity) is on the roadmap as additional providers.

## Runtime hardening & anti-extraction

Once the app runs, its plaintext is in the container's memory. cryptship raises
the extraction cost in three generic, composable ways. **None defeats host
root** (see the threat model) — that needs a confidential-compute provider or
remote execution.

- **Compile/obfuscate before sealing** — `pack --transform-cmd "<cmd>"` runs a
  transform over a copy of the app before it is tar'd and encrypted, so what a
  dump recovers is compiled, not source. The core stays language-agnostic; the
  transform is the adopter's own toolchain (`scripts/compile-python.sh` for
  Python bytecode, Nuitka for native). Proof: `scripts/demo-compiled.sh`.
- **Loader / container hardening** — the loader calls `prctl(PR_SET_DUMPABLE, 0)`
  for its own lifetime (protects the key and decrypted payload during the decrypt
  window). execve resets the flag, so the app should set it again first thing:
  `pkg/harden.NonDumpable()` for Go, `helpers/python/cryptship_harden.py` for
  Python. Until it does, the same uid can ptrace it. `deploy/` ships a seccomp
  profile denying `ptrace`/`process_vm_readv`/`process_vm_writev`/`kcmp`, plus
  non-root, cap-drop, read-only-rootfs and tmpfs settings for docker and k8s.
- **Separate-uid extraction** — with `CRYPTSHIP_APP_USER=uid[:gid]` the loader
  starts as root, extracts, gives the tree to `CRYPTSHIP_EXTRACT_OWNER` (default
  root) and the app's group with modes 0750/0640, and drops to the app uid/gid
  before exec. The app can read and run its code but cannot change it, and no
  other non-root user can read it. It does not stop the app's own uid from
  reading (and copying) the code.
- **memfd exec** — `CRYPTSHIP_EXEC_MEMFD=<entry>` runs one ELF binary from the
  payload out of a sealed, close-on-exec memfd (via `/proc/self/fd`), so no
  decrypted file exists on any filesystem. Scripts cannot run this way. The
  binary is still in RAM, and `/proc/<pid>/exe` reads it back for anyone who
  may ptrace the app, hence the dumpable helpers above.
- **Watermarking** — the loader writes a per-license `.cryptship-manifest.json`
  into the extracted tree and exposes `CRYPTSHIP_LICENSE_ID` /
  `CRYPTSHIP_CUSTOMER` to the app, so a leaked instance names its licensee
  (deterrent / forensics, not prevention — strippable).

## Revocation

- **Offline:** by expiry. Issue short-lived licenses and renew. A distributed
  denylist only helps for clients that check in.
- **Online:** the key server refuses to return the binding secret for a revoked
  license, so its next start fails. Revoke with `cryptship-server --revoke`
  (static) or `--revoke-file` (a live denylist re-read when the file changes —
  no restart); running instances keep running. By default an online-bound app
  does not start while the server is unreachable; `CRYPTSHIP_ONLINE_GRACE=<dur>`
  lets it ride out an outage (no answer, or 502/503/504 from a proxy) using a
  cached secret for that long. The cache is sealed under a key from the machine
  fingerprint (or, where none is readable, a random key in the state dir, which
  binds it to that install only), and its timestamp is authenticated, so editing
  it does not extend grace. A reachable server that says revoked still wins.
  Anyone who can block the server can use the grace window on purpose, and a
  clock held back keeps the window open (the clock check only catches more than
  24 hours), so keep the window short.
- **Signed `revocation_url` check:** the loader sends a nonce and verifies the
  server's signed answer (same envelope and vendor key as key answers, its own
  domain label) against the key ring, so an on-path attacker or captive portal
  cannot forge "not revoked" or replay an old answer. A signed answer that does
  not verify or does not match is an error, not a fallback. `closed` and
  `grace` accept only signed answers; `open` also accepts an unsigned 200 from a
  generic endpoint, with a warning. Only a signed success refreshes the grace
  record, which is sealed under the state key and ignored if dated in the
  future. Deleting it only removes grace.

## Roadmap

1. **TPM provider** — seal the content key to the TPM so a copied license is
   useless off the physical machine, even to root.
2. **Online provider + reference license server** — IMPLEMENTED (signed,
   nonce-bound replies; live `--revoke-file` denylist; signed `revocation_url`
   check; `CRYPTSHIP_ONLINE_GRACE` outage caching; policy-bound server secrets;
   seat enforcement). Still open: a machine (re)activation API (seats are freed
   by lease expiry or `SeatTracker.Release`), server-signed time for offline
   expiry, and an authenticated admin API for revocation.
3. **Cloud KMS provider** — wrap the content key with AWS/GCP/Azure KMS; unwrap
   gated by cloud IAM + signed instance identity.
4. **Confidential-compute provider** — the challenge / ephemeral-key protocol is
   IMPLEMENTED and tested with the test verifier. Still open: SEV-SNP
   (`go-sev-guest`) and TDX (`go-tdx-guest`) attesters and verifiers, which need
   the hardware. This is the only backend that defends against a
   root-privileged host.
5. **Pre-encryption compile/bundle** — IMPLEMENTED as `pack --transform-cmd`:
   runs your compiler/obfuscator over the app before sealing, so a dump yields
   compiled artifacts, not clean source (`scripts/compile-python.sh` for Python
   bytecode; Nuitka native builds are a one-line swap).
