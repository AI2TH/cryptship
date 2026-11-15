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
pkg/keyprovider Provider interface; `offline`, `online` and `attested` (mock attester) providers
pkg/online, pkg/licenseserver  online key protocol and the reference key server
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
```

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
4. (optional) revocation_url check     -> 410 Gone = revoked (fail closed); network error =
                                          CRYPTSHIP_REVOCATION policy: open (run, default), closed (refuse),
                                          grace:<duration> (run if the last good check is younger)
5. provider.ContentKey(license):
      offline:  derive KEK from machine fingerprint (or unbound secret),
                unwrap one of wrapped_keys                -> fail closed on no match
      online:   fetch the per-license binding secret from the key server
                (signed, nonce-bound reply)                -> fail closed if unreachable
      attested: attester evidence gates the key (mock only today)
6. OpenPayload(content_key, payload.enc, payload_id)      -> AEAD; fail closed
7. untar into CRYPTSHIP_EXTRACT (should be tmpfs)
8. exec the app (args after `--`), app becomes PID 1
```

Runtime config (env): `CRYPTSHIP_LICENSE`, `CRYPTSHIP_PAYLOAD`,
`CRYPTSHIP_PUBKEY`, `CRYPTSHIP_EXTRACT`, `CRYPTSHIP_REVOCATION`
(open | closed | grace:<duration>), `CRYPTSHIP_STATE_DIR` (revocation state) and
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
  declines (410/403). Reference server: `cmd/cryptship-server`; demo:
  `scripts/demo-online.sh`.
- **attested** — like online, but the key broker releases the secret only after
  verifying TEE attestation evidence the loader attaches (via an `Attester`).
  Defends against host root **when the guest is vendor-controlled**; needs
  confidential-compute hardware. Built behind an interface with a mock; a real
  SEV-SNP/TDX attester + verifying KBS is the roadmap item.

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
  window; execve resets the flag, so the running app is protected by the
  container config instead). `deploy/` ships a seccomp profile denying
  `ptrace`/`process_vm_readv`/`process_vm_writev`/`kcmp`, plus non-root,
  cap-drop, read-only-rootfs and tmpfs settings for docker and k8s.
- **Watermarking** — the loader writes a per-license `.cryptship-manifest.json`
  into the extracted tree and exposes `CRYPTSHIP_LICENSE_ID` /
  `CRYPTSHIP_CUSTOMER` to the app, so a leaked instance names its licensee
  (deterrent / forensics, not prevention — strippable).

## Revocation

- **Offline:** by expiry. Issue short-lived licenses and renew. A distributed
  denylist only helps for clients that check in.
- **Online:** the key server refuses to return the binding secret for a revoked
  license, so its next start fails (revoke with `cryptship-server --revoke`;
  running instances keep running). An online-bound app does not start while the
  server is unreachable.

## Roadmap

1. **TPM provider** — seal the content key to the TPM so a copied license is
   useless off the physical machine, even to root.
2. **Online provider + reference license server** — IMPLEMENTED (signed,
   nonce-bound replies; revocation by denylist). Still open: seat management
   (the `machine` field is sent but not enforced), machine (re)activation API,
   and offline grace caching of the online key.
3. **Cloud KMS provider** — wrap the content key with AWS/GCP/Azure KMS; unwrap
   gated by cloud IAM + signed instance identity.
4. **Confidential-compute provider** — SEV-SNP/TDX with remote attestation; the
   only backend that defends against a root-privileged host.
5. **Pre-encryption compile/bundle** — IMPLEMENTED as `pack --transform-cmd`:
   runs your compiler/obfuscator over the app before sealing, so a dump yields
   compiled artifacts, not clean source (`scripts/compile-python.sh` for Python
   bytecode; Nuitka native builds are a one-line swap).
