# cryptship

[![CI](https://github.com/AI2TH/cryptship/actions/workflows/ci.yml/badge.svg)](https://github.com/AI2TH/cryptship/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/AI2TH/cryptship)](https://github.com/AI2TH/cryptship/releases/latest)
[![License: GPLv3](https://img.shields.io/badge/license-GPLv3-blue.svg)](LICENSE)

Ship encrypted, license-gated application code inside container images.

Docker images ship your source in the clear. Anyone with the image can
`docker save`, unpack the layers, and read everything — especially for
interpreted languages (Python, Node, Ruby). `cryptship` lets you ship the
application **encrypted**, with a thin loader that decrypts and runs it only
when a valid license is present. One tool, one license format, three deployment
modes: **air-gapped**, **on-prem**, and **cloud**.

> **Honest threat model.** Code that runs on hardware the customer controls can
> never be made perfectly extraction-proof — at some instant the plaintext is in
> memory the CPU can read. cryptship is not DRM snake-oil. Its goal is to **raise
> the bar**: make casual copying (`docker save` + read) impossible, and make
> serious reverse-engineering cost more than a license. If you need protection
> against a root-privileged customer, you need a confidential-computing backend
> (see the roadmap); everything below tmpfs is obfuscation and we say so.

## How it works

**Build time (vendor):**

1. `cryptship keygen` — generate an Ed25519 signing keypair (once).
2. `cryptship pack` — generate a random content key and AES-256-GCM encrypt your
   app directory into `payload.enc`.
3. `cryptship issue` — issue a signed license that **wraps the content key** to a
   binding (none / a machine / a pool of machines).
4. Build an image containing the loader, `payload.enc`, the license, and your
   **public** key. No source, no content key.

**Run time (customer):** the loader verifies the license signature, checks
expiry/revocation, derives the key from the license + machine binding, decrypts
the payload into tmpfs, and `exec`s your app.

### The one principle that makes this real

**Binding is cryptographic, not a boolean.** The content key is *derived from
the license and the binding material*, so there is no "is this the right
machine?" branch to patch:

```
KEK         = HKDF(machine_fingerprint, license_id, bound claims)
content_key = unwrap(license.wrapped_key, KEK)
plaintext   = aead_open(payload.enc, content_key)   # wrong key => AEAD tag fails
```

Run on an unbound machine, or edit any claim, and the unwrap fails. Licenses
issued now are format v2, which binds a hash of **every** claim into the KEK
(everything except the wrapped keys themselves and, for binding `none`, the
unbound secret), so removing `revocation_url` or adding an entitlement breaks
the unwrap even in a loader with the signature check patched out. Older v1
licenses still load; their KEK covers only license and customer id, product,
payload id, binding policy, issue and expiry dates, and their other claims are
protected only by the signature. Two checks remain ordinary code in the loader:
the **signature** and the **expiry** check. Patch those out and an *unedited*
expired license still unwraps on its own machine, so for enforced expiry use the
`online` provider. The loader also refuses to start when the clock is more than
24 hours behind the latest start it recorded for an expiring license (sealed in
`CRYPTSHIP_STATE_DIR`), but deleting that state resets the check: it stops a
casual clock rollback, not a determined one. With binding `none`, the license itself carries the key
material: treat it like a secret.

## Quickstart

Requires only a working `docker` (e.g. [colima](https://github.com/abiosoft/colima)
on macOS). The tools compile in a Go container, and the layer scan and the
tamper step also run in containers.

```bash
bash scripts/demo.sh
```

To install the tools directly (Go 1.24 or later):

```bash
go install github.com/AI2TH/cryptship/cmd/...@latest
```

The demo packs a tiny Python app, issues a license, builds the image, then
**`docker save`s it, unpacks every layer and greps for a marker planted in the
app's source** to show the source isn't there,
runs it to show it decrypts and works, and finally tampers with the license to
show the loader refuses it.

## Documentation

- **[docs/DIAGRAMS.md](docs/DIAGRAMS.md)** — what it solves + flow and
  architecture diagrams (how it works, visually).
- **[docs/HOWTO.md](docs/HOWTO.md)** — step-by-step guide for every workflow
  (build, each binding mode, compile, hardening, the server, rotation).
- **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** — design, threat model, license
  format, roadmap.
- **[deploy/README.md](deploy/README.md)** — hardened docker / Kubernetes deployment.

## Deployment modes = key providers

Air-gapped, on-prem, and cloud differ only in **how the content key is
acquired**. That is a single pluggable interface (`pkg/keyprovider`):

| Mode | Provider | Binding | Revocation |
|---|---|---|---|
| **Air-gapped** | `offline` | machine fingerprint, or none | expiry only |
| **On-prem / cloud** | `online` | per-license secret held by your server | **real** — the server declines |
| **Confidential** | `attested` | SEV-SNP/TDX attestation gates the key | planned: interfaces + test-only verifier today |

The loader, license format, crypto, and app are identical across all modes — only
the key provider differs. `offline` (none/strict/pool) and `online` are built and
tested; `online` uses the reference `cryptship-server` (a stateless key broker).
`attested` is built behind an `Attester` interface (loader) and an
`attest.Verifier` interface (server), each with a test-only implementation. There
is no production verifier yet, so `cryptship-server --require-attestation`
refuses to start rather than accept evidence it cannot check. Real SEV-SNP/TDX
quote generation needs confidential-compute hardware (see
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)).

## Hardening & anti-extraction

The image is ciphertext at rest, but once the app runs its plaintext is in the
container's memory — and container/host **root can dump it**. cryptship cannot
change that fact (only confidential compute or remote execution can), but it
ships mechanisms to raise the cost sharply, especially against AI-assisted
source reconstruction:

- **Compile/obfuscate before sealing** — `cryptship pack --transform-cmd "<cmd>"`
  runs your toolchain over the app before encrypting, so a dump yields compiled
  artifacts, not source. Python-bytecode recipe in `scripts/compile-python.sh`
  (Nuitka for native code is a one-line swap); proof in `scripts/demo-compiled.sh`.
- **Runtime hardening** — the loader marks itself non-dumpable; run the container
  with the seccomp profile + non-root + dropped caps + read-only + tmpfs from
  `deploy/`. Stops other non-root users in the container; anything running as
  the app's own uid, container root or host root can still read the decrypted
  files.
- **Per-license watermark** — the loader drops `.cryptship-manifest.json` and
  exposes `CRYPTSHIP_LICENSE_ID` / `CRYPTSHIP_CUSTOMER` to the app, so a leaked
  instance traces to its licensee (a deterrent — strippable).

**Honest limit:** against **root on the machine where the code runs**, none of
this is a barrier — only a confidential-compute key provider (SEV-SNP/TDX +
attestation) or keeping the crown-jewel logic server-side actually prevents
extraction. See [`deploy/README.md`](deploy/README.md) and
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## License format

A license is signed Ed25519 claims plus a detached signature. The signed claims
carry the wrapped content key, the payload id, expiry, binding policy, and the
signing-key id (for rotation). See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
for the full schema and the threat model.

## Status

**Built & tested:** AES-256-GCM payload encryption; Ed25519 licenses (detached
signature over the stored bytes); context-bound KEK (format v2: editing any claim breaks
the unwrap); machine binding (none / strict / pool); online key provider + reference
`cryptship-server`; signing-key rotation (key ring); configurable revocation
(open / closed / grace); the compile/transform seam; loader + container
hardening; per-license watermarking; and the attested (confidential-compute)
provider behind `Attester` / `attest.Verifier` interfaces with test-only
implementations (no production verifier yet).

**Roadmap:** a real SEV-SNP/TDX `Attester` + Trustee-style KBS integration,
TPM-sealed binding, cloud-KMS wrapping, offline grace caching for `online`, and
chunked AEAD for very large payloads.

## Crypto

All primitives are Go standard library (AES-256-GCM, HKDF-SHA256, Ed25519) — no
third-party crypto, minimal supply chain. Not yet independently audited; do not
rely on it for high-value IP until it is.

## License

GPLv3. See [LICENSE](LICENSE). The GNU GPL requires that distributed modified
versions also be released under the GPL and that recipients can get the source —
appropriate for a tool whose purpose is protecting source you choose to keep
closed while keeping the toolkit itself open.
