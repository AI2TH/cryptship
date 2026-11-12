# cryptship

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

There is **no "is the license valid?" boolean** for an attacker to patch. The
content key is *derived from the license and binding material*, so a valid
signature and a successful decrypt are the same event:

```
content_key = unwrap(license.wrapped_key, KEK = derive(machine_fingerprint, license_id))
plaintext   = aead_open(payload.enc, content_key)   # wrong key => AEAD tag fails
```

Tamper with the license, or run on an unbound machine, and the unwrap produces
nothing usable. There is no code path that decrypts without legitimate license
material.

## Quickstart

Requires a working `docker` (e.g. [colima](https://github.com/abiosoft/colima)
on macOS). Nothing else is installed on the host — the tools compile in a Go
container.

```bash
bash scripts/demo.sh
```

The demo packs a tiny Python app, issues a license, builds the image, then
**`docker save`s it and greps every layer** to prove the source isn't there,
runs it to show it decrypts and works, and finally tampers with the license to
show the loader refuses it.

## Deployment modes = key providers

Air-gapped, on-prem, and cloud differ only in **how the content key is
acquired**. That is a single pluggable interface (`pkg/keyprovider`):

| Mode | Provider | Binding | Revocation |
|---|---|---|---|
| **Air-gapped** | `offline` | machine fingerprint, or none | expiry only |
| **On-prem / cloud** | `online` | per-license secret held by your server | **real** — the server declines |
| **Confidential** | `attested` | SEV-SNP/TDX attestation gates the key | real + anti-tamper |

The loader, license format, crypto, and app are identical across all modes — only
the key provider differs. `offline` (none/strict/pool) and `online` are built and
tested; `online` uses the reference `cryptship-server` (a stateless key broker).
`attested` is built behind an `Attester` interface with a mock for tests — real
SEV-SNP/TDX quote generation needs confidential-compute hardware (see
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
  `deploy/`. Stops a non-root / in-container attacker (not host root).
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
signature over the stored bytes); context-bound KEK (editing a claim breaks the
unwrap); machine binding (none / strict / pool); online key provider + reference
`cryptship-server`; signing-key rotation (key ring); configurable revocation
(open / closed / grace); the compile/transform seam; loader + container
hardening; per-license watermarking; and the attested (confidential-compute)
provider behind an `Attester` interface with a mock key broker.

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
