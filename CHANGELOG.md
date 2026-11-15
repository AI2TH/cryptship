# Changelog

All notable changes to cryptship. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions are git tags /
GitHub releases.

## [Unreleased]

### Added (IMPROVEMENTS.md items)
- **Attested protocol:** server-issued single-use challenge (`POST /v1/challenge`),
  evidence over `AttestationBinding(license, challenge, ephemeral key)`, and the
  secret returned sealed to the ephemeral X25519 key. `online.AttestationNonce`
  is replaced by `online.AttestationBinding`.
- **Policy-bound server secrets:** `binding.secret_v` 2 (default for new
  licenses) derives the secret per binding policy, so an online server cannot
  release an attested secret. `issue --server-secret-version 0` for old loaders;
  `cryptship-server --no-legacy-secrets` once all licenses are reissued.
- **Seats:** `issue --max-machines N` + `cryptship-server --enforce-seats`
  (`--seat-lease`, `--seats-file`, `--license-keys`).
- **Binding-derived state key** (`crypto.DeriveStateKey`, `keyprovider.Unlocker`)
  seals the clock-rollback and revocation-grace records; the revocation-grace
  record is no longer a plain-text timestamp.
- **Opt-in, off by default:** `CRYPTSHIP_APP_USER` (separate-uid extraction and
  privilege drop) and `CRYPTSHIP_EXEC_MEMFD` (single ELF binary from a memfd);
  `pkg/harden` and `helpers/python/cryptship_harden.py`.
- `issue --expires-end-of-day`; `--expires` with `--days` is now an error.
- 502/503/504 count as an outage for `CRYPTSHIP_ONLINE_GRACE`.
- Fuzz tests (license parsing, tar extraction, response decoders, challenges).

### Fixed
- `scripts/check-mermaid.sh` docker fallback on Linux (temp dir was 0700).

### Security / fixed (from a full code review)
- **Online grace cache reworked.** It now caches the **content key** instead of
  the per-license binding secret (no portable license-wide credential), and the
  `cached_at` / `not_after` timestamps are **authenticated via the AEAD** and
  both enforced — editing them to widen the window now fails the open.
- **Live revocation freshness.** `cryptship-server` re-reads `--revoke-file` on
  every request (was an mtime/size cache that could miss a same-length edit and
  keep honouring a just-revoked license).
- **Grace timer only refreshes on a signed answer**, so an unsigned (captive
  portal / on-path) "active" response can't extend `CRYPTSHIP_REVOCATION=grace`.
- Server wipes the per-license secret after signing; the signing-key id is bound
  into the signed response/check inputs.
- Loader no longer writes a separate extract-marker file (removes an `O_EXCL`
  collision with a payload that ships that name); it recognises its own extract
  dir by the manifest instead.
- `cryptship` propagates `crypto/rand` errors when generating ids.

### Docs / project hygiene
- Added `SECURITY.md` (private disclosure + honest scope), `CONTRIBUTING.md`,
  this `CHANGELOG.md`.
- README: `go install` now targets `cryptship` + `cryptship-server` only (not the
  loader); roadmap corrected (online grace is shipped).
- HOWTO: documented the Linux-only `fingerprint`, the `cryptship_devfp` /
  `CRYPTSHIP_FINGERPRINT` dev hatch, and the `-- <command>` default.

## [0.2.0]

- Code-review hardening: context-bound KEK (format **v2** binds every claim;
  editing any claim breaks the unwrap), archive symlink-escape fix, clock-rollback
  guard, non-root example images, a layer-opacity scan that unpacks every layer.
- Online/revocation: live `--revoke-file`, **signed** `/v1/check` revocation,
  `CRYPTSHIP_ONLINE_GRACE` outage caching, attestation fails closed
  (`--require-attestation` without a verifier refuses to start).
- `go.mod` module path corrected to `github.com/AI2TH/cryptship`.

## [0.1.0]

- Initial release: AES-256-GCM payload encryption, Ed25519-signed licenses,
  offline key provider (none / strict / pool machine binding), the loader, the
  `cryptship` CLI, the `cryptship-server` reference broker, compile/transform
  seam, container hardening, per-license watermarking, three demos, and docs.
