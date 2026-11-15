# cryptship — improvements / roadmap

Most items from the November 2026 code review shipped in **v0.2.0–v0.3.0**. See
[CHANGELOG.md](CHANGELOG.md) for what landed and
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) (Roadmap) for the design.

## Shipped (v0.2.x–v0.3.0)

- Signed, nonce-bound revocation checks; live `--revoke-file` (no restart);
  sealed clock-rollback and revocation-grace state.
- Online outage grace (`CRYPTSHIP_ONLINE_GRACE`) — a machine-sealed content key
  with authenticated validity.
- Attested protocol: server-issued single-use challenge + ephemeral **X25519**
  key, secret sealed to that key; policy-bound server-secret versioning
  (`secret_v`) so an online server can't release attested secrets.
- Seat enforcement; opt-in separate-uid extraction and `memfd` exec;
  context-bound KEK (format v2); `--expires-end-of-day`.
- Go fuzzing (license, tar, response/challenge decoders); `SECURITY.md`,
  `CONTRIBUTING.md`, `CHANGELOG.md`.

## Remaining roadmap

- **Real SEV-SNP / TDX attestation verifiers** (`go-sev-guest` / `go-tdx-guest`).
  The protocol and the `attest.Verifier` seam are in place; the verifiers need
  confidential-compute hardware to build and test.
- **TPM sealing and cloud instance-identity** binding providers, so binding
  survives root-level fingerprint spoofing.
- **Chunked AEAD** for very large payloads; seat reactivation API.

## Inherent limits (documented, not "fixable")

- Host/container **root can extract the running plaintext** — only a
  confidential-compute key provider or remote execution prevents this.
- A **patched** open-source loader can skip loader-enforced policy (expiry
  comparison, revocation). The crypto stops license forgery and claim tampering,
  not modification of the loader someone runs.

See the threat model in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
