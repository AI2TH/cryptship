# cryptship — Improvements

What still needs work, in priority order. Last reviewed: November 2026 (after the code review in #8).

---

## P0 — Security

### 1. The revocation check response is unsigned
- **What:** any HTTP 200 from `revocation_url` counts as "not revoked", even with `CRYPTSHIP_REVOCATION=closed`. An on-path attacker or a captive portal can answer for the server. The grace state file is plain text, so anyone who can write the state directory can extend grace.
- **How to fix:** have the revocation endpoint return a signed, nonce-bound response (reuse the online key server's response format and signing key). Seal the grace state with a key derived from the binding material, and reject future timestamps.

### 2. Attested mode can be replayed — #3
- **What:** the client chooses the nonce, and the released secret is not encrypted to a key held inside the TEE. A captured request with genuine evidence can be replayed.
- **How to fix:** make the server issue a challenge nonce, have the guest put `hash(nonce ‖ ephemeral public key)` into the report's REPORT_DATA, and encrypt the secret to that ephemeral key (the Trustee / KBS pattern). Then implement real SEV-SNP (`go-sev-guest`) and TDX (`go-tdx-guest`) verifiers.

### 3. The server cannot tell attested licenses from online ones
- **What:** a server without a verifier, but sharing the same master key, will release attested-license secrets.
- **How to fix:** bind the binding policy into the server-side derivation (`HKDF(master, license_id ‖ policy)`), so an online server cannot produce attested secrets. Until then, use a separate master key for attested servers (documented in HOWTO.md).

### 4. Decrypted payload exposure — #5
`USER 65532` is done (#8). Still open:
- extract into a directory owned by a separate uid, readable only by the app's group;
- an option to exec single-binary payloads from `memfd_create` + `fexecve`, leaving no file on disk;
- small helpers for Go and Python apps to re-apply `PR_SET_DUMPABLE` after exec.

---

## P1 — Correctness and robustness

### 5. Offline expiry hardening — #2
The clock-rollback record (#8) can be reset by deleting it. Seal it with the binding-derived key and keep a copy inside the extract-dir manifest. Add the optional server-signed time for the `online` provider.

### 6. Online provider resilience — #4
- **Grace cache:** after a successful fetch, seal the binding secret under a machine-derived key with an expiry, and use it during an outage when `CRYPTSHIP_ONLINE_GRACE=<duration>` is set.
- **Live denylist:** reload revocations from a file on change, or add an authenticated `POST /admin/revoke`.
- **Seats:** enforce `max` distinct machines per license (the `machine` field is sent but ignored).

### 7. `--expires YYYY-MM-DD` ends at the start of the day
It expires at 00:00 UTC on the given date, which surprises people. Add `--expires-end-of-day`, or change the meaning in a major version with a clear release note.

---

## P2 — Developer experience

### 8. `scripts/check-mermaid.sh` docker fallback fails on Linux
Its `mktemp -d` directory is 0700, so the mermaid-cli container user cannot read it. `chmod 755` the temp dir, or run the container with `--user $(id -u)`.

### 9. Publish the API changes from #8
For anyone importing the packages, note in the release:
- the module path is now `github.com/AI2TH/cryptship`;
- `Claims.BindingContext()` returns `([]byte, error)`;
- `licenseserver.Server.Verify` is now `Verifier`;
- `keyprovider.MockAttester` is removed.

Tag a release (v0.2.0) once #8 is merged.

### 10. Stronger machine binding
Add TPM sealing and cloud instance-identity providers (both on the roadmap) so binding survives root-level fingerprint spoofing.

---

## P3 — Process

### 11. Security policy
Add `SECURITY.md` with a private reporting address and the threat-model summary, and enable GitHub private vulnerability reporting.

### 12. Fuzzing
Add Go fuzz tests for license parsing, tar extraction (traversal and symlinks) and the online response decoder.
