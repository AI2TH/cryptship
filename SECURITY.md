# Security policy

## Reporting a vulnerability

Please report security issues **privately**, not as a public issue or PR.

- Preferred: GitHub → the repository's **Security** tab → **Report a vulnerability**
  (private vulnerability reporting / security advisory).
- Include: affected version or commit, a description, and ideally a minimal
  reproduction (a crafted license, a sequence of commands, or a short test).

We aim to acknowledge a report within a few days and to agree on a disclosure
timeline with you. Please give us reasonable time to fix before any public
disclosure.

## Supported versions

cryptship is pre-1.0 and moves fast. Fixes land on `main` and in the latest
tagged release; please verify against the latest release before reporting.

## Scope — what is and isn't a vulnerability

cryptship's threat model is stated plainly in the [README](README.md) and
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). In particular, these are **known,
documented limitations, not vulnerabilities**:

- **Host/container root extracting the running plaintext** (dumping tmpfs or
  `/proc/<pid>/mem`). Code that runs on hardware the attacker controls can always
  be extracted; only a confidential-compute key provider (SEV-SNP/TDX, the
  `attested` roadmap) or remote execution prevents this.
- **A patched loader** skipping loader-enforced policy (expiry comparison,
  revocation). The crypto design makes license *forgery* and claim *tampering*
  fail the unwrap; it does not stop someone from modifying the open-source loader
  they run.
- **`attested` mode without a real verifier.** It ships with test-only
  attestation; `cryptship-server --require-attestation` fails closed precisely so
  this isn't mistaken for protection.
- **Enabling `CRYPTSHIP_ONLINE_GRACE` on an untrusted host** (documented
  trade-off), and **software machine fingerprints being spoofable by root**.

In scope and very welcome: key/secret handling bugs, signature or AEAD
verification that can be bypassed, nonce/replay/downgrade flaws, path-traversal
or extraction escapes, anything that lets an **unprivileged** in-container
attacker read the decrypted app, or any way to unwrap the content key without
legitimate license material.
