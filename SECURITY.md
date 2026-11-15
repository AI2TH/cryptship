# Security policy

## Reporting a vulnerability

Please report security problems privately, not in a public issue or pull
request.

- Use GitHub private vulnerability reporting:
  <https://github.com/AI2TH/cryptship/security/advisories/new>
  (the repository's **Security** tab, then **Report a vulnerability**).
- If that form is not available, open a public issue that says only that you
  have a security report and would like a private contact. Do not put any
  details in the issue.

Include what you can of: the affected component (loader, `cryptship` CLI,
`cryptship-server`, a `pkg/` package), the version or commit, the steps to
reproduce, and what an attacker gains. A proof of concept helps.

This is a small project maintained on a best-effort basis. Reports are
acknowledged as soon as possible, and a fix and an advisory are coordinated
with the reporter before details are published.

## Supported versions

Only the latest commit on `main` (and the latest tagged release, once there is
one) receives security fixes.

## What cryptship does and does not promise

The full threat model is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). In
short:

**In scope** — please report:

- plaintext application code, or the content key, recoverable from the image,
  the license file or the network traffic;
- a license that decrypts on a machine or with claims it is not bound to, or
  after its binding should have stopped it (forged or edited licenses, KEK
  context bypasses, signature or algorithm confusion);
- a key server that releases a secret it should not (revoked licenses,
  attested secrets without verified evidence, replayed requests or answers);
- forged or replayed revocation answers, or loader state (grace, clock
  records) that can be edited to extend a license;
- path traversal or symlink escapes when the loader extracts a payload;
- the loader running the app with more privilege than configured.

**Out of scope** — known limits, documented as such:

- root (or a hypervisor) on the machine that runs the app can read the
  decrypted code and keys from memory. Only a confidential-compute (`attested`)
  deployment with a real SEV-SNP or TDX verifier addresses this, and cryptship
  does not ship such a verifier yet;
- software machine fingerprints can be spoofed by root; seat limits count the
  fingerprints loaders report;
- deleting the loader's state directory resets the clock-rollback check and
  any revocation grace (it can only shorten grace, not extend it);
- the `attesttest` attester and verifier, which exist for tests and prove
  nothing about the runtime environment;
- denial of service against a license server you operate.
