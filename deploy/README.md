# Hardened deployment

cryptship ships the *mechanisms*; how hard you turn the dials is the adopter's
choice. This directory has the pieces to run a cryptship image with the runtime
hardened against an in-container attacker. **Read the honest limits at the
bottom — none of this stops host/container root; only a confidential-compute key
provider or remote execution does.**

## Hardened `docker run`

```bash
docker run --rm \
  --user 65532:65532 \
  --read-only \
  --tmpfs /run/cryptship:rw,mode=0700,uid=65532,gid=65532 \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --security-opt seccomp=deploy/seccomp.json \
  -e CRYPTSHIP_REQUIRE_TMPFS=1 \
  your-cryptship-image
```

- `--user 65532:65532` — run the loader and the app as an unprivileged user,
  never root (the example Dockerfiles also set `USER 65532:65532`).
- `--read-only` — root filesystem is immutable; the app may only write to the tmpfs.
- `--tmpfs /run/cryptship:...,uid=65532,gid=65532` — decrypted code lives in RAM,
  never on disk, in a directory only that user can enter.
- `CRYPTSHIP_REQUIRE_TMPFS=1` — the loader refuses to run if the extract dir is not tmpfs.
- `--cap-drop=ALL` — removes `CAP_SYS_PTRACE` etc.
- `--security-opt=no-new-privileges` — no privilege escalation via setuid.
- `seccomp=deploy/seccomp.json` — denies `ptrace`/`process_vm_readv`/`process_vm_writev`/`kcmp` for every process in the container.

Run as a non-root user (set `USER` in your image, pass `--user`, and mount the
tmpfs writable by that uid), so a compromised app user cannot read another
user's memory. With `--read-only`, the loader cannot persist revocation-grace or
clock-rollback state in `/var/lib/cryptship`: it warns that the clock check is
disabled, and `CRYPTSHIP_REVOCATION=grace:...` has no record to fall back on. To
keep them, mount a small writable volume owned by that uid at
`CRYPTSHIP_STATE_DIR` (e.g. `-v cryptship-state:/var/lib/cryptship`).

## Variant (opt-in, off by default): the app cannot change its own code

In the setup above the loader and the app share uid 65532, so the app (or
anything that compromises it) can rewrite the extracted code. To prevent that,
start the loader as root and let it drop privileges:

```bash
docker run --rm \
  --user 0:0 \
  -e CRYPTSHIP_APP_USER=65532:65532 \
  --read-only \
  --tmpfs /run/cryptship:rw,mode=0755 \
  --cap-drop=ALL --cap-add=CHOWN --cap-add=SETUID --cap-add=SETGID \
  --security-opt=no-new-privileges \
  --security-opt seccomp=deploy/seccomp.json \
  -e CRYPTSHIP_REQUIRE_TMPFS=1 \
  your-cryptship-image
```

- The loader extracts into `/run/cryptship/app`, gives the tree to root (or
  `CRYPTSHIP_EXTRACT_OWNER=<uid>`) and group 65532 with modes 0750 / 0640, then
  drops to 65532:65532 with no supplementary groups and checks it cannot get
  root back before it execs the app.
- The app can read and run its code but not modify, add or delete files there,
  and no other non-root user can read it. The app's own uid can still read and
  copy the code.
- Only `CAP_CHOWN`, `CAP_SETUID` and `CAP_SETGID` are needed, and only by the
  loader: the app starts with none (a uid change clears capabilities, and
  `no-new-privileges` stops it regaining any).
- The tmpfs mount point must be traversable by the app user (`mode=0755`).
- Root without `CAP_DAC_OVERRIDE` cannot write a state dir owned by 65532, so
  mount the state volume owned by root in this mode, or accept the warning that
  the clock check is off.
- Set without root, `CRYPTSHIP_APP_USER` is an error, never a silent fallback.

## Variant (opt-in, off by default): no decrypted file at all (single binary)

This does not fit a multi-file interpreter app (Python, Node); it is for a
payload that is one native executable.

For a payload that is one ELF executable (Go, Rust, a Nuitka `--onefile`
build), set `CRYPTSHIP_EXEC_MEMFD=<path in payload>`. The loader copies that
entry into a sealed, close-on-exec memfd and executes it from there; nothing is
written to the extract dir. The arguments after `--` become argv
(`cryptship-loader -- server --port 8080`). Scripts (`#!`) cannot run this way.
The binary still exists in RAM and can be read back through
`/proc/<pid>/exe` by anyone allowed to ptrace the app, so combine it with the
next point.

## Make the app non-dumpable again

The loader is non-dumpable while it holds the key, but execve resets that, so
the app starts dumpable. Have the app call `prctl(PR_SET_DUMPABLE, 0)` first:
`harden.NonDumpable()` from `github.com/AI2TH/cryptship/pkg/harden` in Go, or
`cryptship_harden.set_non_dumpable()` from `helpers/python/cryptship_harden.py`
in Python (standard library only). After that, other processes of the same uid
cannot ptrace it or read its `/proc/<pid>/mem` or `/proc/<pid>/exe`.

## Kubernetes

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: cryptship-app
spec:
  containers:
    - name: app
      image: your-cryptship-image
      env:
        - name: CRYPTSHIP_REQUIRE_TMPFS
          value: "1"
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: ["ALL"]
        seccompProfile:
          type: Localhost            # or RuntimeDefault
          localhostProfile: cryptship/seccomp.json
      volumeMounts:
        - name: cryptship-tmpfs
          mountPath: /run/cryptship
  volumes:
    - name: cryptship-tmpfs
      emptyDir:
        medium: Memory               # tmpfs: decrypted code stays in RAM
```

## What this does and does not protect

| Attacker | Stopped? |
|---|---|
| Someone with just the image (not running it) | **Yes** — ciphertext only. |
| Another non-root user in the container | **Yes** — seccomp + non-root + dropped caps block ptrace/mem-read of the app. |
| Code running as the app's own uid | **Read: no** — it can read the decrypted files. **Modify: yes** with `CRYPTSHIP_APP_USER` (the tree belongs to another uid). With the dumpable helpers it cannot ptrace the running app. |
| **Container or host root with a privileged sidecar** | **No** — root can run a process outside this profile and read `/proc/<pid>/mem`. |
| Host root dumping guest RAM | **No** — needs a confidential-compute key provider (SEV-SNP/TDX), on the roadmap. |

To raise the bar against root: ship the app **compiled/obfuscated** (`cryptship
pack --transform-cmd ...`, see the repo root), so even a successful dump yields
compiled artifacts rather than source; and plan for a confidential-compute
provider if "host root cannot read it" must be true.
