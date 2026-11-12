# Hardened deployment

cryptship ships the *mechanisms*; how hard you turn the dials is the adopter's
choice. This directory has the pieces to run a cryptship image with the runtime
hardened against an in-container attacker. **Read the honest limits at the
bottom — none of this stops host/container root; only a confidential-compute key
provider or remote execution does.**

## Hardened `docker run`

```bash
docker run --rm \
  --read-only \
  --tmpfs /run/cryptship:rw,mode=0700 \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --security-opt seccomp=deploy/seccomp.json \
  -e CRYPTSHIP_REQUIRE_TMPFS=1 \
  your-cryptship-image
```

- `--read-only` — root filesystem is immutable; the app may only write to the tmpfs.
- `--tmpfs /run/cryptship` — decrypted code lives in RAM, never on disk.
- `CRYPTSHIP_REQUIRE_TMPFS=1` — the loader refuses to run if the extract dir is not tmpfs.
- `--cap-drop=ALL` — removes `CAP_SYS_PTRACE` etc.
- `--security-opt=no-new-privileges` — no privilege escalation via setuid.
- `seccomp=deploy/seccomp.json` — denies `ptrace`/`process_vm_readv`/`process_vm_writev`/`kcmp` for every process in the container.

Run as a non-root user as well (set `USER` in your image, and mount the tmpfs
writable by that uid), so a compromised app user cannot read another user's
memory.

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
| A non-root process / compromised app user in the container | **Yes** — seccomp + non-root + dropped caps block ptrace/mem-read. |
| **Container or host root with a privileged sidecar** | **No** — root can run a process outside this profile and read `/proc/<pid>/mem`. |
| Host root dumping guest RAM | **No** — needs a confidential-compute key provider (SEV-SNP/TDX), on the roadmap. |

To raise the bar against root: ship the app **compiled/obfuscated** (`cryptship
pack --transform-cmd ...`, see the repo root), so even a successful dump yields
compiled artifacts rather than source; and plan for a confidential-compute
provider if "host root cannot read it" must be true.
