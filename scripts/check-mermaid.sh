#!/usr/bin/env bash
# Validate every ```mermaid block in the repo's markdown by rendering it with
# mermaid-cli. Exits non-zero if any diagram has a syntax error, so broken
# diagrams fail CI instead of showing "Unable to render" on GitHub.
#
# Uses `mmdc` if it is on PATH (CI installs @mermaid-js/mermaid-cli); otherwise
# falls back to the mermaid-cli Docker image (handy locally with colima/docker).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMG="ghcr.io/mermaid-js/mermaid-cli/mermaid-cli@sha256:18938e53497376d524e04b1fc0bf7b6d61a491ce9ff7032bb2855d57155acb10"
# Keep the temp dir under the repo so the Docker fallback (colima) can mount it;
# /var/folders and /tmp are not shared into the VM by default.
tmp="$(mktemp -d "$ROOT/.mermaid-check.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

python3 - "$ROOT" "$tmp" <<'PY'
import sys, re, pathlib
root, tmp = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
i = 0
for md in sorted(root.rglob("*.md")):
    if "_work" in str(md):
        continue
    for blk in re.findall(r"```mermaid\n(.*?)```", md.read_text(), re.S):
        i += 1
        (tmp / f"{i:03d}.mmd").write_text(blk)
print(f"extracted {i} mermaid block(s)")
PY

shopt -s nullglob
blocks=("$tmp"/*.mmd)
if [ ${#blocks[@]} -eq 0 ]; then
  echo "no mermaid blocks found"; exit 0
fi

echo '{"args":["--no-sandbox"]}' > "$tmp/pp.json"
render() { # render <in.mmd> <out.svg>
  if command -v mmdc >/dev/null 2>&1; then
    mmdc -q -p "$tmp/pp.json" -i "$1" -o "$2"
  else
    docker run --rm -v "$tmp":/data "$IMG" -i "/data/$(basename "$1")" -o "/data/$(basename "$2")"
  fi
}

fail=0
for f in "${blocks[@]}"; do
  if render "$f" "$f.svg" >/dev/null 2>"$tmp/err"; then
    echo "OK   $(basename "$f")"
  else
    echo "FAIL $(basename "$f")"; sed 's/^/     /' "$tmp/err"; fail=1
  fi
done
[ $fail -eq 0 ] && echo "all mermaid diagrams valid"
exit $fail
