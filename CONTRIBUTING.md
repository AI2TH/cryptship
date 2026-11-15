# Contributing to cryptship

Thanks for your interest! cryptship is an open-source (GPLv3) toolkit for
shipping encrypted, license-gated application code in container images.

## Build and test

The module is **Go 1.24+** and standard-library only (no third-party
dependencies). You don't need Go on your host — everything can run in a
container:

```bash
# build + vet + race tests, exactly as CI runs them
docker run --rm -v "$PWD":/src -w /src golang:1.24 sh -c '
  gofmt -l .            # must print nothing
  go vet ./...
  go build ./...
  go build -tags cryptship_devfp ./cmd/cryptship-loader
  go test -race ./...'
```

End-to-end demos (need Docker, e.g. colima):

```bash
bash scripts/demo.sh            # baseline
bash scripts/demo-compiled.sh   # ships bytecode, not source
bash scripts/demo-online.sh     # server-gated key + revocation
bash scripts/check-mermaid.sh   # validates the diagrams in docs/
```

The `cryptship_devfp` build tag enables the `CRYPTSHIP_FINGERPRINT` override so
you can exercise `strict`/`pool` binding without real machine ids; it is compiled
out of production builds.

## Pull requests

- Keep the tree **gofmt-clean** and `go vet` / `go test -race` green — CI gates on all three plus mermaid rendering.
- Add tests for behavior changes (the suite leans heavily on table/round-trip tests).
- Touching crypto, the license format, or the online/attested protocol? Say so
  in the PR description and keep changes minimal and reviewable — these are
  security-sensitive. Note any on-disk or wire-format change.
- One logical change per PR where practical.

## Security

Please report vulnerabilities privately — see [SECURITY.md](SECURITY.md). Do not
open a public issue for a security problem.

## License

By contributing, you agree your contributions are licensed under the project's
GPLv3 license.
