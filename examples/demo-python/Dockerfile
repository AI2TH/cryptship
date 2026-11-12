# Build context is the repository root:
#   docker build -f examples/demo-python/Dockerfile -t cryptship-demo .
#
# Stage 1 compiles the loader as a static binary. Stage 2 is the shipped image:
# it contains ONLY the loader, the encrypted payload, the signed license, and
# the vendor PUBLIC key. No application source, no content key.

FROM golang:1.24 AS build
WORKDIR /src
COPY go.mod ./
COPY pkg ./pkg
COPY cmd ./cmd
RUN CGO_ENABLED=0 go build -trimpath -o /loader ./cmd/cryptship-loader

FROM python:3.12-slim
COPY --from=build /loader /cryptship-loader
# These three are produced by the vendor steps in scripts/demo.sh.
COPY examples/demo-python/_work/payload.enc  /cryptship/payload.enc
COPY examples/demo-python/_work/license.json /cryptship/license.json
COPY examples/demo-python/_work/vendor.pub   /cryptship/vendor.pub
# Decrypt into tmpfs at runtime: docker run --tmpfs /run/cryptship ...
ENTRYPOINT ["/cryptship-loader", "--", "python", "app.py"]
