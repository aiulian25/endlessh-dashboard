# syntax=docker/dockerfile:1.7

# =============================================================================
# Base image digests
# =============================================================================
# Both stages are pinned by digest, not just by tag, so a rebuild months from
# now produces the same bits and a compromised tag cannot silently change the
# base.
#
# The digests below are real and were resolved on 2026-08-24. Refresh them
# whenever you bump the Go version or pick up a distroless security update:
#
#   docker buildx imagetools inspect golang:1.26-bookworm \
#     --format '{{.Manifest.Digest}}'
#   docker buildx imagetools inspect gcr.io/distroless/static-debian12:nonroot \
#     --format '{{.Manifest.Digest}}'
#
# Paste each result after the `@` on the matching FROM line.
# =============================================================================

# =============================================================================
# Stage 1 - builder
# =============================================================================
# --platform=$BUILDPLATFORM pins the builder to the machine doing the building
# and cross-compiles from there, rather than emulating the target architecture
# through QEMU to run a Go toolchain on it. Nothing here is arch-specific —
# CGO is off and the SQLite driver is pure Go — so the cross-built binary is
# the same binary, produced in a fraction of the time.
FROM --platform=$BUILDPLATFORM golang:1.26-bookworm@sha256:6ef6e30f0ea5c384f6d111cf856e024e3086bbdcb1779da3f3b3fbba0aea53d2 AS builder

WORKDIR /src

# Module download is its own layer, invalidated only when go.mod/go.sum change.
# Ordinary source edits reuse the cached module tree.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev

# TARGETARCH is one of BuildKit's automatic platform arguments: it is filled in
# per platform in the manifest (amd64, arm64) and MUST be declared with no
# default. Giving it one turns it into an ordinary build argument, the default
# wins for every platform, and the arm64 image silently ships an amd64 binary
# that dies with "exec format error" on the machine it was built for.
ARG TARGETARCH

# CGO_ENABLED=0 is what makes the binary static, which is what makes the
# distroless-static runtime stage (and the sub-30MB image) possible.
# -trimpath removes local filesystem paths; -s -w drop the symbol table and
# DWARF debug data, which is most of the size saving.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build \
        -trimpath \
        -ldflags="-s -w -X main.version=${VERSION}" \
        -o /out/endlessh-dashboard \
        ./cmd/endlessh-dashboard

# A named volume mounted at /data inherits its ownership from this directory
# the first time Docker initialises it. Without it the volume comes up
# root-owned and the nonroot process cannot create the database.
# 65532 is the uid/gid of distroless's `nonroot` user.
RUN mkdir -p /data && chown 65532:65532 /data

# =============================================================================
# Stage 2 - runtime
# =============================================================================
# static-debian12 (not `base`) carries CA certificates and tzdata and nothing
# else: no shell, no package manager, no libc. A static Go binary needs
# nothing more.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

ARG VERSION=dev

LABEL org.opencontainers.image.title="endlessh-dashboard" \
      org.opencontainers.image.description="Self-hosted dashboard for endlessh-go SSH tarpits" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.base.name="gcr.io/distroless/static-debian12:nonroot" \
      org.opencontainers.image.source="https://github.com/aiulian25/endlessh-dashboard"

COPY --from=builder /out/endlessh-dashboard /usr/local/bin/endlessh-dashboard
COPY --from=builder --chown=65532:65532 /data /data

USER nonroot:nonroot
EXPOSE 18222
VOLUME /data

ENTRYPOINT ["/usr/local/bin/endlessh-dashboard"]
