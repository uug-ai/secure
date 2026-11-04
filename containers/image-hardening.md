# Container image hardening

Source: [UUG Learn image hardening guide](https://learn.uug.ai/guides/security/image-hardening/).
Imported on 2026-11-04 for further development in this repository.

This document defines security guidance, not evidence that any particular image
meets it. See the [container scan inventory](README.md) for vulnerability evidence
and the [security control register](../controls/control-register.md) for assessment
status. Neither a published standard nor a clean vulnerability scan establishes
CIS compliance.

Container images must be small, reproducible, traceable, and safe to run with least privilege. This guide defines our baseline for production images and aligns image construction with the image and Dockerfile controls in Section 4 of the [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker).

This is an image-build standard. Customers remain responsible for hardening their container runtime, hosts, orchestrator, network, and deployment policies. Describe an image as **CIS Docker Benchmark Section 4 aligned** only when the applicable controls have been assessed and any exceptions are documented. Do not make an unqualified claim that the complete deployment is CIS compliant.

## Required practices

### Use trusted and immutable base images

* Use official or otherwise approved images from a trusted registry.
* Use a currently supported release and track its end-of-support date.
* Pin every build and runtime base to its multi-platform SHA-256 digest.
* Keep the human-readable tag next to the digest so maintainers can see the expected version.
* Review and update pinned digests regularly. Digest pinning prevents an unexpected change; it does not deliver security updates automatically.

```dockerfile
FROM golang:1.25.14-bookworm@sha256:<builder-image-digest> AS builder
```

Never use floating tags such as `latest` for production builds.

### Use multi-stage builds

Compilers, source code, package managers, and build tools belong in a builder stage, not in the image delivered to a customer. Copy only the files required at runtime into the final stage.

For a Go service, copy `go.mod` and `go.sum` before application source. This allows dependency downloads to be cached independently while ensuring that a source-code change does not invalidate the dependency layer.

```dockerfile
WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked \
    go mod download && \
    go mod verify

COPY main.go ./
COPY internal/ ./internal/
```

Prefer explicit `COPY` instructions over `COPY . .`. Explicit copies prevent credentials, repository metadata, local binaries, and unrelated source files from entering the build context or cache.

### Protect the build context

Every repository that builds an image must have a `.dockerignore`, even when the Dockerfile uses explicit copies.

```text
.git
.github
.devcontainer
.vscode

.env
.env.*

coverage.out
*.test
main
```

Add project-specific generated data, local state, test output, and credentials to this list. Never rely on a multi-stage build alone to protect sensitive files: anything left out of the final stage can still be sent to the builder and retained in its cache.

### Keep dependency verification enabled

Do not set `GOSUMDB=off` globally. Public Go dependencies must continue to use the public checksum database. Scope private modules with `GOPRIVATE`, which also sets the default behaviour for `GONOPROXY` and `GONOSUMDB`.

```dockerfile
ENV GOPRIVATE=github.com/uug-ai/*
```

Continue to commit `go.sum`, use `-mod=readonly`, and run `go mod verify`.

### Never pass credentials as build arguments

Docker `ARG` and `ENV` are not secret transports. Credentials can be exposed through image metadata, build history, logs, or cache. If a clean build needs access to a private module, use a [BuildKit secret mount](https://docs.docker.com/build/building/secrets/).

```dockerfile
RUN --mount=type=secret,id=github_token,env=GITHUB_TOKEN \
    git config --global \
      url."https://x-access-token:${GITHUB_TOKEN}@github.com/".insteadOf \
      "https://github.com/" && \
    go mod download && \
    go mod verify && \
    rm -f /root/.gitconfig
```

Supply the secret from CI without writing it to the repository:

```shell
docker buildx build \
  --secret id=github_token,env=GITHUB_TOKEN \
  .
```

Use a short-lived, read-only token with access only to the required modules. When all dependencies are public, do not provide a token.

### Produce a static Go binary when possible

A static binary allows the final image to omit libc and an operating-system distribution. Use reproducible build flags and verify both supported architectures.

```dockerfile
ARG TARGETOS=linux
ARG TARGETARCH

RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked \
    --mount=type=cache,target=/root/.cache/go-build,sharing=locked \
    CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    go build \
      -mod=readonly \
      -trimpath \
      -buildvcs=false \
      -tags timetzdata,netgo \
      -ldflags="-s -w -buildid=" \
      -o /out/main \
      .
```

Do not set `CGO_ENABLED=0` without testing the resulting application. Database drivers, Kafka clients, image-processing libraries, and hardware integrations may require CGO or shared libraries. When they do, use a minimal, supported, digest-pinned distroless runtime containing only the required libraries.

### Prefer an empty or distroless runtime

Use `scratch` for a verified static binary:

```dockerfile
FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt \
  /etc/ssl/certs/ca-certificates.crt
COPY --from=builder --chown=65532:65532 /out/main /app/main

USER 65532:65532
WORKDIR /app

EXPOSE 8080/tcp
ENTRYPOINT ["/app/main"]
```

`scratch` is a special empty base. It contains no operating system, shell, package manager, libc, or debugging tools. Copy CA certificates when the service makes TLS connections. Compile timezone data into the Go binary or copy it explicitly when the application requires it.

Use a minimal distroless image instead when the application requires dynamic libraries. Do not install a shell, `curl`, a compiler, or a package manager in the final image merely for convenience.

### Run as a fixed non-root identity

* Set `USER` to an explicit numeric UID and GID.
* Use a high, unprivileged ID consistently; `65532:65532` is our default for images without an `/etc/passwd`.
* Copy runtime files with explicit ownership.
* Keep application files read-only for the runtime identity.
* Write only to documented data or temporary paths.
* Listen on ports above 1024.

Numeric identities work in `scratch` without a user database because the Linux kernel runs the process directly with those IDs.

### Do not add capabilities or special permission bits

A normal service image must not contain setuid or setgid executables, and its application binary must not have file capabilities. In particular, do not add `CAP_NET_BIND_SERVICE` when the service can listen on an unprivileged port such as 8080.

Runtime platforms can override image defaults, so customers must still enforce capability dropping, non-root execution, privilege-escalation prevention, and a read-only root filesystem in their deployment policy.

### Add health checks only when they are valid

Do not weaken a minimal image by installing `curl` or a shell only to implement a health check. A `scratch` or distroless image should expose a health-check subcommand in the application or include a purpose-built static probe.

The check must:

* Exercise a meaningful readiness or liveness signal.
* Have a bounded timeout.
* Return a non-zero status when unhealthy.
* Avoid credentials and external dependencies where possible.

Do not publish a health check that starts a second copy of the service or tests the wrong port. If the customer orchestrator owns health checking, document the endpoint, port, timeout, and expected response as part of the image contract.

### Add traceable metadata

Add standard OCI labels and populate release-specific values from CI:

```dockerfile
ARG VERSION=dev
ARG REVISION=unknown
ARG CREATED

LABEL org.opencontainers.image.title="service-name" \
      org.opencontainers.image.source="https://github.com/uug-ai/service-name" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.vendor="UUG.AI"
```

Publish immutable image digests alongside readable version tags.

## CI and release controls

Hardening is not complete when the Dockerfile builds. CI must:

1. Build every supported architecture from the same source revision.
2. Scan the final image for operating-system and application dependency vulnerabilities.
3. Scan the repository, Dockerfile, and image for embedded secrets and misconfiguration.
4. Fail the release for prohibited findings. At minimum, critical and high vulnerabilities require remediation or an approved exception with an owner and expiry date.
5. Generate an SPDX or CycloneDX software bill of materials.
6. Generate build provenance rather than disabling it.
7. Sign the final multi-platform image with Cosign or an equivalent signing system.
8. Retain the scan reports, SBOM, provenance, signature, source revision, base image digest, and final image digest as release evidence.

Scanning must be release-blocking. A scanner configured to report findings but always exit successfully is informational, not an enforcement control.

## Image contract

Document the following for customers:

* Image registry, version tag, immutable digest, and supported architectures.
* Numeric UID and GID.
* Entrypoint and exposed ports.
* Required environment variables and secrets, without example credentials.
* Required CA certificates and timezone behaviour.
* Writable paths and expected volume mounts.
* Health and metrics endpoints.
* Expected outbound connections.
* SBOM, signature-verification instructions, and vulnerability policy.

The customer is responsible for runtime controls such as seccomp or AppArmor, capability dropping, read-only filesystem enforcement, secrets injection, resource limits, network policy, and orchestrator configuration.

## Review checklist

Before releasing an image, verify:

* Builder and runtime bases are approved, supported, and digest-pinned.
* The final image contains only required runtime files.
* `.dockerignore` excludes credentials, VCS metadata, and generated files.
* No credential is passed through `ARG`, `ENV`, a copied file, or a layer.
* Public dependency checksum verification remains enabled.
* Private modules are scoped with `GOPRIVATE`.
* The application runs as a fixed numeric non-root UID/GID.
* No shell, package manager, unnecessary utility, capability, setuid file, or setgid file is present.
* TLS certificates and timezone data are included only when required.
* Health-check behaviour is valid and documented.
* All supported architectures build and pass tests.
* Vulnerability, secret, and configuration scans enforce the release policy.
* SBOM, provenance, signature, and immutable image digest are published.
* Any CIS control exception is documented with justification, owner, and expiry date.
