# syntax=docker/dockerfile:1
#
# Minimal container image for the openszigno CLI. The build stage links a
# static musl binary; the final stage is `scratch`, so the image contains
# the binary and nothing else: no shell, no package manager, no libc.
#
# Built for linux/amd64 and linux/arm64 by .github/workflows/container.yml.

FROM rust:1-alpine AS build

# musl-dev provides the C toolchain rustc needs to link a musl binary.
RUN apk add --no-cache musl-dev

WORKDIR /src
COPY . .

RUN cargo build --release --locked -p openszigno-cli \
    && strip target/release/openszigno

FROM scratch

ARG VERSION=0.5.1
ARG REVISION=unknown

LABEL org.opencontainers.image.title="openSzigno" \
      org.opencontainers.image.description="Safe, agent-friendly CLI for inspecting and extracting Microsec e-Szigno dossiers" \
      org.opencontainers.image.url="https://github.com/watt-mind/openSzigno" \
      org.opencontainers.image.source="https://github.com/watt-mind/openSzigno" \
      org.opencontainers.image.documentation="https://github.com/watt-mind/openSzigno#readme" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.vendor="Watt-Mind" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

COPY --from=build /src/LICENSE /LICENSE
COPY --from=build /src/target/release/openszigno /openszigno

# No passwd database exists in a scratch image, so the user is numeric.
USER 65532:65532

WORKDIR /work

ENTRYPOINT ["/openszigno"]
CMD ["--help"]
