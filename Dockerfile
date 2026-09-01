# The builder digest is an OCI index supporting the release architectures.
FROM rust:1.98.0-slim-bookworm@sha256:1469a27c125cb5a3aebfa4f4e4665d935b02fb72cc093b2c974b3d740e43f157 AS builder
WORKDIR /workspace
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY docs/mist-api/catalog.json ./docs/mist-api/catalog.json
RUN cargo build --release --locked --bin rustmistmcp

# This distroless Debian 13 image supplies the required CA trust store.
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:c31ff9abcb1910f3ab25c7957bdaf0bfe12a01eb546e8df2282f1c8f682b606c
ARG VERSION=0.0.0-pre-release
ARG REVISION=unknown
ARG CREATED=unknown
LABEL org.opencontainers.image.title="rustmistmcp" \
      org.opencontainers.image.description="Pre-release MCP server for HPE Juniper Mist" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$REVISION" \
      org.opencontainers.image.created="$CREATED" \
      org.opencontainers.image.source="https://github.com/fastrevmd-lab/rustmistmcp" \
      org.opencontainers.image.licenses="MIT"
COPY --from=builder /workspace/target/release/rustmistmcp /usr/local/bin/rustmistmcp
USER 65532:65532
EXPOSE 30030
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/rustmistmcp"]
CMD ["--device-mapping", "/etc/rustmistmcp/mist.json", "--transport", "streamable-http", "--host", "127.0.0.1", "--port", "30030", "--tokens-file", "/var/lib/rustmistmcp/tokens.json", "--audit-format", "json", "--audit-redact", "devices=hmac,host=hmac,name=hmac,basename=hmac,command=hmac,pfe_command=hmac", "--audit-hmac-key-file", "/etc/rustmistmcp/audit-hmac.key"]
