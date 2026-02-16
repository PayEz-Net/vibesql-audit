FROM postgres:16 AS pg-build

RUN apt-get update && apt-get install -y \
    build-essential \
    postgresql-server-dev-16 \
    && rm -rf /var/lib/apt/lists/*

COPY ext/ /build/ext/
WORKDIR /build/ext
RUN make clean && make && make install

FROM rust:1.83-slim AS rust-build

RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

COPY forwarder/ /build/forwarder/
WORKDIR /build/forwarder
RUN cargo build --release

FROM postgres:16

COPY --from=pg-build /usr/lib/postgresql/16/lib/vibe_audit.so /usr/lib/postgresql/16/lib/
COPY --from=pg-build /usr/share/postgresql/16/extension/vibe_audit* /usr/share/postgresql/16/extension/
COPY --from=rust-build /build/forwarder/target/release/vibe-audit-forwarder /usr/local/bin/

RUN echo "shared_preload_libraries = 'vibe_audit'" >> /usr/share/postgresql/postgresql.conf.sample

EXPOSE 5432 9100
