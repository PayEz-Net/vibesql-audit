FROM postgres:16

RUN apt-get update && apt-get install -y \
    build-essential \
    postgresql-server-dev-16 \
    && rm -rf /var/lib/apt/lists/*

COPY ext/ /build/ext/
WORKDIR /build/ext

RUN make clean && make && make install

RUN echo "shared_preload_libraries = 'vibe_audit'" >> /usr/share/postgresql/postgresql.conf.sample
