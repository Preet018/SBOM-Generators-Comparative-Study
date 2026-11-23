# syntax=docker/dockerfile:1
# Variants of the multi-client TCP server (plain C, libc + pthread).
# Build context: corpus/multi-client-tcp-server
# Named context "planted": variants/tcp-server/planted
# Only *.c / *.h / Makefile are copied: the corpus also contains prebuilt macOS (Mach-O) binaries
# named "server"/"client" that would make `make` think the targets are already up to date.

# ---------- glibc build (Debian bookworm toolchain) ----------
FROM gcc:14 AS build-glibc
WORKDIR /src
COPY *.c *.h Makefile ./
RUN make server client && mkdir -p /out && cp server client /out/ \
 && readelf -d /out/server > /out/readelf-server.txt

# ---------- musl builds (Alpine toolchain): dynamic and fully static ----------
FROM alpine:3.22 AS build-musl
RUN apk add --no-cache build-base
WORKDIR /src
COPY *.c *.h Makefile ./
RUN make server && mkdir -p /out && cp server /out/server-dynamic \
 && gcc -g -std=gnu11 -static server.c auth.c customer.c employee.c manager.c admin.c utils.c session_manager.c \
        -o /out/server-static -lpthread \
 && apk info -v 2>/dev/null | grep -E '^musl-[0-9]' > /out/musl-version.txt \
 && grep -qE '^musl-[0-9]' /out/musl-version.txt

# ---------- planted: same program + vendored cJSON source + zlib built from source and linked statically ----------
FROM gcc:14 AS build-planted
ADD https://github.com/DaveGamble/cJSON/archive/refs/tags/v1.7.18.tar.gz /dl/cjson.tar.gz
ADD https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz /dl/zlib.tar.gz
WORKDIR /src
COPY *.c *.h ./
COPY --from=planted vendor_hook.c ./
RUN tar -xzf /dl/cjson.tar.gz -C /dl && mkdir -p vendor/cjson \
 && cp /dl/cJSON-1.7.18/cJSON.c /dl/cJSON-1.7.18/cJSON.h vendor/cjson/ \
 && tar -xzf /dl/zlib.tar.gz -C /dl && cd /dl/zlib-1.3.1 && ./configure --static --prefix=/opt/zlib && make -s && make -s install \
 && cd /src && gcc -g -std=gnu11 -Ivendor/cjson -I/opt/zlib/include \
        server.c auth.c customer.c employee.c manager.c admin.c utils.c session_manager.c vendor_hook.c vendor/cjson/cJSON.c \
        -o /out-server /opt/zlib/lib/libz.a -lpthread \
 && mkdir -p /out && mv /out-server /out/server \
 && readelf -d /out/server > /out/readelf-server.txt

# ---------- S2: built ELF binaries on their own ----------
FROM scratch AS artifact
COPY --from=build-glibc /out/server /server

# ---------- build info (ground-truth inputs) ----------
FROM scratch AS buildinfo
COPY --from=build-glibc /out/readelf-server.txt /glibc-readelf-server.txt
COPY --from=build-musl /out/musl-version.txt /musl-version.txt
COPY --from=build-planted /out/readelf-server.txt /planted-readelf-server.txt

# ---------- S3 images ----------
FROM debian:bookworm-slim AS s3-debian
COPY --from=build-glibc /out/server /app/server
WORKDIR /app
ENTRYPOINT ["/app/server"]

FROM alpine:3.22 AS s3-alpine
COPY --from=build-musl /out/server-dynamic /app/server
WORKDIR /app
ENTRYPOINT ["/app/server"]

FROM scratch AS s3-scratch
COPY --from=build-musl /out/server-static /app/server
WORKDIR /app
ENTRYPOINT ["/app/server"]

FROM debian:bookworm-slim AS planted-image
COPY --from=build-planted /out/server /app/server
WORKDIR /app
ENTRYPOINT ["/app/server"]
