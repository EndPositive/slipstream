FROM debian:bookworm-slim AS builder

WORKDIR /usr/src/app

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y \
    python3-pip \
    cmake \
    git \
    pkg-config \
    libssl-dev \
    ninja-build \
    gcc g++ && \
    pip3 install --user --break-system-packages meson

COPY . .

RUN /root/.local/bin/meson setup \
    -Db_lto=true \
    --buildtype=release \
    --warnlevel=0 \
    -Ddefault_library=static \
    meson-build-release && \
    ninja -C meson-build-release && \
    cp /usr/src/app/meson-build-release/slipstream-client . && \
    cp /usr/src/app/meson-build-release/slipstream-server .

FROM gcr.io/distroless/cc-debian12 AS runtime

WORKDIR /usr/src/app

COPY --from=builder /lib/x86_64-linux-gnu/libgcc_s.so.1 /lib/x86_64-linux-gnu/

COPY ./certs/ ./certs/

ENV PATH=/usr/src/app/:$PATH

LABEL org.opencontainers.image.source=https://github.com/EndPositive/slipstream

FROM runtime AS client

COPY --from=builder --chmod=755 /usr/src/app/slipstream-client .

ENTRYPOINT ["/usr/src/app/slipstream-client"]

FROM runtime AS server

COPY --from=builder --chmod=755 /usr/src/app/slipstream-server .

ENTRYPOINT ["/usr/src/app/slipstream-server"]
