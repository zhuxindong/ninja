ARG BASE_IMAGE

FROM $BASE_IMAGE

ARG TARGETPLATFORM
ARG BASE_IMAGE

WORKDIR /home/rust/src

LABEL org.opencontainers.image.authors "gngpp <gngppz@gmail.com>"
LABEL org.opencontainers.image.source https://github.com/gngpp/opengpt

RUN mkdir -p /root/.cargo/registry
RUN mkdir -p /root/.cargo/git

RUN if [ "${BASE_IMAGE}" = "ghcr.io/messense/cargo-xwin:latest" ]; then \
        apt update -y && apt install -y nasm; \
        mkdir /usr/local/cargo/git /usr/local/cargo/registry; \
        ln -s /usr/local/cargo/git /root/.cargo/git; \
        ln -s /usr/local/cargo/registry /root/.cargo/registry; \
    else \
        if [ "${TARGETPLATFORM}" = "linux/arm64" ]; then \
            apt update -y && apt install -y gcc-aarch64-linux-gnu; \
        elif [ "${TARGETPLATFORM}" = "linux/amd64" ]; then \
            apt update -y && apt install -y gcc-multilib; \
        fi \
    fi
