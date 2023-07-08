FROM alpine:latest as builder

ARG VERSION
ARG TARGETPLATFORM

RUN if [ "${TARGETPLATFORM}" = "linux/arm64" ]; then \
        echo "aarch64" > arch; \
        echo "musl" > env; \
    elif [ "${TARGETPLATFORM}" = "linux/amd64" ]; then \
        echo "x86_64" > arch; \
        echo "musl" > env; \
    elif [ "${TARGETPLATFORM}" = "linux/arm/v7" ]; then \
        echo "armv7" > arch; \
        echo "musleabi" > env; \
    elif [ "${TARGETPLATFORM}" = "linux/arm/v6" ]; then \
        echo "arm" > arch; \
        echo "musleabi" > env; \
    fi
RUN apk update && apk add wget
RUN wget https://github.com/gngpp/opengpt/releases/download/v${VERSION}/opengpt-${VERSION}-$(cat arch)-unknown-linux-$(cat env).tar.gz
RUN tar -xvf opengpt-${VERSION}-$(cat arch)-unknown-linux-$(cat env).tar.gz

FROM alpine:latest

LABEL org.opencontainers.image.authors "gngpp <gngppz@gmail.com>"
LABEL org.opencontainers.image.source https://github.com/gngpp/opengpt
LABEL name opengpt
LABEL url https://github.com/gngpp/opengpt

ENV LANG=C.UTF-8 DEBIAN_FRONTEND=noninteractive LANG=zh_CN.UTF-8 LANGUAGE=zh_CN.UTF-8 LC_ALL=C

COPY --from=builder /opengpt /bin/opengpt

ENTRYPOINT ["/bin/opengpt"]