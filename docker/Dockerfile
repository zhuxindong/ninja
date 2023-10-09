FROM alpine:3.16.6 as builder

ARG VERSION
ARG TARGETPLATFORM

RUN if [ "${TARGETPLATFORM}" = "linux/arm64" ]; then \
        echo "aarch64" > arch; \
    elif [ "${TARGETPLATFORM}" = "linux/amd64" ]; then \
        echo "x86_64" > arch; \
    fi
RUN apk update && apk add wget
RUN wget https://github.com/zhuxindong/ninja/releases/download/v${VERSION}/ninja-${VERSION}_$(cat arch).tar.gz
RUN tar -xvf ninja-${VERSION}_$(cat arch).tar.gz

FROM alpine:3.16.6

LABEL org.opencontainers.image.authors "zhuxindong <zhuxindong1995@gmail.com>"
LABEL org.opencontainers.image.source https://github.com/zhuxindong/ninja
LABEL name ninja
LABEL url https://github.com/zhuxindong/ninja

ENV LANG=C.UTF-8 DEBIAN_FRONTEND=noninteractive LANG=zh_CN.UTF-8 LANGUAGE=zh_CN.UTF-8 LC_ALL=C

COPY --from=builder /ninja /bin/ninja

ENTRYPOINT ["/bin/ninja"]