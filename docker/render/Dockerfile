FROM gngpp/ninja:latest as builder

FROM gngpp/warp:latest

LABEL org.opencontainers.image.authors "gngpp <gngppz@gmail.com>"
LABEL org.opencontainers.image.source https://github.com/gngpp/ninja
LABEL name ninja
LABEL url https://github.com/gngpp/ninja

ENV LANG=C.UTF-8 DEBIAN_FRONTEND=noninteractive LANG=zh_CN.UTF-8 LANGUAGE=zh_CN.UTF-8 LC_ALL=C

COPY --from=builder /bin/ninja /bin/ninja