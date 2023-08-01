FROM ubuntu:focal

LABEL org.opencontainers.image.authors "gngpp <gngppz@gmail.com>"
LABEL org.opencontainers.image.source https://github.com/gngpp/opengpt
LABEL name opengpt
LABEL url https://github.com/gngpp/opengpt

RUN DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC
RUN apt update && apt install -y curl gpg systemd tzdata socat
RUN curl https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
RUN echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ focal main' | tee /etc/apt/sources.list.d/cloudflare-client.list
RUN apt update -y && apt install -y cloudflare-warp

COPY boot.sh boot.sh
CMD ["/bin/bash", "/boot.sh"]