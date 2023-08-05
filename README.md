<br>English | [简体中文](README_zh.md)

[![CI](https://github.com/gngpp/opengpt/actions/workflows/CI.yml/badge.svg)](https://github.com/gngpp/opengpt/actions/workflows/CI.yml)
[![CI](https://github.com/gngpp/opengpt/actions/workflows/Release.yml/badge.svg)](https://github.com/gngpp/opengpt/actions/workflows/Release.yml)
	<a target="_blank" href="https://github.com/gngpp/vdns/blob/main/LICENSE">
		<img src="https://img.shields.io/badge/license-MIT-blue.svg"/>
	</a>
  <a href="https://github.com/gngpp/opengpt/releases">
    <img src="https://img.shields.io/github/release/gngpp/opengpt.svg?style=flat">
  </a><a href="https://github.com/gngpp/opengpt/releases">
    <img src="https://img.shields.io/github/downloads/gngpp/opengpt/total?style=flat">
  </a>
  [![](https://img.shields.io/docker/image-size/gngpp/opengpt)](https://registry.hub.docker.com/r/gngpp/opengpt)
  [![Docker Image](https://img.shields.io/docker/pulls/gngpp/opengpt.svg)](https://hub.docker.com/r/gngpp/opengpt/)

# opengpt

A reverse engineered unofficial `ChatGPT` proxy (bypass Cloudflare 403 Access Denied)

###  Features

- API key acquisition
- Email/password account authentication (Google/Microsoft third-party login is not supported for now because the author does not have an account)
- Unofficial/Official Http API proxy (for third-party client access)
- The original ChatGPT WebUI
- Minimal memory usage

> Limitations: This cannot bypass OpenAI's outright IP ban

### Platform Support

- Linux musl current supports
  - `x86_64-unknown-linux-musl`
  - `aarch64-unknown-linux-musl`
  - `armv7-unknown-linux-musleabi`
  - `armv7-unknown-linux-musleabihf`
  - `arm-unknown-linux-musleabi`
  - `arm-unknown-linux-musleabihf`
  - `armv5te-unknown-linux-musleabi`
- Windows current supports
  - `x86_64-pc-windows-msvc`
- MacOS current supports
  - `x86_64-apple-darwin`
  - `aarch64-apple-darwin`

### Install

  > #### Ubuntu(Other Linux)

Making [Releases](https://github.com/gngpp/opengpt/releases/latest) has a precompiled deb package, binaries, in Ubuntu, for example:

```shell
wget https://github.com/gngpp/opengpt/releases/download/v0.3.1/opengpt-0.3.1-x86_64-unknown-linux-musl.deb
dpkg -i opengpt-0.3.1-x86_64-unknown-linux-musl.deb
opengpt serve run
```

> #### Docker

```shell
docker run --rm -it -p 7999:7999 --hostname=opengpt \
  -e OPENGPT_WORKERS=1 \
  -e OPENGPT_LOG_LEVEL=info \
  gngpp/opengpt:latest serve run
```

> docker-compose

```yaml
version: '3'

services:
  opengpt:
    image: ghcr.io/gngpp/opengpt:latest
    container_name: opengpt
    restart: unless-stopped
    environment:
      - TZ=Asia/Shanghai
      - OPENGPT_PROXY=socks5://cloudflare-warp:10000
      # - OPENGPT_CONFIG=/opengpt-serve.toml
      # - OPENGPT_PORT=8080
      # - OPENGPT_HOST=0.0.0.0
      # - OPENGPT_WORKERS=10
      # - OPENGPT_TIMEOUT=360
      # - OPENGPT_CONNECT_TIMEOUT=60
      # - OPENGPT_TCP_KEEPALIVE=60
      # - OPENGPT_TLS_CERT=
      # - OPENGPT_TLS_KEY=
      # - OPENGPT_UI_API_PREFIX=
      # - OPENGPT_SIGNATURE=
      # - OPENGPT_TB_ENABLE=
      # - OPENGPT_TB_STORE_STRATEGY
      # - OPENGPT_TB_REDIS_URL=
      # - OPENGPT_TB_CAPACITY=
      # - OPENGPT_TB_FILL_RATE=
      # - OPENGPT_TB_EXPIRED=
      # - OPENGPT_CF_SITE_KEY=
      # - OPENGPT_CF_SECRET_KEY=
    volumes:
      # - ${PWD}/ssl:/etc
      - ${PWD}/opengpt-serve.toml:/opengpt-serve.toml
    command: serve run
    ports:
      - "8080:7999"
    depends_on:
      - cloudflare-warp

  cloudflare-warp:
    container_name: cloudflare-warp
    image: ghcr.io/gngpp/cloudflare-warp:latest
    restart: unless-stopped

  watchtower:
    container_name: watchtower
    image: containrrr/watchtower
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    command: --interval 3600 --cleanup
    restart: unless-stopped

```

> #### OpenWrt

There are pre-compiled ipk files in GitHub [Releases](https://github.com/gngpp/opengpt/releases/latest), which currently provide versions of aarch64/x86_64 and other architectures. After downloading, use opkg to install, and use nanopi r4s as example:

```shell
wget https://github.com/gngpp/opengpt/releases/download/v0.3.1/opengpt_0.3.1_aarch64_generic.ipk
wget https://github.com/gngpp/opengpt/releases/download/v0.3.1/luci-app-opengpt_1.0.2-1_all.ipk
wget https://github.com/gngpp/opengpt/releases/download/v0.3.1/luci-i18n-opengpt-zh-cn_1.0.2-1_all.ipk

opkg install opengpt_0.3.1_aarch64_generic.ipk
opkg install luci-app-opengpt_1.0.2-1_all.ipk
opkg install luci-i18n-opengpt-zh-cn_1.0.2-1_all.ipk
```

### Command Line(dev)

### Http Server

- Authentic ChatGPT WebUI
- Support unofficial/official API proxy
- The API prefix is consistent with the official
- Accessible to third-party clients
- Access to IP proxy pool to increase concurrency
- API documentation

- Parameter Description
  - Platfrom API [doc](https://platform.openai.com/docs/api-reference)
  - Backend API [doc](doc/rest.http)

- Parameter Description
  - `--level`, environment variable `OPENGPT_LOG_LEVEL`, log level: default info
  - `--host`, environment variable `OPENGPT_HOST`, service listening address: default 0.0.0.0,
  - `--port`, environment variable `OPENGPT_PORT`, listening port: default 7999
  - `--workers`, environment variable `OPENGPT_WORKERS`, worker threads: default 1
  - `--tls-cert`, environment variable `OPENGPT_TLS_CERT`', TLS certificate public key. Supported format: EC/PKCS8/RSA
  - `--tls-key`, environment variable `OPENGPT_TLS_KEY`, TLS certificate private key
  - `--proxies`, environment variable `OPENGPT_PROXY`, proxies，support multiple proxy pools, format: protocol://user:pass@ip:port

```shell
$ opengpt serve --help
Start the http server

Usage: opengpt serve run [OPTIONS]

Options:
  -H, --host <HOST>
          Server Listen host [env: OPENGPT_HOST=] [default: 0.0.0.0]
  -P, --port <PORT>
          Server Listen port [env: OPENGPT_PORT=] [default: 7999]
  -W, --workers <WORKERS>
          Server worker-pool size (Recommended number of CPU cores) [env: OPENGPT_WORKERS=] [default: 1]
  -L, --level <LEVEL>
          Log level (info/debug/warn/trace/error) [env: OPENGPT_LOG_LEVEL=] [default: info]
      --proxies <PROXIES>
          Server proxies pool, example: protocol://user:pass@ip:port [env: OPENGPT_PROXY=]
      --tcp-keepalive <TCP_KEEPALIVE>
          TCP keepalive (second) [env: OPENGPT_TCP_KEEPALIVE=] [default: 5]
      --tls-cert <TLS_CERT>
          TLS certificate file path [env: OPENGPT_TLS_CERT=]
      --tls-key <TLS_KEY>
          TLS private key file path (EC/PKCS8/RSA) [env: OPENGPT_TLS_KEY=]
  -S, --sign-secret-key <SIGN_SECRET_KEY>
          Enable url signature (signature secret key) [env: OPENGPT_SIGNATURE=]
  -T, --tb-enable
          Enable token bucket flow limitation [env: OPENGPT_TB_ENABLE=]
      --tb-store-strategy <TB_STORE_STRATEGY>
          Token bucket store strategy (mem/redis) [env: OPENGPT_TB_STORE_STRATEGY=] [default: mem]
      --tb-capacity <TB_CAPACITY>
          Token bucket capacity [env: OPENGPT_TB_CAPACITY=] [default: 60]
      --tb-fill-rate <TB_FILL_RATE>
          Token bucket fill rate [env: OPENGPT_TB_FILL_RATE=] [default: 1]
      --tb-expired <TB_EXPIRED>
          Token bucket expired (second) [env: OPENGPT_TB_EXPIRED=] [default: 86400]
      --cf-site-key <CF_SITE_KEY>
          Cloudflare turnstile captcha site key [env: OPENGPT_CF_SITE_KEY=]
      --cf-secret-key <CF_SECRET_KEY>
          Cloudflare turnstile captcha secret key [env: OPENGPT_CF_SECRET_KEY=]
  -D, --disable-webui
          Disable WebUI [env: OPENGPT_DISABLE_WEBUI=]
  -h, --help
          Print help
```

### Compile

- Linux compile, Ubuntu machine for example:

```shell

sudo apt update -y && sudo apt install rename

# Native compilation
git clone https://github.com/gngpp/opengpt.git && cd opengpt
./build.sh

# Cross-platform compilation, relying on docker (if you can solve cross-platform compilation dependencies on your own)
./build_cross.sh # Default using docker build linux/windows platform 
os=macos ./build_cross.sh # The MacOS platform is built on MacOS by default

# Compile a single platform binary, take aarch64-unknown-linux-musl as an example: 
docker run --rm -it \
  -v $(pwd):/home/rust/src \
  -v $HOME/.cargo/registry:/root/.cargo/registry \
  -v $HOME/.cargo/git:/root/.cargo/git \
  ghcr.io/gngpp/opengpt-builder:x86_64-unknown-linux-musl \
  cargo build --release
```

- OpenWrt compile

```shell
cd package
svn co https://github.com/gngpp/opengpt/trunk/openwrt
cd -
make menuconfig # choose LUCI->Applications->luci-app-opengpt  
make V=s
```

### Preview

![img0](./doc/img/img0.png)
![img1](./doc/img/img1.png)
![img2](./doc/img/img2.png)
