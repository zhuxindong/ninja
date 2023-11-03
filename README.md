<br>English | [简体中文](README_zh.md)

[![CI](https://github.com/gngpp/ninja/actions/workflows/CI.yml/badge.svg)](https://github.com/gngpp/ninja/actions/workflows/CI.yml)
[![CI](https://github.com/gngpp/ninja/actions/workflows/Release.yml/badge.svg)](https://github.com/gngpp/ninja/actions/workflows/Release.yml)
 <a target="_blank" href="https://github.com/gngpp/ninja/blob/main/LICENSE">
  <img src="https://img.shields.io/badge/license-GPL_3.0-blue.svg"/>
 </a>
  <a href="https://github.com/gngpp/ninja/releases">
    <img src="https://img.shields.io/github/release/gngpp/ninja.svg?style=flat">
  </a><a href="https://github.com/gngpp/ninja/releases">
    <img src="https://img.shields.io/github/downloads/gngpp/ninja/total?style=flat">
  </a>
  [![](https://img.shields.io/docker/image-size/gngpp/ninja)](https://registry.hub.docker.com/r/gngpp/ninja)
  [![Docker Image](https://img.shields.io/docker/pulls/gngpp/ninja.svg)](https://hub.docker.com/r/gngpp/ninja/)

# ninja

Reverse engineered `ChatGPT` proxy (bypass Cloudflare 403 Access Denied)

### Features

- API key acquisition
- Email/password account authentication (Google/Microsoft third-party login not supported)
-Supports obtaining RefreshToken
- `ChatGPT-API`/`OpenAI-API`/`ChatGPT-to-API` Http API proxy (for third-party client access)
- Support IP proxy pool (support using Ipv6 subnet as proxy pool)
- ChatGPT WebUI
- Very small memory footprint

> Limitations: This cannot bypass OpenAI's outright IP ban

### ArkoseLabs

Sending `GPT4/GPT-3.5 (already grayscale)/Creating API-Key` dialog requires sending `Arkose Token` as a parameter. There are only two supported solutions for the time being.

1) Use HAR

   - Supports HAR feature pooling, multiple HARs can be uploaded at the same time, and the usage strategy is random request.
   > The `ChatGPT` official website sends a `GPT4` session message, and the browser `F12` downloads the `https://tcr9i.chat.openai.com/fc/gt2/public_key/35536E1E-65B4-4D96-9D97-6ADB7EFF8147` interface. HAR log file, use the startup parameter `--arkose-gpt4-har-dir` to specify the HAR directory path to use (if you do not specify a path, use the default path `~/.chat4.openai.com.har`, you can directly upload and update HAR ), the same method applies to `GPT3.5` and other types. Supports WebUI to upload and update HAR, request path: `/har/upload`, optional upload authentication parameter: `--arkose-har-upload-key`. and

2) Use [YesCaptcha](https://yescaptcha.com/i/1Cc5i4) / [CapSolver](https://dashboard.capsolver.com/passport/register?inviteCode=y7CtB_a-3X6d)
    > The platform performs verification code parsing, start the parameter `--arkose-solver` to select the platform (use `YesCaptcha` by default), `--arkose-solver-key` fill in `Client Key`

- Both solutions are used, the priority is: `HAR` > `YesCaptcha` / `CapSolver`
- `YesCaptcha` / `CapSolver` is recommended to be used with HAR. When the verification code is generated, the parser is called for processing. After verification, HAR is more durable.

> Currently OpenAI has updated `Login` which requires verification of `Arkose Token`. The solution is the same as GPT4. Fill in the startup parameters and specify the HAR file `--arkose-auth-har-dir`. If you don't want to upload, you can log in through the browser code, which is not required. To create an API-Key, you need to upload the HAR feature file related to the Platform. The acquisition method is the same as above.

### Http Server

#### Public interface, `*` represents any `URL` suffix

- ChatGPT-API
  - <https://host:port/public-api/*>
  - <https://host:port/backend-api/*>
  
- OpenAI-API
  - <https://host:port/v1/*>

- Platform-API
  - <https://host:port/dashboard/*>
- ChatGPT-To-API
  - <https://host:port/to/v1/chat/completions>
  > About using `ChatGPT` to `API`, use `AceessToken` directly as `API Key`, interface path: `/to/v1/chat/completions`

#### API documentation

- Platfrom API [doc](https://platform.openai.com/docs/api-reference)
- Backend API [doc](doc/rest.http)

#### Basic services

- ChatGPT WebUI
- Expose `ChatGPT-API`/`OpenAI-API` proxies
- `API` prefix is consistent with the official one
- `ChatGPT` to `API`
- Can access third-party clients
- Can access IP proxy pool to improve concurrency
- Supports obtaining RefreshToken
- Support file feature pooling in HAR format

#### Parameter Description

- `--level`, environment variable `LOG`, log level: default info
- `--bind`, environment variable `BIND`, service listening address: default 0.0.0.0:7999,
- `--tls-cert`, environment variable `TLS_CERT`', TLS certificate public key. Supported format: EC/PKCS8/RSA
- `--tls-key`, environment variable `TLS_KEY`, TLS certificate private key
- `--proxies`, Proxy, supports proxy pool, multiple proxies are separated by `,`, format: protocol://user:pass@ip:port, if the local IP is banned, you need to turn off the use of direct IP when using the proxy pool, `--disable-direct` turns off direct connection, otherwise your banned local IP will be used according to load balancing
- `--workers`, worker threads: default 1
- `--disable-webui`, if you don’t want to use the default built-in WebUI, use this parameter to turn it off

[...](https://github.com/gngpp/ninja/blob/main/README.md#command-manual)

#### RefreshToken

`About the method of obtaining Refresh Token`, use the `ChatGPT App` login method of the `Apple` platform. The principle is to use the built-in MITM agent. When the `Apple device` is connected to the agent, you can log in to the `Apple platform` to obtain `RefreshToken`. It is only suitable for small quantities or personal use `(large quantities will seal the device, use with caution)`. For detailed usage, please see the startup parameter description.

### Install

- #### Ubuntu(Other Linux)

Making [Releases](https://github.com/gngpp/ninja/releases/latest) has a precompiled deb package, binaries, in Ubuntu, for example:

```shell
wget https://github.com/gngpp/ninja/releases/download/v0.7.4/ninja-0.7.4-x86_64-unknown-linux-musl.deb
dpkg -i ninja-0.7.4-x86_64-unknown-linux-musl.deb
ninja run
```

- #### OpenWrt

There are pre-compiled ipk files in GitHub [Releases](https://github.com/gngpp/ninja/releases/latest), which currently provide versions of aarch64/x86_64 and other architectures. After downloading, use opkg to install, and use nanopi r4s as example:

```shell
wget https://github.com/gngpp/ninja/releases/download/v0.7.4/ninja_0.7.4_aarch64_generic.ipk
wget https://github.com/gngpp/ninja/releases/download/v0.7.4/luci-app-ninja_1.1.4-1_all.ipk
wget https://github.com/gngpp/ninja/releases/download/v0.7.4/luci-i18n-ninja-zh-cn_1.1.4-1_all.ipk

opkg install ninja_0.7.4_aarch64_generic.ipk
opkg install luci-app-ninja_1.1.4-1_all.ipk
opkg install luci-i18n-ninja-zh-cn_1.1.4-1_all.ipk
```

- #### Docker

```shell
docker run --rm -it -p 7999:7999 --name=ninja \
  -e WORKERS=1 \
  -e LOG=info \
  gngpp/ninja:latest run
```

- Docker Compose

> `CloudFlare Warp` is not supported in your region (China), please delete it, or if your `VPS` IP can be directly connected to `OpenAI`, you can also delete it

```yaml
version: '3'

services:
  ninja:
    image: ghcr.io/gngpp/ninja:latest
    container_name: ninja
    restart: unless-stopped
    environment:
      - TZ=Asia/Shanghai
      - PROXIES=socks5://warp:10000
    command: run
    ports:
      - "8080:7999"
    depends_on:
      - warp

  warp:
    container_name: warp
    image: ghcr.io/gngpp/warp:latest
    restart: unless-stopped

  watchtower:
    container_name: watchtower
    image: containrrr/watchtower
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    command: --interval 3600 --cleanup
    restart: unless-stopped

```

### Command Manual

```shell
$ ninja --help
Reverse engineered ChatGPT proxy

Usage: ninja [COMMAND]

Commands:
  run      Run the HTTP server
  stop     Stop the HTTP server daemon
  start    Start the HTTP server daemon
  restart  Restart the HTTP server daemon
  status   Status of the Http server daemon process
  log      Show the Http server daemon log
  genca    Generate MITM CA certificate
  gt       Generate config template file (toml format file)
  update   Update the application
  help     Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version

$ ninja run --help
Run the HTTP server

Usage: ninja run [OPTIONS]

Options:
  -L, --level <LEVEL>
          Log level (info/debug/warn/trace/error) [env: LOG=] [default: info]
  -C, --config <CONFIG>
          Configuration file path (toml format file) [env: CONFIG=]
  -b, --bind <BIND>
          Server bind address [env: BIND=] [default: 0.0.0.0:7999]
  -W, --workers <WORKERS>
          Server worker-pool size (Recommended number of CPU cores) [default: 1]
      --concurrent-limit <CONCURRENT_LIMIT>
          Enforces a limit on the concurrent number of requests the underlying [default: 1024]
  -x, --proxies <PROXIES>
          Server proxies pool, Example: protocol://user:pass@ip:port [env: PROXIES=]
  -i, --interface <INTERFACE>
          Bind address for outgoing connections (or IPv6 subnet fallback to Ipv4) [env: INTERFACE=]
  -I, --ipv6-subnet <IPV6_SUBNET>
          IPv6 subnet, Example: 2001:19f0:6001:48e4::/64 [env: IPV6_SUBNET=]
      --disable-direct
          Disable direct connection [env: DISABLE_DIRECT=]
      --cookie-store
          Enabled Cookie Store [env: COOKIE_STORE=]
      --timeout <TIMEOUT>
          Client timeout (seconds) [default: 360]
      --connect-timeout <CONNECT_TIMEOUT>
          Client connect timeout (seconds) [default: 20]
      --tcp-keepalive <TCP_KEEPALIVE>
          TCP keepalive (seconds) [default: 60]
      --pool-idle-timeout <POOL_IDLE_TIMEOUT>
          Set an optional timeout for idle sockets being kept-alive [default: 90]
      --tls-cert <TLS_CERT>
          TLS certificate file path [env: TLS_CERT=]
      --tls-key <TLS_KEY>
          TLS private key file path (EC/PKCS8/RSA) [env: TLS_KEY=]
  -A, --auth-key <AUTH_KEY>
          Login Authentication Key [env: AUTH_KEY=]
      --api-prefix <API_PREFIX>
          WebUI api prefix [env: API_PREFIX=]
  -D, --disable-webui
          Disable WebUI [env: DISABLE_WEBUI=]
      --cf-site-key <CF_SITE_KEY>
          Cloudflare turnstile captcha site key [env: CF_SECRET_KEY=]
      --cf-secret-key <CF_SECRET_KEY>
          Cloudflare turnstile captcha secret key [env: CF_SITE_KEY=]
      --arkose-endpoint <ARKOSE_ENDPOINT>
          Arkose endpoint, Example: https://client-api.arkoselabs.com
      --arkose-gpt3-har-dir <ARKOSE_GPT3_HAR_DIR>
          About the browser HAR directory path requested by ChatGPT GPT-3.5 ArkoseLabs
      --arkose-gpt4-har-dir <ARKOSE_GPT4_HAR_DIR>
          About the browser HAR directory path requested by ChatGPT GPT-4 ArkoseLabs
      --arkose-auth-har-dir <ARKOSE_AUTH_HAR_DIR>
          About the browser HAR directory path requested by Auth ArkoseLabs
      --arkose-platform-har-dir <ARKOSE_PLATFORM_HAR_DIR>
          About the browser HAR directory path requested by Platform ArkoseLabs
  -K, --arkose-har-upload-key <ARKOSE_HAR_UPLOAD_KEY>
          HAR file upload authenticate key
  -s, --arkose-solver <ARKOSE_SOLVER>
          About ArkoseLabs solver platform [default: yescaptcha]
  -k, --arkose-solver-key <ARKOSE_SOLVER_KEY>
          About the solver client key by ArkoseLabs
  -T, --tb-enable
          Enable token bucket flow limitation
      --tb-store-strategy <TB_STORE_STRATEGY>
          Token bucket store strategy (mem/redis) [default: mem]
      --tb-redis-url <TB_REDIS_URL>
          Token bucket redis connection url [default: redis://127.0.0.1:6379]
      --tb-capacity <TB_CAPACITY>
          Token bucket capacity [default: 60]
      --tb-fill-rate <TB_FILL_RATE>
          Token bucket fill rate [default: 1]
      --tb-expired <TB_EXPIRED>
          Token bucket expired (seconds) [default: 86400]
  -B, --pbind <PBIND>
          Preauth MITM server bind address [env: PREAUTH_BIND=]
  -X, --pupstream <PUPSTREAM>
          Preauth MITM server upstream proxy, Only support http protocol [env: PREAUTH_UPSTREAM=]
      --pcert <PCERT>
          Preauth MITM server CA certificate file path [default: ca/cert.crt]
      --pkey <PKEY>
          Preauth MITM server CA private key file path [default: ca/key.pem]
  -h, --help
          Print help
```

### Platform Support

- Linux
  - `x86_64-unknown-linux-musl`
  - `aarch64-unknown-linux-musl`
  - `armv7-unknown-linux-musleabi`
  - `armv7-unknown-linux-musleabihf`
  - `arm-unknown-linux-musleabi`
  - `arm-unknown-linux-musleabihf`
  - `armv5te-unknown-linux-musleabi`
- Windows
  - `x86_64-pc-windows-msvc`
- MacOS
  - `x86_64-apple-darwin`
  - `aarch64-apple-darwin`

### Compile

- Linux compile, Ubuntu machine for example:

```shell
git clone https://github.com/gngpp/ninja.git && cd ninja
cargo build --release
```

- OpenWrt Compile

```shell
cd package
svn co https://github.com/gngpp/ninja/trunk/openwrt
cd -
make menuconfig # choose LUCI->Applications->luci-app-ninja  
make V=s
```

### Instructions

- Open source projects can be modified, but please keep the original author information to avoid losing technical support.
- Project is standing on the shoulders of other giants, thanks!
- Submit an issue if there are errors, bugs, etc., and I will fix them.

### Preview

![img0](./doc/img/img0.png)
![img1](./doc/img/img1.png)
