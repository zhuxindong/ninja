[![CI](https://github.com/gngpp/opengpt/actions/workflows/CI.yml/badge.svg)](https://github.com/gngpp/opengpt/actions/workflows/CI.yml)
<a href="/LICENSE">
    <img src="https://img.shields.io/github/license/gngpp/opengpt?style=flat">
  </a>
  <a href="https://github.com/gngpp/opengpt/releases">
    <img src="https://img.shields.io/github/release/gngpp/opengpt.svg?style=flat">
  </a><a href="hhttps://github.com/gngpp/opengpt/releases">
    <img src="https://img.shields.io/github/downloads/gngpp/opengpt/total?style=flat&?">
  </a>
  [![Docker Image](https://img.shields.io/docker/pulls/gngpp/opengpt.svg)](https://hub.docker.com/r/gngpp/opengpt/)

<br>English | [简体中文](README.md)

# opengpt

Not just an unofficial ChatGPT proxy (bypass Cloudflare 403 Access Denied)

- API key acquisition, email/password account authentication (because the author does not have an account, Google/Microsoft third-party login is not currently supported)
- Http API proxy (for other clients to access)
- Authentic ChatGPT WebUI

> Limitations: This cannot bypass OpenAI's outright IP ban

### Compile

> Ubuntu machine for example:

```shell

sudo apt update -y && sudo apt install rename

# Native compilation
git clone https://github.com/gngpp/opengpt.git && cd opengpt
./build.sh

# Cross-platform compilation, relying on docker (if you can solve cross-platform compilation dependencies on your own)
./corss-build.sh
```

### Ubuntu(Other Linux)

Making [Releases](https://github.com/gngpp/opengpt/releases/latest) has a precompiled deb package, binaries, in Ubuntu, for example:

```shell
wget https://github.com/gngpp/opengpt/releases/download/v0.1.1/opengpt-0.1.1-x86_64-unknown-linux-musl.deb

dpkg -i opengpt-0.1.1-x86_64-unknown-linux-musl.deb

opengpt serve
```

### Docker

```shell
docker run --rm -it -p 7999:7999 --hostname=opengpt \
  -e OPENGPT_TLS_CERT=/path/to/cert \
  -e OPENGPT_TLS_KEY=/path/to/key \
  gngpp/opengpt:latest opengpt serve
```

### Command Line(dev)

### Http Server

- Comes with original ChatGPT WebUI
- Support unofficial/official API, forward to proxy
- The API prefix is the same as the official one, only the host name is changed

- Parameter Description
  - Platfrom API [doc](https://platform.openai.com/docs/api-reference)
  - Backend API [doc](doc/rest.http)

- Parameter Description
- `--host`, environment variable `OPENGPT_HOST`, service listening address: default 0.0.0.0,
- `--port`, environment variable `OPENGPT_PORT`, listening port: default 7999
- `--workers`, environment variable `OPENGPT_WORKERS`, number of service threads: default 1
- `--level`, environment variable `OPENGPT_LOG_LEVEL`, log level: default info
- `-- TLs-cert`, environment variable `OPENGPT_TLS_CERT`', TLS certificate public key. Supported format: EC/PKCS8/RSA
- `-- TLs-key`, environment variable `OPENGPT_TLS_KEY`, TLS certificate private key
- `--proxy`, environment variable `OPENGPT_PROXY`, proxy, format: protocol://user:pass@ip:port

```shell
$ opengpt serve --help
Start the http server

Usage: opengpt serve [OPTIONS]

Options:
  -H, --host <HOST>
          Server Listen host [env: OPENGPT_HOST=] [default: 0.0.0.0]
  -P, --port <PORT>
          Server Listen port [env: OPENGPT_PORT=] [default: 7999]
  -W, --workers <WORKERS>
          Server worker-pool size (Recommended number of CPU cores) [env: OPENGPT_WORKERS=] [default: 1]
  -L, --level <LEVEL>
          Log level (info/debug/warn/trace/error) [env: OPENGPT_LOG_LEVEL=] [default: info]
      --proxy <PROXY>
          Server proxy, example: protocol://user:pass@ip:port [env: OPENGPT_PROXY=]
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
  -h, --help
          Print help
```

### Reference

- <https://github.com/tjardoo/openai-client>
- <https://github.com/jpopesculian/reqwest-eventsource>
