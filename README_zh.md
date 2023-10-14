<br>简体中文 | [English](README.md)

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

逆向工程的 `ChatGPT` 代理（绕过 Cloudflare 403 Access Denied）

### 功能

- API密钥获取
- 电子邮件/密码帐户认证 (暂时不支持Google/Microsoft第三方登录)
- `Unofficial`/`Official`/`ChatGPT-to-API` Http API 代理 (供第三方客户端接入)
- 支持IP代理池
- 极少的内存占用
- ChatGPT WebUI

> 局限性: 无法绕过 OpenAI 的彻底 IP 禁令

### 绕过IP限制

这里`IP限制`是指`OpenAI`对`单IP`请求速率限制，你需要了解什么是`puid`，默认请求models接口返回`puid cookie`。
另外，`GPT-4`会话必须带上`puid`发送，在使用第三方客户端发送`GPT-4`会话时可能不会保存也不会获取`puid`，你需要在服务端处理:

- 使用启动参数`--puid-user`，设置`Account Plus`账号来获取`puid`，并且会定时更新

### ArkoseLabs

发送`GPT4`对话需要`Arkose Token`作为参数发送，支持的解决方案暂时只有三种

1) 获取`Arkose Token`的端点，不管你用什么方式，使用 `--arkose-token-endpoint` 指定端点获取token，支持的`JSON`格式，一般按照社区的格式：`{"token":"xxxxxx"}`

2) 使用HAR，`ChatGPT` 官网发送一次 `GPT4` 会话消息，浏览器 `F12` 下载 `https://tcr9i.chat.openai.com/fc/gt2/public_key/35536E1E-65B4-4D96-9D97-6ADB7EFF8147` 接口的HAR日志记录文件，使用启动参数 `--arkose-chat-har-file` 指定HAR文件路径使用（不指定路径则使用默认路径`~/.chat.openai.com.har`，可直接上传更新HAR），支持上传更新HAR，请求路径:`/har/upload`，可选上传身份验证参数:`--arkose-har-upload-key`

3) 使用[YesCaptcha](https://yescaptcha.com/i/1Cc5i4) / [CapSolver](https://dashboard.capsolver.com/passport/register?inviteCode=y7CtB_a-3X6d)平台进行验证码解析，启动参数`--arkose-solver`选择平台（默认使用`YesCaptcha`），`--arkose-solver-key` 填写`Client Key`

- 三种方案都使用，优先级是：`HAR` > `YesCaptcha` / `CapSolver` > `Arkose Token 端点`
- `YesCaptcha` / `CapSolver`推荐搭配HAR使用，出验证码则调用解析器处理，验证后HAR使用更持久

> 目前OpenAI已经更新登录需要验证`Arkose Token`，解决方式同GPT4，填写启动参数指定HAR文件`--arkose-auth-har-file`。不想上传，可以通过浏览器打码登录，非必需。

### Command Line(dev)

### Http 服务

#### 公开接口, `*` 表示任意`URL`后缀

- backend-api, <https://host:port/backend-api/*>
- public-api, <https://host:port/public-api/*>
- platform-api, <https://host:port/v1/*>
- dashboard-api, <https://host:port/dashboard/*>
- chatgpt-to-api, <https://host:port/to/v1/chat/completions>

#### API文档

- Platfrom API [doc](https://platform.openai.com/docs/api-reference)
- Backend API [doc](doc/rest.http)

> 关于关于`ChatGPT`转`API`使用，直接拿`AceessToken`当`API Key`使用，接口路径：`/to/v1/chat/completions`

#### 基本服务

- 原汁原味ChatGPT WebUI
- 公开`非官方`/`官方API`代理
- `API`前缀与官方一致
- `ChatGPT` 转 `API`
- 可接入第三方客户端
- 可接入IP代理池，提高并发

- 参数说明
  - `--level`，环境变量 `LOG`，日志级别: 默认info
  - `--host`，环境变量 `HOST`， 服务监听地址: 默认0.0.0.0，
  - `--port`，环境变量 `PORT`， 监听端口: 默认7999
  - `--tls-cert`，环境变量 `TLS_CERT`，TLS证书公钥，支持格式: EC/PKCS8/RSA
  - `--tls-key`，环境变量 `TLS_KEY`，TLS证书私钥
  - `--proxies`，代理，支持代理池，多个代理使用`,`隔开，格式: protocol://user:pass@ip:port，如果本地IP被Ban，使用代理池时需要关闭直连IP使用，`--disable-direct`关闭直连，否则会根据负载均衡使用你被Ban的本地IP
  - `--workers`， 工作线程: 默认1
  - `--disable-webui`, 如果不想使用默认自带的WebUI，使用此参数关闭

[...](https://github.com/gngpp/ninja/blob/main/README_zh.md#%E5%91%BD%E4%BB%A4%E6%89%8B%E5%86%8C)

### 安装

- #### Ubuntu(Other Linux)

  GitHub [Releases](https://github.com/gngpp/ninja/releases/latest) 中有预编译的 deb包，二进制文件，以Ubuntu为例：

```shell
wget https://github.com/gngpp/ninja/releases/download/v0.6.7/ninja-0.6.7-x86_64-unknown-linux-musl.deb
dpkg -i ninja-0.6.7-x86_64-unknown-linux-musl.deb
ninja serve run
```

- #### OpenWrt

GitHub [Releases](https://github.com/gngpp/ninja/releases/latest) 中有预编译的 ipk 文件， 目前提供了 aarch64/x86_64 等架构的版本，下载后使用 opkg 安装，以 nanopi r4s 为例：

```shell
wget https://github.com/gngpp/ninja/releases/download/v0.6.7/ninja_0.6.7_aarch64_generic.ipk
wget https://github.com/gngpp/ninja/releases/download/v0.6.7/luci-app-ninja_1.1.3-1_all.ipk
wget https://github.com/gngpp/ninja/releases/download/v0.6.7/luci-i18n-ninja-zh-cn_1.1.3-1_all.ipk

opkg install ninja_0.6.7_aarch64_generic.ipk
opkg install luci-app-ninja_1.1.3-1_all.ipk
opkg install luci-i18n-ninja-zh-cn_1.1.3-1_all.ipk
```

- #### Docker

```shell
docker run --rm -it -p 7999:7999 --name=ninja \
  -e WORKERS=1 \
  -e LOG=info \
  gngpp/ninja:latest serve run
```

- Docker Compose

> `CloudFlare Warp`你的地区不支持（China）请把它删掉，或者你的`VPS`IP可直连`OpenAI`，那么也可以删掉

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
      # - CONFIG=/serve.toml
      # - PORT=8080
      # - HOST=0.0.0.0
      # - TLS_CERT=
      # - TLS_KEY=
    # volumes:
      # - ${PWD}/ssl:/etc
      # - ${PWD}/serve.toml:/serve.toml
    command: serve run
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

### 命令手册

```shell
$ ninja serve --help
Start the http server

Usage: ninja serve run [OPTIONS]

Options:
  -C, --config <CONFIG>
          Configuration file path (toml format file) [env: CONFIG=]
  -H, --host <HOST>
          Server Listen host [env: HOST=] [default: 0.0.0.0]
  -L, --level <LEVEL>
          Log level (info/debug/warn/trace/error) [env: LOG=] [default: info]
  -P, --port <PORT>
          Server Listen port [env: PORT=] [default: 7999]
  -W, --workers <WORKERS>
          Server worker-pool size (Recommended number of CPU cores) [default: 1]
      --concurrent-limit <CONCURRENT_LIMIT>
          Enforces a limit on the concurrent number of requests the underlying [default: 65535]
  -x, --proxies <PROXIES>
          Server proxies pool, Example: protocol://user:pass@ip:port [env: PROXIES=]
      --disable-direct
          Disable direct connection [env: DISABLE_DIRECT=]
      --cookie-store
          Enabled Cookie Store [env: COOKIE_STORE=]
      --timeout <TIMEOUT>
          Client timeout (seconds) [default: 600]
      --connect-timeout <CONNECT_TIMEOUT>
          Client connect timeout (seconds) [default: 60]
      --tcp-keepalive <TCP_KEEPALIVE>
          TCP keepalive (seconds) [default: 60]
      --tls-cert <TLS_CERT>
          TLS certificate file path [env: TLS_CERT=]
      --tls-key <TLS_KEY>
          TLS private key file path (EC/PKCS8/RSA) [env: TLS_KEY=]
      --puid-user <PUID_USER>
          Obtain the PUID of the Plus account user, Example: `user:pass`
      --api-prefix <API_PREFIX>
          WebUI api prefix [env: API_PREFIX=]
      --preauth-api <PREAUTH_API>
          PreAuth Cookie API URL [env: PREAUTH_API=] [default: https://ai.fakeopen.com/auth/preauth]
      --arkose-endpoint <ARKOSE_ENDPOINT>
          Arkose endpoint, Example: https://client-api.arkoselabs.com
  -A, --arkose-token-endpoint <ARKOSE_TOKEN_ENDPOINT>
          Get arkose token endpoint
      --arkose-chat-har-file <ARKOSE_CHAT_HAR_FILE>
          About the browser HAR file path requested by ChatGPT ArkoseLabs
      --arkose-auth-har-file <ARKOSE_AUTH_HAR_FILE>
          About the browser HAR file path requested by Auth ArkoseLabs
      --arkose-platform-har-file <ARKOSE_PLATFORM_HAR_FILE>
          About the browser HAR file path requested by Platform ArkoseLabs
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
      --cf-site-key <CF_SITE_KEY>
          Cloudflare turnstile captcha site key [env: CF_SECRET_KEY=]
      --cf-secret-key <CF_SECRET_KEY>
          Cloudflare turnstile captcha secret key [env: CF_SITE_KEY=]
  -D, --disable-webui
          Disable WebUI [env: DISABLE_WEBUI=]
  -h, --help
          Print help
```

### 平台支持

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

### 编译

- Linux编译，Ubuntu机器为例:

```shell
git clone https://github.com/gngpp/ninja.git && cd ninja
cargo build --release
```

- OpenWrt 编译

```shell
cd package
svn co https://github.com/gngpp/ninja/trunk/openwrt
cd -
make menuconfig # choose LUCI->Applications->luci-app-ninja  
make V=s
```

### 说明

- 开源项目可以魔改，但请保留原作者信息，以免失去技术支持。
- 项目是站在其他巨人的肩膀上，感谢！
- 报错、BUG之类的提出Issue，我会修复。

### 预览

![img0](./doc/img/img0.png)
![img1](./doc/img/img1.png)
