local m, s

m = Map("ninja", translate("Ninja"))
m.description = translate("<a>Reverse engineered ChatGPT proxy</a> | <a href=\"https://github.com/gngpp/ninja\" target=\"_blank\">Project GitHub URL</a>")

m:section(SimpleSection).template = "ninja/ninja_status"

s = m:section(TypedSection, "ninja")
s.addremove = false
s.anonymous = true

o = s:option(Flag, "enabled", translate("Enabled"))
o.rmempty = false

o = s:option(Value, "proxies", translate("Proxies"), translate("Supports http/https/socks5/socks5h, format: protocol://user:pass@ip:port"))


o = s:option(Flag, "enable_direct", translate("Turn on direct connection"), translate("Turn on direct connection using proxy"))
o.rmempty = false

o = s:option(Value, "level", translate("Log Level"), translate("info/debug/warn/trace/error"))
o.default = "info"

o = s:option(Value, "bind", translate("Bind Address"), translate("Default listening address: 0.0.0.0:7999"))
o.default = "0.0.0.0:7999"

o = s:option(Value, "concurrent_limit", translate("Concurrent Limit"), translate("Default 100 concurrent connections"))
o.default = "100"

o = s:option(Value, "timeout", translate("Timeout"), translate("Client timeout (secends), default 600 secends"))
o.default = "600"

o = s:option(Value, "connect_timeout", translate("Connect timeout"), translate("Client connect timeout (secends), default 60 secends"))
o.default = "60"

o = s:option(Value, "tcp_keepalive", translate("TCP Keep-Alive"), translate("Default 60 seconds"))
o.default = "60"

o = s:option(Value, "pool_idle_timeout", translate("Pool idle timeout"), translate("Set an optional timeout for idle sockets being kept-alive"))
o.default = "90"

o = s:option(Flag, "cookie_store", translate("Enable Cookie Store"))
o.rmempty = false

o = s:option(Flag, "disable_webui", translate("Disable WebUI"))
o.rmempty = false

o = s:option(Value, "auth_key", translate("Auth Key"), translate("Login Authentication Key"))
o.password = true

o = s:option(Value, "cf_site_key", translate("CF Site Key"), translate("Cloudflare turnstile captcha site key"))

o = s:option(Value, "cf_secret_key", translate("CF Secret Key"), translate("Cloudflare turnstile captcha secret key"))
o.password = true

o = s:option(Flag, "arkose_gpt3_experiment", translate("Enable ChatGPT GPT-3.5 ArkoseLabs"))

o = s:option(Value, "arkose_gpt3_har_dir", translate("ChatGPT GPT-3.5 HAR directory path"), translate("About the browser HAR directory path requested by ChatGPT GPT-3.5 ArkoseLabs"))

o = s:option(Value, "arkose_gpt4_har_dir", translate("ChatGPT GPT-4 HAR directory path"), translate("About the browser HAR directory path requested by ChatGPT GPT-4 ArkoseLabs"))

o = s:option(Value, "arkose_auth_har_dir", translate("Auth HAR directory path"), translate(" About the browser HAR directory path requested by Auth ArkoseLabs"))

o = s:option(Value, "arkose_platform_har_dir", translate("Platform HAR directory path"), translate("About the browser HAR directory path requested by Platform ArkoseLabs"))

o = s:option(Value, "arkose_har_upload_key", translate("HAR Auth Key"), translate("HAR file upload authenticate key"))
o.password = true

o = s:option(Value, "arkose_solver", translate("Solver"), translate("About ArkoseLabs solver platform"))
o:value("yescaptcha", "yescaptcha");
o:value("capsolver", "capsolver");

o = s:option(Value, "arkose_solver_key", translate("Solver Client Key"), translate("About the solver client key by ArkoseLabs"))

o = s:option(Value, "tls_cert", translate("TLS certificate file path"), translate("Certificate in DER format"))

o = s:option(Value, "tls_key", translate("TLS private key file path"), translate("Supports EC/PKCS8/RSA type formats"))

o = s:option(Flag, "tb_enable", translate("Enable Token Bucket Limit"))
o.rmempty = false

o = s:option(ListValue, "tb_store_strategy", translate("Token Bucket Storage Strategy"), translate("Token bucket storage strategy, mem/redis"))
o:value("mem", "mem");
o:value("redis", "redis");
o.default = "mem"

o = s:option(Value, "tb_redis_url", translate("Token bucket redis url"), translate("Example: redis://user:pass@ip:port"))
o.default = "redis://127.0.0.1:6379"

o = s:option(Value, "tb_capacity", translate("Token Bucket Capacity"), translate("Token bucket capacity, the default is 60"))
o.default = "60"

o = s:option(Value, "tb_fill_rate", translate("Token Bucket Fill Rate"), translate("Token bucket fill rate, the default is 1"))
o.default = "1"

o = s:option(Value, "tb_expired", translate("Token Bucket Expired"), translate("Token bucket expired time, the default is 86400 seconds"))
o.default = "86400"

o = s:option(Value, "pbind", translate("Preauth MITM server bind address"))

o = s:option(Value, "pupstream", translate("MITM Upstream proxy"), translate("Supports http/https/socks5/socks5h, format: protocol://user:pass@ip:port"))

o = s:option(Value, "pcert", translate("Preauth MITM server CA certificate file path"))

o = s:option(Value, "pkey", translate("Preauth MITM server CA private key file path"))

return m
