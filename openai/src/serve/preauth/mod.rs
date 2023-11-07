use std::{fs, net::SocketAddr, path::PathBuf};

use anyhow::Context;
use http::{header, Request, Response};
use hyper::Body;

use self::proxy::mitm::RequestOrResponse;
use crate::{
    context,
    serve::preauth::proxy::{handler::HttpHandler, CertificateAuthority},
};
use log::info;

pub mod cagen;
mod proxy;

pub(super) async fn mitm_proxy(
    bind: SocketAddr,
    upstream_proxy: Option<String>,
    cert: PathBuf,
    key: PathBuf,
) -> anyhow::Result<()> {
    info!("PreAuth CA Private key use: {}", key.display());
    let private_key_bytes = fs::read(key).context("ca private key file path not valid!")?;
    let private_key = rustls_pemfile::pkcs8_private_keys(&mut private_key_bytes.as_slice())
        .context("Failed to parse private key")?;
    let key = rustls::PrivateKey(private_key[0].clone());

    info!("PreAuth CA Certificate use: {}", cert.display());
    let ca_cert_bytes = fs::read(cert).context("ca cert file path not valid!")?;
    let ca_cert = rustls_pemfile::certs(&mut ca_cert_bytes.as_slice())
        .context("Failed to parse CA certificate")?;
    let cert = rustls::Certificate(ca_cert[0].clone());

    let ca = CertificateAuthority::new(
        key,
        cert,
        String::from_utf8(ca_cert_bytes).context("Failed to parse CA certificate")?,
        1_000,
    )
    .context("Failed to create Certificate Authority")?;

    info!("PreAuth Http MITM Proxy listen on: http://{bind}");

    let http_handler = PreAuthHanlder;

    let proxy = proxy::Proxy::builder()
        .ca(ca.clone())
        .listen_addr(bind)
        .upstream_proxy(upstream_proxy)
        .mitm_filters(vec![String::from("ios.chat.openai.com")])
        .handler(http_handler.clone())
        .build();

    tokio::spawn(proxy.start_proxy());
    Ok(())
}

#[derive(Clone)]
struct PreAuthHanlder;

#[async_trait::async_trait]
impl HttpHandler for PreAuthHanlder {
    async fn handle_request(&self, req: Request<Body>) -> RequestOrResponse {
        // remove accept-encoding to avoid encoded body
        if log::log_enabled!(log::Level::Debug) {
            log_req(&req).await;
        }
        // extract preauth cookie
        collect_preauth_cookie(req.headers());

        RequestOrResponse::Request(req)
    }

    async fn handle_response(&self, res: Response<Body>) -> Response<Body> {
        if log::log_enabled!(log::Level::Debug) {
            log_res(&res).await;
        }
        collect_preauth_cookie(res.headers());
        res
    }
}

use std::fmt::Write;

fn collect_preauth_cookie(headers: &http::HeaderMap<http::HeaderValue>) {
    headers
        .iter()
        .filter(|(k, _)| k.eq(&header::COOKIE) || k.eq(&header::SET_COOKIE))
        .for_each(|(_, v)| {
            let _ = v
                .to_str()
                .map(|value| context::get_instance().push_preauth_cookie(value));
        });
}

pub async fn log_req(req: &Request<Body>) {
    let headers = req.headers();
    let mut header_formated = String::new();
    for (key, value) in headers {
        let v = match value.to_str() {
            Ok(v) => v.to_string(),
            Err(_) => {
                format!("[u8]; {}", value.len())
            }
        };
        write!(
            &mut header_formated,
            "\t{:<20}{}\r\n",
            format!("{}:", key.as_str()),
            v
        )
        .unwrap();
    }

    info!(
        "{} {}
Headers:
{}",
        req.method(),
        req.uri().to_string(),
        header_formated
    )
}

pub async fn log_res(res: &Response<Body>) {
    let headers = res.headers();
    let mut header_formated = String::new();
    for (key, value) in headers {
        let v = match value.to_str() {
            Ok(v) => v.to_string(),
            Err(_) => {
                format!("[u8]; {}", value.len())
            }
        };
        write!(
            &mut header_formated,
            "\t{:<20}{}\r\n",
            format!("{}:", key.as_str()),
            v
        )
        .unwrap();
    }

    info!(
        "{} {:?}
Headers:
{}",
        res.status(),
        res.version(),
        header_formated
    )
}
