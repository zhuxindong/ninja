pub mod cagen;
pub mod proxy;

use anyhow::Context;
use std::{fs, net::SocketAddr, path::PathBuf};
use typed_builder::TypedBuilder;

use crate::proxy::{handler::HttpHandler, CertificateAuthority};
use log::info;

#[derive(TypedBuilder)]
pub struct Builder<T: HttpHandler + Clone> {
    bind: SocketAddr,
    upstream_proxy: Option<String>,
    cert: PathBuf,
    key: PathBuf,
    graceful_shutdown: tokio::sync::mpsc::Receiver<()>,
    cerificate_cache_size: u32,
    mitm_filters: Vec<String>,
    handler: T,
}

impl<T: HttpHandler + Clone> Builder<T> {
    pub async fn proxy(self) -> anyhow::Result<()> {
        info!("PreAuth CA Private key use: {}", self.key.display());
        let private_key_bytes =
            fs::read(self.key).context("ca private key file path not valid!")?;
        let private_key = rustls_pemfile::pkcs8_private_keys(&mut private_key_bytes.as_slice())
            .context("Failed to parse private key")?;
        let key = rustls::PrivateKey(private_key[0].clone());

        info!("PreAuth CA Certificate use: {}", self.cert.display());
        let ca_cert_bytes = fs::read(self.cert).context("ca cert file path not valid!")?;
        let ca_cert = rustls_pemfile::certs(&mut ca_cert_bytes.as_slice())
            .context("Failed to parse CA certificate")?;
        let cert = rustls::Certificate(ca_cert[0].clone());

        let ca = CertificateAuthority::new(
            key,
            cert,
            String::from_utf8(ca_cert_bytes).context("Failed to parse CA certificate")?,
            self.cerificate_cache_size.into(),
        )
        .context("Failed to create Certificate Authority")?;

        info!("PreAuth Http MITM Proxy listen on: http://{}", self.bind);

        let proxy = proxy::Proxy::builder()
            .ca(ca.clone())
            .listen_addr(self.bind)
            .upstream_proxy(self.upstream_proxy)
            .mitm_filters(self.mitm_filters)
            .handler(self.handler)
            .graceful_shutdown(self.graceful_shutdown)
            .build();

        tokio::spawn(proxy.start_proxy());
        Ok(())
    }
}
