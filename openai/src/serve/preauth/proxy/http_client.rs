use http::{response::Builder, Request, Response};
use hyper::Body;
use reqwest::impersonate::Impersonate;

use super::error::Error;

#[derive(Clone)]
pub struct HttpClient {
    inner: reqwest::Client,
}

impl HttpClient {
    pub fn new(proxy: Option<String>) -> Self {
        let mut builder = reqwest::Client::builder();
        if let Some(p) = proxy {
            builder = builder.proxy(reqwest::Proxy::all(p).expect("faild build proxy"));
        }
        let inner = builder
            .impersonate(Impersonate::Chrome99Android)
            .http1_title_case_headers()
            .danger_accept_invalid_certs(true)
            .build()
            .expect("faild build reqwest client");
        Self { inner }
    }

    pub(super) async fn request(&self, req: Request<Body>) -> Result<Response<Body>, Error> {
        let (method, url) = (req.method().clone(), req.uri().to_string());
        let (parts, body) = req.into_parts();
        let resp = self
            .inner
            .clone()
            .request(method, url)
            .headers(parts.headers)
            .version(parts.version)
            .body(hyper::body::to_bytes(body).await?)
            .send()
            .await?;

        let mut builder = Builder::new()
            .status(resp.status())
            .version(resp.version())
            .extension(parts.extensions);

        builder
            .headers_mut()
            .map(|h| h.extend(resp.headers().clone()));

        Ok(builder.body(hyper::body::Body::wrap_stream(resp.bytes_stream()))?)
    }
}
