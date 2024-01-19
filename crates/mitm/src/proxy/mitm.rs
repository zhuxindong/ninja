use super::{
    ca::CertificateAuthority,
    handler::{HttpHandler, MitmFilter},
    http_client::HttpClient,
    sni_reader::{
        read_sni_host_name_from_client_hello, HandshakeRecordReader, PrefixedReaderWriter,
        RecordingBufReader,
    },
};
use http::{header, uri::Scheme, HeaderValue, Uri};
use hyper::{
    body::HttpBody, server::conn::Http, service::service_fn, Body, Method, Request, Response,
};
use log::*;
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    pin,
};
use tokio_rustls::TlsAcceptor;

/// Enum representing either an HTTP request or response.
#[allow(dead_code)]
#[derive(Debug)]
pub enum RequestOrResponse {
    Request(Request<Body>),
    Response(Response<Body>),
}

#[derive(Clone)]
pub(crate) struct MitmProxy<H>
where
    H: HttpHandler,
{
    pub ca: Arc<CertificateAuthority>,
    pub client: HttpClient,

    pub http_handler: Arc<H>,
    pub mitm_filter: Arc<MitmFilter>,
}

impl<H> MitmProxy<H>
where
    H: HttpHandler,
{
    pub(crate) async fn proxy_req(
        self,
        req: Request<Body>,
    ) -> Result<Response<Body>, hyper::Error> {
        let res = if req.method() == Method::CONNECT {
            self.process_connect(req).await
        } else {
            self.process_request(req, Scheme::HTTP).await
        };

        match res {
            Ok(mut res) => {
                allow_all_cros(&mut res);
                Ok(res)
            }
            Err(err) => {
                error!("proxy request failed: {err:?}");
                Err(err)
            }
        }
    }

    async fn process_request(
        self,
        mut req: Request<Body>,
        scheme: Scheme,
    ) -> Result<Response<Body>, hyper::Error> {
        if req.uri().path().starts_with("/preauth/cert") {
            return Ok(self.get_cert_res());
        }

        if req.version() == http::Version::HTTP_10 || req.version() == http::Version::HTTP_11 {
            let (mut parts, body) = req.into_parts();

            if let Some(Ok(authority)) = parts
                .headers
                .get(http::header::HOST)
                .map(|host| host.to_str())
            {
                let mut uri = parts.uri.into_parts();
                uri.scheme = Some(scheme.clone());
                uri.authority = authority.try_into().ok();
                parts.uri = Uri::from_parts(uri).expect("build uri");
            }

            req = Request::from_parts(parts, body);
        };

        // Proxy request
        let mut req = match self.http_handler.handle_request(req).await {
            RequestOrResponse::Request(req) => req,
            RequestOrResponse::Response(res) => return Ok(res),
        };

        {
            let header_mut = req.headers_mut();
            header_mut.remove(http::header::HOST);
            header_mut.remove(http::header::CONNECTION);
            header_mut.remove(http::header::CONTENT_LENGTH);
        }

        let res = match self.client.request(req).await {
            Ok(res) => res,
            Err(err) => {
                warn!("proxy request failed: {err:?}");
                Response::builder()
                    .status(http::StatusCode::BAD_GATEWAY)
                    .body(Body::empty())
                    .expect("failed build response")
            }
        };

        let mut res = self.http_handler.handle_response(res).await;
        let length = res.size_hint().lower();

        {
            let header_mut = res.headers_mut();

            if let Some(content_length) = header_mut.get_mut(http::header::CONTENT_LENGTH) {
                *content_length = HeaderValue::from_str(&length.to_string()).unwrap();
            }

            // Remove `Strict-Transport-Security` to avoid HSTS
            // See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
            header_mut.remove(header::STRICT_TRANSPORT_SECURITY);
        }

        Ok(res)
    }

    async fn process_connect(self, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
        // Filter mitm
        if self.mitm_filter.filter_req(&req).await {
            tokio::task::spawn(async move {
                let authority = req
                    .uri()
                    .authority()
                    .expect("URI does not contain authority")
                    .clone();

                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        self.serve_tls(upgraded).await;
                    }
                    Err(err) => warn!("upgrade error for {authority}: {err}"),
                };
            });
        } else {
            tokio::task::spawn(async move {
                let remote_addr = host_addr(req.uri()).unwrap();
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        if let Some(err) = tunnel(upgraded, remote_addr).await.err() {
                            debug!("tunnel error: {err}");
                        }
                    }
                    Err(err) => warn!("upgrade error for {remote_addr}: {err}"),
                }
            });
        }
        Ok(Response::new(Body::empty()))
    }

    pub async fn serve_tls<IO: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
        self,
        mut stream: IO,
    ) {
        // Read SNI hostname.
        let mut recording_reader = RecordingBufReader::new(&mut stream);
        let reader = HandshakeRecordReader::new(&mut recording_reader);
        pin!(reader);
        let sni_hostname = match tokio::time::timeout(
            Duration::from_secs(5),
            read_sni_host_name_from_client_hello(reader),
        )
        .await
        {
            Ok(Ok(ok)) => ok,
            Ok(Err(err)) => {
                warn!("read sni hostname failed: {}", err);
                return;
            }
            Err(err) => {
                warn!("read sni hostname timeout: {}", err);
                return;
            }
        };

        let read_buf = recording_reader.buf();
        let client_stream = PrefixedReaderWriter::new(stream, read_buf);

        // If the hostname is not in the filter list, then just tunnel the connection.
        if !self.mitm_filter.filter(&sni_hostname).await {
            let remote_addr = format!("{sni_hostname}:443");
            tokio::task::spawn(async move { tunnel(client_stream, remote_addr).await });
            return;
        }

        let server_config = self.ca.clone().gen_server_config();

        match TlsAcceptor::from(server_config).accept(client_stream).await {
            Ok(stream) => {
                if let Err(e) = Http::new()
                    .http2_enable_connect_protocol()
                    .pipeline_flush(true)
                    .serve_connection(
                        stream,
                        service_fn(|req| self.clone().process_request(req, Scheme::HTTPS)),
                    )
                    .with_upgrades()
                    .await
                {
                    let e_string = e.to_string();
                    if !e_string.starts_with("error shutting down connection") {
                        debug!("res:: {}", e);
                    }
                }
            }
            Err(err) => {
                error!("Tls accept failed: {err}")
            }
        }
    }

    pub async fn serve_stream<S>(self, stream: S) -> Result<(), hyper::Error>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Http::new()
            .http2_enable_connect_protocol()
            .pipeline_flush(true)
            .serve_connection(stream, service_fn(|req| self.clone().proxy_req(req)))
            .with_upgrades()
            .await
    }

    fn get_cert_res(&self) -> hyper::Response<Body> {
        Response::builder()
            .header(
                http::header::CONTENT_DISPOSITION,
                "attachment; filename=preauth-mitm.crt",
            )
            .header(http::header::CONTENT_TYPE, "application/octet-stream")
            .status(http::StatusCode::OK)
            .body(Body::from(self.ca.clone().get_cert()))
            .unwrap()
    }
}

fn allow_all_cros(res: &mut Response<Body>) {
    let header_mut = res.headers_mut();
    let all = HeaderValue::from_str("*").unwrap();
    header_mut.insert(http::header::ACCESS_CONTROL_ALLOW_ORIGIN, all.clone());
    header_mut.insert(http::header::ACCESS_CONTROL_ALLOW_METHODS, all.clone());
    header_mut.insert(http::header::ACCESS_CONTROL_ALLOW_METHODS, all);
}

fn host_addr(uri: &http::Uri) -> Option<String> {
    uri.authority().map(|auth| auth.to_string())
}

async fn tunnel<A>(mut client_stream: A, addr: String) -> std::io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
{
    let mut server = TcpStream::connect(addr).await?;
    tokio::io::copy_bidirectional(&mut client_stream, &mut server).await?;
    Ok(())
}
