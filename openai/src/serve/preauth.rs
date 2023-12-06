use crate::{info, with_context};
use mitm::proxy::hyper::{
    body::Body,
    http::{header, HeaderMap, HeaderValue, Request, Response},
};
use mitm::proxy::{handler::HttpHandler, mitm::RequestOrResponse};
use std::fmt::Write;

#[derive(Clone)]
pub struct PreAuthHanlder;

#[async_trait::async_trait]
impl HttpHandler for PreAuthHanlder {
    async fn handle_request(&self, req: Request<Body>) -> RequestOrResponse {
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

fn collect_preauth_cookie(headers: &HeaderMap<HeaderValue>) {
    headers
        .iter()
        .filter(|(k, _)| k.eq(&header::COOKIE) || k.eq(&header::SET_COOKIE))
        .for_each(|(_, v)| {
            let _ = v
                .to_str()
                .map(|value| with_context!(push_preauth_cookie, value));
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
