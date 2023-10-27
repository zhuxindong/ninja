use crate::preauth::proxy::handler::HttpHandler;

pub mod cagen;
pub mod proxy;

pub fn run() {}

#[derive(Clone)]
struct PreAuthHanlder {}

impl HttpHandler for PreAuthHanlder {
    async fn handle_request(&self, req: Request<Body>) -> RequestOrResponse {
        RequestOrResponse::Request(req)
    }

    async fn handle_response(&self, res: Response<Body>) -> Response<Body> {
        res
    }
}
