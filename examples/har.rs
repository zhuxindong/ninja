use openai::{
    arkose::ArkoseToken,
    context::{self, args::Args},
    proxy,
};

#[tokio::main]
async fn main() {
    let args = Args::builder()
        .proxies(vec![proxy::Proxy::try_from((
            "all",
            "http://127.0.0.1:8100",
        ))
        .unwrap()])
        .build();
    context::init(args);
    for _ in 0..100 {
        match ArkoseToken::new_from_har(
            "/Users/gngpp/VSCode/ninja/har/auth0.openai.com_Archive.har",
        )
        .await
        {
            Ok(token) => {
                println!("{}", token.value());
            }
            Err(err) => {
                println!("{}", err);
            }
        };
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }
}
