use openai::{
    arkose::ArkoseToken,
    context::{self, args::Args},
};

#[tokio::main]
async fn main() {
    let args = Args::builder().build();
    context::init(args);
    for _ in 0..100 {
        match ArkoseToken::new_from_har(
            "/Users/gngpp/PycharmProjects/arkose-generator/har_pool/0A1D34FC-659D-4E23-B17B-694DCFCF6A6C/ua_9ccf5392af6a2715a08456f19ebf3de9.har",
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
