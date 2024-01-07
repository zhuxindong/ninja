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
            "/Users/gngpp/VSCode/ninja/har/signup.chat.openai.com.har",
            None,
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
