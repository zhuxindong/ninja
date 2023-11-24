use openai::arkose::ArkoseToken;

#[tokio::main]
async fn main() {
    for _ in 0..100 {
        let token =
            ArkoseToken::new_from_har("/Users/gngpp/VSCode/ninja/6.login.chat.openai.com.har")
                .await
                .unwrap();
        println!("{}", token.value());
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }
}
