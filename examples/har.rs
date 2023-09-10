use openai::arkose::ArkoseToken;

#[tokio::main]
async fn main() {
    let token =
        ArkoseToken::new_form_har("/Users/gngpp/Desktop/incogniton/117.chat.openai.com.har")
            .await
            .unwrap();
    println!("{}", token.value())
}
