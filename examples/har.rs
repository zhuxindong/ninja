use openai::arkose::ArkoseToken;

#[tokio::main]
async fn main() {
    for _ in 0..100 {
        let token =
            ArkoseToken::new_from_har("/Users/gngpp/PycharmProjects/arkose-generator/har_pool/0A1D34FC-659D-4E23-B17B-694DCFCF6A6C/ua_9b5d630be777ff786e428d055ad3025d.har")
                .await
                .unwrap();
        println!("{}", token.value());
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }
}
