use openai::arkose::{
    funcaptcha::{self, start_challenge},
    ArkoseToken,
};
use tokio::time::Instant;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let key = std::env::var("KEY").unwrap();
    // start time
    let start_time = Instant::now();

    let arkose_token = ArkoseToken::new().await.unwrap();
    let token = arkose_token.value();
    println!("arkose_token: {token:?}");
    if !arkose_token.valid() {
        match start_challenge(token).await {
            Ok(session) => {
                if let Some(funs) = session.funcaptcha() {
                    let mut answer_list = vec![];
                    for fun in funs {
                        let answer = funcaptcha::yescaptcha::submit_task(
                            &key,
                            &fun.image,
                            &fun.instructions,
                        )
                        .await?;
                        answer_list.push(answer);
                    }
                    println!("answer: {answer_list:?}");
                    session.submit_answer(answer_list).await?;
                }
            }
            Err(error) => {
                eprintln!("Error creating session: {}", error);
            }
        }
    }

    // use time
    let elapsed_time = Instant::now() - start_time;

    println!("Function execution time: {} ms", elapsed_time.as_millis());
    Ok(())
}
