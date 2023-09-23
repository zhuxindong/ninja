use openai::arkose::{
    funcaptcha::{self, solver::SubmitSolverBuilder, start_challenge},
    ArkoseToken,
};
use tokio::time::Instant;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let key = std::env::var("KEY")?;
    // start time
    let start_time = Instant::now();

    let arkose_token = ArkoseToken::new_platform().await?;
    let token = arkose_token.value();
    println!("arkose_token: {:?}", token);
    if !arkose_token.success() {
        match start_challenge(token).await {
            Ok(session) => {
                if let Some(funs) = session.funcaptcha() {
                    let max_cap = funs.len();
                    let (tx, mut rx) = tokio::sync::mpsc::channel(max_cap);
                    for (i, fun) in funs.into_iter().enumerate() {
                        let sender = tx.clone();
                        let submit_task = SubmitSolverBuilder::default()
                            .solved(funcaptcha::Solver::Capsolver)
                            .client_key(key.clone())
                            .question(fun.game_variant)
                            .image_as_base64(fun.image)
                            .build()?;
                        tokio::spawn(async move {
                            let res = funcaptcha::solver::submit_task(submit_task).await;
                            sender.send((i, res)).await.expect("Send failed")
                        });
                    }

                    // Wait for all tasks to complete
                    let mut r = Vec::with_capacity(max_cap);
                    for _ in 0..max_cap {
                        if let Some((i, res)) = rx.recv().await {
                            let answer = res?;
                            r.push((i, answer));
                            println!("recv: {answer}");
                        }
                    }

                    r.sort_by_key(|&(i, _)| i);

                    let answers = r
                        .into_iter()
                        .map(|(_, answer)| answer)
                        .collect::<Vec<i32>>();

                    session.submit_answer(answers).await?;
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
