use openai::arkose::funcaptcha::Solver;
use openai::arkose::{
    funcaptcha::{self, solver::SubmitSolverBuilder, start_challenge},
    ArkoseToken,
};
use std::str::FromStr;
use tokio::sync::OnceCell;
use tokio::time::Instant;

static KEY: OnceCell<String> = OnceCell::const_new();
static SOLVER: OnceCell<Solver> = OnceCell::const_new();

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let key = KEY
        .get_or_init(|| async { std::env::var("KEY").expect("Need solver client key") })
        .await;

    let solver = SOLVER
        .get_or_init(|| async {
            let solver = std::env::var("SOLVER").expect("Need solver");
            Solver::from_str(&solver).expect(&format!("Not support solver: {solver}"))
        })
        .await;

    // start time
    let now = Instant::now();

    let arkose_token = ArkoseToken::new_from_har("/Users/gngpp/VSCode/ninja/login.chat.openai.com.har").await?;

    parse(arkose_token, solver, key).await?;

    println!("Function execution time: {:?}", now.elapsed());
    Ok(())
}

async fn parse(
    arkose_token: ArkoseToken,
    solver: &'static Solver,
    key: &'static str,
) -> anyhow::Result<()> {
    let token = arkose_token.value();
    println!("arkose_token: {:?}", token);
    if !arkose_token.success() {
        match start_challenge(token).await {
            Ok(session) => {
                if let Some(funs) = session.funcaptcha() {
                    let mut rx = match solver {
                        Solver::Yescaptcha => {
                            let (tx, rx) = tokio::sync::mpsc::channel(funs.len());
                            for (i, fun) in funs.iter().enumerate() {
                                let sender = tx.clone();
                                let submit_task = SubmitSolverBuilder::default()
                                    .solved(solver)
                                    .client_key(key)
                                    .question(fun.instructions.clone())
                                    .image(fun.image.clone())
                                    .build()?;
                                tokio::spawn(async move {
                                    let res = funcaptcha::solver::submit_task(submit_task).await;
                                    if let Some(err) = sender.send((i, res)).await.err() {
                                        println!("submit funcaptcha answer error: {err}")
                                    }
                                });
                            }
                            rx
                        }
                        Solver::Capsolver => {
                            let mut classified_data = std::collections::HashMap::new();

                            for item in funs.iter() {
                                let question = item.game_variant.clone();
                                classified_data
                                    .entry(question)
                                    .or_insert(Vec::new())
                                    .push(item);
                            }

                            let (tx, rx) = tokio::sync::mpsc::channel(classified_data.len());

                            for (i, data) in classified_data.into_iter().enumerate() {
                                let images = data
                                    .1
                                    .into_iter()
                                    .map(|item| item.image.clone())
                                    .collect::<Vec<String>>();
                                let submit_task = SubmitSolverBuilder::default()
                                    .solved(solver)
                                    .client_key(key)
                                    .question(data.0)
                                    .images(images)
                                    .build()?;
                                let sender = tx.clone();
                                tokio::spawn(async move {
                                    let res = funcaptcha::solver::submit_task(submit_task).await;
                                    if let Some(err) = sender.send((i, res)).await.err() {
                                        println!("submit funcaptcha answer error: {err}")
                                    }
                                });
                            }
                            rx
                        }
                    };

                    // Wait for all tasks to complete
                    let mut r = Vec::new();
                    let mut need_soty = false;

                    while let Some((i, res)) = rx.recv().await {
                        let answers = res?;
                        println!("index: {i}, answers: {:?}", answers);
                        if answers.len() == 1 {
                            r.push((i, answers[0]));
                            need_soty = true;
                        } else {
                            r.extend(
                                answers
                                    .into_iter()
                                    .enumerate()
                                    .map(|(i, answer)| (i, answer)),
                            );
                        }
                    }

                    if need_soty {
                        r.sort_by_key(|&(i, _)| i);
                    }

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
    Ok(())
}
