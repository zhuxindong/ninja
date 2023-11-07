use openai::arkose;
use openai::arkose::funcaptcha::solver::SubmitSolver;
use openai::arkose::funcaptcha::Solver;
use openai::arkose::{
    funcaptcha::{self, start_challenge},
    ArkoseToken,
};
use std::str::FromStr;
use tokio::sync::OnceCell;
use tokio::time::Instant;

static KEY: OnceCell<String> = OnceCell::const_new();
static SOLVER: OnceCell<Solver> = OnceCell::const_new();
static SOLVER_TYPE: OnceCell<String> = OnceCell::const_new();

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let key = KEY
        .get_or_init(|| async { std::env::var("KEY").expect("Need solver client key") })
        .await;

    let solver = SOLVER
        .get_or_init(|| async {
            let solver = std::env::var("SOLVER").expect("Need solver");
            Solver::from_str(&solver).expect(&format!("Not support solver: {solver}"))
        })
        .await;

    let solver_type = SOLVER_TYPE
        .get_or_init(|| async { std::env::var("SOLVER_TYPE").expect("Need solver type") })
        .await;

    let t = match solver_type.as_str() {
        "auth" => arkose::Type::Auth,
        "platform" => arkose::Type::Platform,
        "chat3" => arkose::Type::GPT3,
        "chat4" => arkose::Type::GPT4,
        _ => anyhow::bail!("Not support solver type: {solver_type}"),
    };

    // start time
    let now = Instant::now();

    let arkose_token = ArkoseToken::new(t).await?;

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
                                let submit_task = SubmitSolver::builder()
                                    .solved(solver)
                                    .client_key(key)
                                    .question(fun.instructions.clone())
                                    .image(fun.image.clone())
                                    .build();
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

                            for data in classified_data {
                                let images_chunks = data
                                    .1
                                    .chunks(3)
                                    .map(|item| {
                                        item.iter().map(|item| item.image.clone()).collect()
                                    })
                                    .collect::<Vec<Vec<String>>>();

                                for (i, images) in images_chunks.into_iter().enumerate() {
                                    let submit_task = SubmitSolver::builder()
                                        .solved(solver)
                                        .client_key(key)
                                        .question(data.0.clone())
                                        .images(images)
                                        .build();
                                    let sender = tx.clone();
                                    tokio::spawn(async move {
                                        let res =
                                            funcaptcha::solver::submit_task(submit_task).await;
                                        if let Some(err) = sender.send((i, res)).await.err() {
                                            println!("submit funcaptcha answer error: {err}")
                                        }
                                    });
                                }
                            }
                            rx
                        }
                    };

                    // Wait for all tasks to complete
                    let mut r = Vec::new();
                    let mut mr = Vec::new();

                    while let Some((i, res)) = rx.recv().await {
                        let answers = res?;
                        println!("index: {i}, answers: {:?}", answers);
                        if answers.len() == 1 {
                            r.push((i, answers[0]));
                        } else {
                            mr.push((i, answers));
                        }
                    }

                    mr.sort_by_key(|&(i, _)| i);
                    for (_, answers) in mr {
                        for answer in answers {
                            r.push((0, answer));
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

    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
    Ok(())
}
