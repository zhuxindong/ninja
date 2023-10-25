use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::arkose::funcaptcha::get_time_stamp;

use super::model::ApiBreaker;

/// Rust does not have dynamic types, and there may be errors in calculations.
fn handle_v2_game3_api_breaker_value(key: &str) -> Box<dyn Fn(Loc) -> Loc> {
    match key {
        "alpha" => Box::new(|c| Loc {
            x: c.x,
            y: (c.y + c.x) * c.x,
            px: c.px,
            py: c.py,
        }),
        "beta" => Box::new(|c| Loc {
            x: c.y,
            y: c.x,
            py: c.px,
            px: c.py,
        }),
        "gamma" => Box::new(|c| Loc {
            x: c.y + (1 as f64),
            y: -c.x,
            px: c.px,
            py: c.py,
        }),
        "delta" => Box::new(|c| Loc {
            x: c.y + 0.25,
            y: c.x + 0.5,
            px: c.px,
            py: c.py,
        }),
        "epsilon" => Box::new(|c| Loc {
            x: c.x * 0.5,
            y: c.y * (5 as f64),
            px: c.px,
            py: c.py,
        }),
        "zeta" => Box::new(|c| Loc {
            x: c.x + (1 as f64),
            y: c.y + (2 as f64),
            px: c.px,
            py: c.py,
        }),
        _ => Box::new(|answer| answer),
    }
}

fn handle_v2_game4_api_breaker_value(key: &str) -> Box<dyn Fn(i32) -> i32> {
    match key {
        "alpha" => Box::new(|answer| {
            let y_value_str = answer.to_string();
            let combined_str = y_value_str + &1.to_string();
            let combined_int = combined_str.parse::<i32>().unwrap();
            combined_int - 2
        }),
        "beta" => Box::new(|answer| -answer),
        "delta" => Box::new(|answer| 7 * answer),
        "gamma" => Box::new(|answer| 3 * (3 - answer)),
        "epsilon" => Box::new(|answer| 2 * answer),
        "zeta" => Box::new(|answer| if answer != 0 { 100 / answer } else { answer }),
        _ => Box::new(|answer| answer),
    }
}

/// Rust does not have dynamic types, and there may be errors in calculations.
fn handle_v2_game3_api_breaker_key(key: &str) -> Box<dyn Fn(Loc) -> serde_json::Value> {
    match key {
        "alpha" => Box::new(|c| json!([c.y, c.px, c.py, c.x])),
        "beta" => Box::new(|c| json!({ "x": c.x, "y": c.y, "px": c.px, "py": c.py })),
        "delta" => Box::new(|c| json!([1, c.x, 2, c.y, 3, c.px, 4, c.py])),
        "epsilon" => Box::new(|c| json!({ "x": c.x, "y": c.y, "px": c.px, "py": c.py })),
        "zeta" => Box::new(|c| json!([c.x, [c.y, [c.px, [c.py]]]])),
        "gamma" | _ => Box::new(|c| {
            json!(vec![
                c.x.to_string(),
                c.y.to_string(),
                c.px.to_string(),
                c.py.to_string()
            ]
            .join(" "))
        }),
    }
}

fn handle_v2_game4_api_breaker_key(key: &str) -> Box<dyn Fn(i32) -> serde_json::Value> {
    match key {
        "alpha" => Box::new(|answer| {
            let v = [
                rand::thread_rng().gen_range(0..100),
                answer,
                rand::thread_rng().gen_range(0..100),
            ];
            json!(v)
        }),
        "beta" => Box::new(|answer| {
            json!({
                "size": 50 - answer,
                "id": answer,
                "limit": 10 * answer,
                "req_timestamp": get_time_stamp(),
            })
        }),
        "delta" => Box::new(|answer| {
            json!({
                "index": answer,
            })
        }),
        "epsilon" => Box::new(|answer| {
            let mut arr: Vec<i32> = Vec::new();
            let len = rand::thread_rng().gen_range(1..=5);
            let rand = rand::thread_rng().gen_range(0..=len);
            for i in 0..len {
                if i == rand {
                    arr.push(answer);
                } else {
                    arr.push(rand::thread_rng().gen_range(0..=10));
                }
            }
            arr.push(rand);
            json!(arr)
        }),
        "zeta" => Box::new(|answer| {
            let array_len = rand::thread_rng().gen_range(0..5) + 1;
            let mut vec = vec![0; array_len];
            vec.push(answer);
            json!(vec)
        }),
        "gamma" | _ => Box::new(|answer| json!(answer)),
    }
}

fn tile_to_loc(tile: i32) -> Loc {
    let x_click =
        (tile % 3) * 100 + (tile % 3) * 3 + 3 + 10 + (rand::random::<f64>() * 80.0) as i32;
    let y_click =
        (tile / 3) * 100 + (tile / 3) * 3 + 3 + 10 + (rand::random::<f64>() * 80.0) as i32;
    Loc {
        x: x_click as f64,
        y: y_click as f64,
        px: x_click as f64 / 300.0,
        py: y_click as f64 / 200.0,
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Loc {
    x: f64,
    y: f64,
    px: f64,
    py: f64,
}

pub(super) fn hanlde_answer(
    v2: bool,
    game_type: u32,
    api_breaker: &ApiBreaker,
    mut answer: i32,
) -> anyhow::Result<serde_json::Value> {
    if !v2 && (game_type == 3 || game_type == 4) {
        let loc = tile_to_loc(answer);
        return Ok(json!(loc));
    }

    if v2 && game_type == 3 {
        let mut loc = tile_to_loc(answer);
        for v in &api_breaker.value {
            loc = handle_v2_game3_api_breaker_value(&v)(loc)
        }
        return Ok(handle_v2_game3_api_breaker_key(&api_breaker.key)(loc));
    }

    if v2 && game_type == 4 {
        for v in &api_breaker.value {
            answer = handle_v2_game4_api_breaker_value(&v)(answer)
        }
        return Ok(handle_v2_game4_api_breaker_key(&api_breaker.key)(answer));
    }

    anyhow::bail!("Unknown game type: {}", game_type)
}
