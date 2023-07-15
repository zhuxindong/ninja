use std::collections::HashMap;

use serde_json::Value;
use url::Url;

#[tokio::main]
async fn main() {
    let client = reqwest::Client::builder()
        .chrome_builder(reqwest::browser::ChromeVersion::V104)
        .cookie_store(true)
        .build()
        .unwrap();
    let resp = client
        .get("https://chat.openai.com/api/auth/csrf")
        .send()
        .await
        .unwrap();

    let res = resp.json::<Value>().await.unwrap();
    let csrf_token = res
        .as_object()
        .unwrap()
        .get("csrfToken")
        .unwrap()
        .as_str()
        .unwrap();
    println!("csrf_token: {}", csrf_token);

    let form = [
        ("callbackUrl", "/"),
        ("csrfToken", csrf_token),
        ("json", "true"),
    ];
    let resp = client
        .post("https://chat.openai.com/api/auth/signin/auth0?prompt=login")
        .form(&form)
        .send()
        .await
        .unwrap();

    if resp.status().is_success() {
        let res = resp.json::<Value>().await.unwrap();
        println!("url: {}", res);
        let url = res
            .as_object()
            .unwrap()
            .get("url")
            .unwrap()
            .as_str()
            .unwrap();
        let resp = client.get(url).send().await.unwrap();
        let text = resp.text().await.unwrap();

        let tag_start = "<input";
        let attribute_name = "name=\"state\"";
        let value_start = "value=\"";

        let mut remaining = text.as_str();
        let mut found_state = None;

        while let Some(tag_start_index) = remaining.find(tag_start) {
            remaining = &remaining[tag_start_index..];

            if let Some(attribute_index) = remaining.find(attribute_name) {
                remaining = &remaining[attribute_index..];

                if let Some(value_start_index) = remaining.find(value_start) {
                    remaining = &remaining[value_start_index + value_start.len()..];

                    if let Some(value_end_index) = remaining.find("\"") {
                        let value = &remaining[..value_end_index];
                        found_state = Some(value);
                        break; // 找到目标后跳出循环
                    }
                }
            }

            remaining = &remaining[tag_start.len()..];
        }

        if let Some(value) = found_state {
            println!("State: {}", value);
        }

        // let form: [(&str, &str); 7] = [("state", &state), ("username", "vertx.verticle@gmail.com"), ("js-available", "true"),("webauthn-available", "true"), ("is-brave", "false"),  ("webauthn-platform-available", "false"), ("action", "default")];
        // let resp = client
        //     .post(format!("https://chat.openai.com/u/login/identifier?state={state}"))
        //     .form(&form)
        //     .send()
        //     .await.unwrap();

        // if resp.status().is_success() {
        //     println!("check username ok");
        // } else {
        //     println!("check username error: {}", resp.text().await.unwrap())
        // }
    }
}
