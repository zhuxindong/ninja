use openai::arkose::har::Har;
use serde_json::{json, Value};

fn main() {
    let bytes = std::fs::read("/Users/gngpp/VSCode/opengpt/examples/chat.openai.com.har").unwrap();
    // let json = serde_json::to_string_pretty(&bytes).unwrap();
    let json = &json!(serde_json::from_slice::<Value>(&bytes).unwrap())["log"];
    let har = serde_json::from_value::<Har>(json.clone()).unwrap();
    for entrie in har.entries {
        if entrie.request.url.contains("fc/gt2/public_key") {
            println!("{entrie:?}")
        }
    }
}
