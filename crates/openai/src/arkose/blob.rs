use super::Type;
use crate::with_context;
use serde::Deserialize;

/// Get arkose blob payload
pub async fn get_blob(typed: Type, identifier: Option<String>) -> anyhow::Result<Option<String>> {
    match (typed, identifier) {
        (Type::GPT4, Some(identifier)) => {
            #[derive(Deserialize)]
            struct Blob {
                data: String,
            }
            let resp = with_context!(arkose_client)
                .post("https://chat.openai.com/backend-api/sentinel/arkose/dx")
                .bearer_auth(identifier)
                .send()
                .await?
                .error_for_status()?
                .json::<Blob>()
                .await?;
            Ok(Some(resp.data))
        }
        (Type::SignUp, Some(identifier)) => Ok(Some(identifier)),
        _ => Ok(None),
    }
}
