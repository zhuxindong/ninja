use std::str::FromStr;

use openai::gpt_model::GPTModel;

#[test]
fn test_gpt_model_from_str() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(GPTModel::from_str("gpt-3.5").unwrap(), GPTModel::Gpt35);
    assert_eq!(GPTModel::from_str("text-davinci").unwrap(), GPTModel::Gpt35);
    assert_eq!(GPTModel::from_str("code-davinci").unwrap(), GPTModel::Gpt35);
    assert_eq!(GPTModel::from_str("gpt-4").unwrap(), GPTModel::Gpt4);
    assert_eq!(
        GPTModel::from_str("gpt-4-mobile").unwrap(),
        GPTModel::Gpt4Mobile
    );
    assert!(GPTModel::from_str("gpt-5").is_err());
    Ok(())
}

#[test]
fn test_gpt_model_serialize() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        serde_json::to_string(&GPTModel::Gpt35)?,
        "\"text-davinci-002-render-sha\""
    );
    assert_eq!(serde_json::to_string(&GPTModel::Gpt4)?, "\"gpt-4\"");
    assert_eq!(
        serde_json::to_string(&GPTModel::Gpt4Mobile)?,
        "\"gpt-4-mobile\""
    );
    Ok(())
}
