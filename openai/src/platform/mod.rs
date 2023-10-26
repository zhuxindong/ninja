//! More information: [set API key](#set-api-key), [add proxy](#add-proxy), [use model names](#use-model-names)
//!
//! ## Endpoints
//!
//! - Models
//!   - [List models](#list-models)
//!   - [Retrieve model](#retrieve-model)
//! - Completions
//!   - [Create completion](#create-completion)
//!   - [Create completion (stream)](#create-completion-stream)
//! - Chat
//!   - [Create chat completion](#create-chat-completion)
//!   - [Create chat completion (stream)](#create-chat-completion-stream)
//!
//! # Endpoints
//!
//! ## List models
//!
//! Lists the currently available models, and provides basic information about each one such as the owner and availability.
//!
//! **URL** `https://api.openai.com/v1/models`
//!
//! **Method** `GET`
//!
//! ```rust
//! use openai::v1::api::Client;
//!
//! #[tokio::main]
//! async fn main() {
//!     let api_key = std::env::var("OPENAI_API_KEY").expect("$OPENAI_API_KEY is not set");
//!
//!     let client = Client::new(api_key);
//!
//!     let result = client.models().list().await.unwrap();
//!
//!     println!("{:?}", result);
//! }
//! ```
//!
//! More information: [List models](https://platform.openai.com/docs/api-reference/models/list)
//!
//! ## Retrieve model
//!
//! Retrieves a model instance, providing basic information about the model such as the owner and permissioning.
//!
//! **URL** `https://api.openai.com/v1/models/{model}`
//!
//! **Method** `GET`
//!
//! ```rust
//! use openai::v1::api::Client;
//!
//! #[tokio::main]
//! async fn main() {
//!     let api_key = std::env::var("OPENAI_API_KEY").expect("$OPENAI_API_KEY is not set");
//!
//!     let client = Client::new(api_key);
//!
//!     let result = client.models().get("text-davinci-003").await.unwrap();
//!
//!     println!("{:?}", result);
//! }
//! ```
//!
//! More information: [Retrieve models](https://platform.openai.com/docs/api-reference/models/retrieve)
//!
//! ## Create completion
//!
//! Creates a completion for the provided prompt and parameters.
//!
//! **URL** `https://api.openai.com/v1/completions`
//!
//! **Method** `POST`
//!
//! ```rust
//! use openai::v1::api::Client;
//! use openai::v1::resources::completion::CompletionParameters;
//!
//! #[tokio::main]
//! async fn main() {
//!     let api_key = std::env::var("OPENAI_API_KEY").expect("$OPENAI_API_KEY is not set");
//!
//!     let client = Client::new(api_key);
//!
//!     let parameters = CompletionParameters {
//!         model: "text-davinci-003".to_string(),
//!         prompt: "Say this is a test".to_string(),
//!         suffix: None,
//!         max_tokens: Some(10),
//!         temperature: None,
//!         top_p: None,
//!         n: None,
//!         logprobs: None,
//!         echo: None,
//!         stop: None,
//!         presence_penalty: None,
//!         frequency_penalty: None,
//!         best_of: None,
//!         logit_bias: None,
//!         user: None,
//!         // or use ..Default::default()
//!     };
//!
//!     let result = client.completions().create(parameters).await.unwrap();
//!
//!     println!("{:?}", result);
//! }
//! ```
//!
//! More information: [Create completion](https://platform.openai.com/docs/api-reference/completions/create)
//!
//! ## Create completion (stream)
//!
//! Creates a completion for the provided prompt and parameters.
//!
//! **URL** `https://api.openai.com/v1/completions`
//!
//! **Method** `POST`
//!
//! ```rust
//! use futures::StreamExt;
//! use openai::v1::api::Client;
//! use openai::v1::resources::completion::CompletionParameters;
//!
//! #[tokio::main]
//! async fn main() {
//!     let api_key = std::env::var("OPENAI_API_KEY").expect("$OPENAI_API_KEY is not set");
//!
//!     let client = Client::new(api_key);
//!
//!     let parameters = CompletionParameters {
//!         model: "text-davinci-003".to_string(),
//!         prompt: "Say this is a test".to_string(),
//!         suffix: None,
//!         max_tokens: Some(10),
//!         temperature: None,
//!         top_p: None,
//!         n: None,
//!         logprobs: None,
//!         echo: None,
//!         stop: None,
//!         presence_penalty: None,
//!         frequency_penalty: None,
//!         best_of: None,
//!         logit_bias: None,
//!         user: None,
//!     };
//!
//!     let mut stream = client.completions().create_stream(parameters).await.unwrap();
//!
//!     while let Some(response) = stream.next().await {
//!         match response {
//!             Ok(completion_response) => completion_response.choices.iter().for_each(|choice| {
//!                 print!("{}", choice.text);
//!             }),
//!             Err(e) => eprintln!("{}", e),
//!         }
//!     }
//! }
//! ```
//!
//! More information: [Create completion](https://platform.openai.com/docs/api-reference/completions/create)
//!
//! ## Create chat completion
//!
//! Creates a completion for the chat message.
//!
//! **URL** `https://api.openai.com/v1/chat/completions`
//!
//! **Method** `POST`
//!
//! ```rust
//! use openai::v1::api::Client;
//! use openai::v1::resources::chat_completion::{ChatCompletionParameters, ChatMessage, Role};
//!
//! #[tokio::main]
//! async fn main() {
//!     let api_key = std::env::var("OPENAI_API_KEY").expect("$OPENAI_API_KEY is not set");
//!
//!     let client = Client::new(api_key);
//!
//!     let parameters = ChatCompletionParameters {
//!         model: "gpt-3.5-turbo-0301".to_string(),
//!         messages: vec![
//!             ChatMessage {
//!                 role: Role::User,
//!                 content: "Hello!".to_string(),
//!                 name: None,
//!             },
//!             ChatMessage {
//!                 role: Role::User,
//!                 content: "Where are you located?".to_string(),
//!                 name: None,
//!             },
//!         ],
//!         temperature: None,
//!         top_p: None,
//!         n: None,
//!         stop: None,
//!         max_tokens: Some(12),
//!         presence_penalty: None,
//!         frequency_penalty: None,
//!         logit_bias: None,
//!         user: None,
//!         // or use ..Default::default()
//!     };
//!
//!     let result = client.chat().create(parameters).await.unwrap();
//!
//!     println!("{:?}", result);
//! }
//! ```
//!
//! More information: [Create chat completion](https://platform.openai.com/docs/api-reference/chat/create)
//!
//! ## Create chat completion (stream)
//!
//! Creates a completion for the chat message.
//!
//! **URL** `https://api.openai.com/v1/chat/completions`
//!
//! **Method** `POST`
//!
//! ```rust
//! use futures::StreamExt;
//! use openai::v1::api::Client;
//! use openai::v1::resources::chat_completion::{ChatCompletionParameters, ChatMessage, Role};
//!
//! #[tokio::main]
//! async fn main() {
//!     let api_key = std::env::var("OPENAI_API_KEY").expect("$OPENAI_API_KEY is not set");
//!
//!     let client = Client::new(api_key);
//!
//!     let parameters = ChatCompletionParameters {
//!         model: "gpt-3.5-turbo-0301".to_string(),
//!         messages: vec![
//!             ChatMessage {
//!                 role: Role::User,
//!                 content: "Hello!".to_string(),
//!                 name: None,
//!             },
//!             ChatMessage {
//!                 role: Role::User,
//!                 content: "Where are you located?".to_string(),
//!                 name: None,
//!             },
//!         ],
//!         temperature: None,
//!         top_p: None,
//!         n: None,
//!         stop: None,
//!         max_tokens: Some(12),
//!         presence_penalty: None,
//!         frequency_penalty: None,
//!         logit_bias: None,
//!         user: None,
//!     };
//!
//!     let mut stream = client.chat().create_stream(parameters).await.unwrap();
//!
//!     while let Some(response) = stream.next().await {
//!         match response {
//!             Ok(chat_response) => chat_response.choices.iter().for_each(|choice| {
//!                 if let Some(content) = choice.delta.content.as_ref() {
//!                     print!("{}", content);
//!                 }
//!             }),
//!             Err(e) => eprintln!("{}", e),
//!         }
//!     }
//! }
//! ```
//!
//! More information: [Create chat completion](https://platform.openai.com/docs/api-reference/chat/create)
//!
//! ## Set API key
//!
//! Add the OpenAI API key to your environment variables.
//!
//! ```sh
//! # Windows PowerShell
//! $Env:OPENAI_API_KEY='sk-...'
//!
//! # Windows cmd
//! set OPENAI_API_KEY=sk-...
//!
//! # Linux/macOS
//! export OPENAI_API_KEY='sk-...'
//! ```
//!
//! ## Add proxy
//!
//! This crate uses `reqwest` as HTTP Client. Reqwest has proxies enabled by default. You can set the proxy via the system environment variable or by overriding the default client.
//!
//! ### Example: set system environment variable
//!
//! You can set the proxy in the system environment variables ([https://docs.rs/reqwest/latest/reqwest/#proxies](https://docs.rs/reqwest/latest/reqwest/#proxies)).
//!
//! ```sh
//! export https_proxy=socks5://127.0.0.1:1086
//! ```
//!
//! ### Example: overriding the default client
//!
//! ```rust
//! use openai::v1::api::Client;
//!
//! let http_client = reqwest::Client::builder()
//!     .proxy(reqwest::Proxy::https("socks5://127.0.0.1:1086")?)
//!     .build()?;
//!
//! let client = Client {
//!     http_client,
//!     base_url: "https://api.openai.com/v1".to_string(),
//!     api_key: "YOUR API KEY".to_string(),
//! };
//! ```
//!
//! ## Use model names
//!
//! ```rust
//! use openai::v1::models::OpenAIModel;
//!
//! assert_eq!(OpenAIModel::Gpt4.to_string(), "gpt-4");
//! assert_eq!(OpenAIModel::Gpt4_0314.to_string(), "gpt-4-0314");
//! assert_eq!(OpenAIModel::Gpt4_32K.to_string(), "gpt-4-32k");
//! assert_eq!(OpenAIModel::Gpt4_32K0314.to_string(), "gpt-4-32k-0314");
//! assert_eq!(OpenAIModel::Gpt3_5Turbo.to_string(), "gpt-3.5-turbo-0301");
//! assert_eq!(OpenAIModel::Gpt3_5Turbo0301.to_string(), "gpt-3.5-turbo");
//! assert_eq!(OpenAIModel::TextDavinci003.to_string(), "text-davinci-003");
//! assert_eq!(OpenAIModel::TextDavinciEdit001.to_string(), "text-davinci-edit-001");
//! assert_eq!(OpenAIModel::TextCurie001.to_string(), "text-curie-001");
//! assert_eq!(OpenAIModel::TextBabbage001.to_string(), "text-babbage-001");
//! assert_eq!(OpenAIModel::TextAda001.to_string(), "text-ada-001");
//! assert_eq!(OpenAIModel::TextEmbeddingAda002.to_string(), "text-embedding-ada-002");
//! assert_eq!(OpenAIModel::Whisper1.to_string(), "whisper-1");
//! assert_eq!(OpenAIModel::TextModerationStable.to_string(), "text-moderation-stable");
//! assert_eq!(OpenAIModel::TextModerationLatest.to_string(), "text-moderation-latest");
//!
//! // so instead of this..
//! let parameters = CompletionParameters {
//!     model: "text-davinci-003".to_string(),
//!     prompt: "Say this is a test".to_string(),
//!     // ...
//! }
//!
//! // you can do this (with auto-complete)
//! let parameters = CompletionParameters {
//!     model: OpenAIModel::TextDavinci003.to_string(),
//!     prompt: "Say this is a test".to_string(),
//!     // ...
//! }
//! ```

#[cfg(feature = "api")]
pub mod v1;
