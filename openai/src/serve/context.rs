use std::sync::Once;

use crate::{
    arkose::{funcaptcha, ArkoseToken},
    auth::AuthClient,
    debug, info,
};
use reqwest::Client;

use super::{err::ResponseError, load_balancer, Launcher};

static mut ENV: Option<Env> = None;
static INIT: Once = Once::new();

pub(super) struct Env {
    client_load: load_balancer::ClientLoadBalancer<Client>,
    auth_client_load: load_balancer::ClientLoadBalancer<AuthClient>,
    share_puid: Option<String>,
    arkose_token_endpoint: Option<String>,
    yescaptcha_client_key: Option<String>,
}

impl Env {
    fn new(args: &Launcher) -> Self {
        let puid = if let Some(puid) = args.puid.as_ref() {
            info!("Using PUID: {puid}");
            Some(puid.to_owned())
        } else {
            None
        };
        Env {
            client_load: load_balancer::ClientLoadBalancer::<Client>::new_api_client(args)
                .expect("Failed to initialize the requesting client"),
            auth_client_load: load_balancer::ClientLoadBalancer::<AuthClient>::new_auth_client(
                args,
            )
            .expect("Failed to initialize the requesting oauth client"),
            share_puid: puid,
            arkose_token_endpoint: args.arkose_token_endpoint.clone(),
            yescaptcha_client_key: args.yescaptcha_client_key.clone(),
        }
    }

    pub fn load_client(&self) -> Client {
        self.client_load.next()
    }

    pub fn load_auth_client(&self) -> AuthClient {
        self.auth_client_load.next()
    }

    pub fn get_share_puid(&self) -> Option<&str> {
        self.share_puid.as_deref()
    }

    pub fn set_share_puid(&mut self, puid: Option<String>) {
        self.share_puid = puid;
    }

    pub async fn get_arkose_token(&self) -> anyhow::Result<ArkoseToken, ResponseError> {
        if self.arkose_token_endpoint.is_some() || self.yescaptcha_client_key.is_some() {
            if let Some(ref arkose_token_endpoint) = self.arkose_token_endpoint {
                if let Ok(arkose_token) =
                    ArkoseToken::new_from_endpoint("gpt4-fuck", arkose_token_endpoint).await
                {
                    return Ok(arkose_token);
                }
            }

            if let Some(ref key) = self.yescaptcha_client_key {
                let arkose_token = ArkoseToken::new("gpt4-fuck").await?;
                let arkose_token_value = arkose_token.value();
                if !arkose_token.valid() {
                    let session = funcaptcha::start_challenge(arkose_token_value)
                        .await
                        .map_err(|error| {
                            eprintln!("Error creating session: {}", error);
                            ResponseError::InternalServerError(error)
                        })?;

                    let funcaptcha =
                        session
                            .funcaptcha()
                            .ok_or(ResponseError::InternalServerError(anyhow::anyhow!(
                                "valid funcaptcha error"
                            )))?;

                    let answer = funcaptcha::yescaptcha::submit_task(
                        key,
                        &funcaptcha.image,
                        &funcaptcha.instructions,
                    )
                    .await
                    .map_err(|error| ResponseError::InternalServerError(error))?;

                    return match session.submit_answer(answer).await {
                        Ok(_) => Ok(ArkoseToken::from(format!("{arkose_token_value}|sup=1"))),
                        Err(err) => {
                            debug!("submit funcaptcha answer error: {err}");
                            Ok(arkose_token)
                        }
                    };
                }
            }
        }
        Ok(ArkoseToken::new("gpt-4-fuck")
            .await
            .map_err(|err| ResponseError::InternalServerError(err))?)
    }
}

pub(super) struct Context;

impl Context {
    pub fn init(args: &Launcher) {
        // Use Once to guarantee initialization only once
        INIT.call_once(|| unsafe { ENV = Some(Env::new(args)) });
    }

    pub fn get_instance() -> &'static mut Env {
        unsafe {
            ENV.as_mut()
                .expect("Runtime Env component is not initialized")
        }
    }
}
