use super::error::{ProxyError, ResponseError};
use crate::with_context;

pub(super) fn check_whitelist(identify: &str) -> Result<(), ResponseError> {
    if let Some(w) = with_context!(visitor_email_whitelist) {
        if !w.is_empty() {
            w.iter()
                .find(|&w| w.eq(identify))
                .ok_or(ResponseError::Forbidden(ProxyError::AccessNotInWhitelist))?;
        }
    }
    Ok(())
}
