use super::error::ProxyError;
use crate::with_context;

pub(super) fn check_whitelist(identify: &str) -> Result<(), ProxyError> {
    if let Some(w) = with_context!(visitor_email_whitelist) {
        if !w.is_empty() {
            w.iter()
                .find(|&w| w.eq(identify))
                .ok_or(ProxyError::AccessNotInWhitelist)?;
        }
    }
    Ok(())
}
