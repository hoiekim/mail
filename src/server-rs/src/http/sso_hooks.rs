//! The points where the request pipeline and the user routes consult single
//! sign-on. Kept in one place so the HTTP layer names `sso` in one file.

use serde::Serialize;

use crate::http::session::HttpSession;

/// How the browser may sign in: what the sign-in page shows.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct SsoMode {
    pub enabled: bool,
    #[serde(rename = "localLogin")]
    pub local_login: bool,
}

/// Single sign-on is off until the `sso` module is wired in.
pub fn sso_mode() -> SsoMode {
    SsoMode { enabled: false, local_login: true }
}

/// Whether passwords stored in this app's own database may sign in.
pub fn is_local_login_allowed() -> bool {
    sso_mode().local_login
}

/// Holds the session a request arrived with to the sign-in mode, before any
/// route reads it.
pub async fn enforce_sso_session(_session: &mut HttpSession) -> anyhow::Result<()> {
    Ok(())
}
