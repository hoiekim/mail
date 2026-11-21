//! PROXY protocol v1 on the mail ports.

use crate::env;

/// Whether every mail connection (SMTP and IMAP) starts with a PROXY protocol
/// v1 header naming the client, as a TCP proxy in front of the server sends
/// it. The header is then required.
pub fn is_proxy_protocol_enabled() -> bool {
    env::var("PROXY_PROTOCOL").as_deref() == Some("true")
}
