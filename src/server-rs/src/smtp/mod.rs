//! The SMTP server.
//!
//! This is the protocol: listeners, connections and the command state
//! machine. What happens to the mail is behind [`SmtpHandler`], the hooks a
//! listener calls for AUTH, MAIL FROM, RCPT TO and DATA.

pub mod address_command;
pub mod connection;
pub mod data_budget;
pub mod data_stream;
pub mod listeners;
pub mod registry;
pub mod server;
pub mod types;

pub use data_budget::{with_smtp_data_budget, DataBudgetUnavailableError};
pub use data_stream::{SmtpDataAbandoned, SmtpDataStream};
pub use listeners::{close_smtp_servers, initialize_smtp, SmtpListeners};
pub use registry::{evict_smtp_connections, register_smtp_server, unregister_smtp_server};
pub use server::{create_smtp_server, HandshakeErrorMeta, SmtpServer, SmtpServerError};
pub use types::{
    SharedSmtpHandler, SmtpAddress, SmtpArgValue, SmtpAuthMethod, SmtpAuthRequest, SmtpAuthResponse, SmtpEnvelope,
    SmtpHandler, SmtpHookError, SmtpServerOptions, SmtpSession, SmtpSessionState, SmtpTlsSource,
};
