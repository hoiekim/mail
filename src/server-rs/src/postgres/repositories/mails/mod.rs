//! The `mails` table and everything keyed on it.

pub mod core;
pub mod core_query;
pub mod counters;
pub mod http;
pub mod http_query;
pub mod imap;
pub mod imap_query;
pub mod inflight;
pub mod mapping_decisions;
pub mod pivot_decisions;
pub mod set_flags_query;
pub mod thread;
pub mod views;
