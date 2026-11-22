use std::time::Duration;

use mail_server::alarm::send_alarm;
use mail_server::postgres::initialize::{
    boot_maintenance, initialize_admin_read_only_user, initialize_admin_user, initialize_postgres,
};
use mail_server::postgres::pool;
use mail_server::{env, http, push, smtp};
use tokio_util::sync::CancellationToken;

/// Ceiling on the startup-failure alarm, so a wedged webhook cannot hold the exit.
const CRASH_ALARM_TIMEOUT: Duration = Duration::from_secs(5);

/// Stands in for a mail listener that is not ported yet: accepts and closes,
/// completing a TLS handshake first on an implicit-TLS port.
async fn placeholder_listener(name: &str, default: u16, implicit_tls: bool) -> anyhow::Result<()> {
    let port = env::port(name, default).unwrap_or(default);
    let listener = mail_server::net::bind_all(port).await?;
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { continue };
            if implicit_tls {
                tokio::spawn(async move {
                    if let Ok(acceptor) = mail_server::tls::acceptor() {
                        let _ = acceptor.accept(stream).await;
                    }
                });
            }
        }
    });
    Ok(())
}

async fn start() -> anyhow::Result<()> {
    // Settings only: a misconfiguration stops the start here, before anything
    // binds, and the provider is first contacted by the first sign-in.
    mail_server::sso::initialize_sso()?;
    initialize_postgres().await?;
    initialize_admin_user().await?;
    initialize_admin_read_only_user().await?;
    push::init_push()?;
    let http_server = http::initialize_http().await?;
    // Sweeps `attachments/.incoming`, then opens SMTP_PORT, and with a
    // certificate SMTPS_PORT and SMTP_SUBMISSION_PORT.
    let smtp_servers = smtp::initialize_mail_smtp().await?;
    placeholder_listener("IMAP_PORT", 143, false).await?;
    if mail_server::tls::is_tls_available() {
        placeholder_listener("IMAP_TLS_PORT", 993, true).await?;
    }
    push::clean_subscriptions();

    // Index builds and the search-vector reindex scale with the size of
    // `mails`, so they run after the listeners are bound rather than in
    // front of them.
    let maintenance_cancel = CancellationToken::new();
    let maintenance = tokio::spawn(boot_maintenance(maintenance_cancel.clone()));

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let signal = tokio::select! {
        _ = sigterm.recv() => "SIGTERM",
        _ = tokio::signal::ctrl_c() => "SIGINT",
    };
    println!("{signal} received — shutting down gracefully");

    // First: cancelling an in-flight index build is a round trip on another
    // connection, so it overlaps the server closes below.
    maintenance_cancel.cancel();

    http_server.stop().await;
    println!("HTTP server closed");

    // In-flight DATA gets SMTP_CLOSE_TIMEOUT_MS before the rest are answered
    // 421; this runs at the same time as the IMAP close.
    let close_smtp = async {
        smtp::close_smtp_servers(&smtp_servers).await;
        println!("SMTP servers closed");
    };
    close_smtp.await;

    let _ = maintenance.await;
    println!("Boot maintenance stopped");

    pool().end();
    println!("Database pool closed");
    Ok(())
}

fn main() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        // Deeply nested client JSON is parsed and dropped recursively.
        .thread_stack_size(16 * 1024 * 1024)
        .build()
        .expect("the runtime starts");
    let outcome = runtime.block_on(async {
        match start().await {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("Fatal error during startup: {error}");
                let detail = format!("**Message:** {error}\n```\n{error:?}\n```");
                let _ = tokio::time::timeout(CRASH_ALARM_TIMEOUT, send_alarm("Startup Failed", &detail, None)).await;
                1
            }
        }
    });
    // Background tasks hold timers that would keep the runtime alive.
    runtime.shutdown_background();
    std::process::exit(outcome);
}
