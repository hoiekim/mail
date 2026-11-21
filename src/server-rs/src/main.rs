use mail_server::postgres::initialize::{
    boot_maintenance, initialize_admin_read_only_user, initialize_admin_user, initialize_postgres,
};
use mail_server::postgres::pool;
use tokio_util::sync::CancellationToken;

async fn start() -> anyhow::Result<()> {
    initialize_postgres().await?;
    initialize_admin_user().await?;
    initialize_admin_read_only_user().await?;

    let maintenance_cancel = CancellationToken::new();
    let maintenance = tokio::spawn(boot_maintenance(maintenance_cancel.clone()));

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let signal = tokio::select! {
        _ = sigterm.recv() => "SIGTERM",
        _ = tokio::signal::ctrl_c() => "SIGINT",
    };
    println!("{signal} received — shutting down gracefully");

    maintenance_cancel.cancel();
    let _ = maintenance.await;
    println!("Boot maintenance stopped");
    pool().end();
    println!("Database pool closed");
    Ok(())
}

#[tokio::main]
async fn main() {
    if let Err(error) = start().await {
        eprintln!("Fatal error during startup: {error}");
        std::process::exit(1);
    }
}
