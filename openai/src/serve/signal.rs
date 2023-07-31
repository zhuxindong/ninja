use axum_server::Handle;
use std::time::Duration;
#[cfg(target_family = "unix")]
use tokio::signal::unix::{signal, SignalKind};
use tokio::time::sleep;

use crate::info;

pub(super) async fn graceful_shutdown(handle: Handle) {
    #[cfg(target_family = "windows")]
    {
        tokio::signal::ctrl_c()
            .await
            .expect("Ctrl+C signal hanlde error");
        sending_graceful_shutdown_signal(handle).await;
    }

    #[cfg(target_family = "unix")]
    {
        let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM signal hanlde error");
        let mut sigquit = signal(SignalKind::quit()).expect("SIGQUIT signal hanlde error");
        let mut sigchld = signal(SignalKind::child()).expect("SIGCHLD signal hanlde error");
        let mut sighup = signal(SignalKind::hangup()).expect("SIGHUP signal hanlde error");
        tokio::select! {
            _ = sigterm.recv() => {
                sending_graceful_shutdown_signal(handle).await;
            },
            _ = sigquit.recv() => {
                sending_graceful_shutdown_signal(handle).await;
            },
            _ = sigchld.recv() => {
                sending_graceful_shutdown_signal(handle).await;
            },
            _ = sighup.recv() => {
                sending_graceful_shutdown_signal(handle).await;
            },
            _ = tokio::signal::ctrl_c() => {
                sending_graceful_shutdown_signal(handle).await;
            }
        };
    }
}

async fn sending_graceful_shutdown_signal(handle: Handle) {
    info!("Sending graceful shutdown signal");

    // Signal the server to shutdown using Handle.
    handle.graceful_shutdown(Some(Duration::from_secs(30)));

    // Print alive connection count every second.
    loop {
        sleep(Duration::from_secs(1)).await;
        info!("Alive connections: {}", handle.connection_count());
    }
}
