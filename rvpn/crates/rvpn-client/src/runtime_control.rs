//! The panel lives on the process runtime; every VPN generation owns a separate
//! runtime. Dropping that runtime cancels all nested relay/DNS/pool tasks before
//! listeners are reused, including tasks spawned by library components.
use std::{path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use tokio::sync::{mpsc, oneshot, watch};

use crate::{
    config::ClientConfig,
    control_panel::{ApplyRequest, ControlPanel},
    dashboard,
};

#[derive(Clone, Default)]
pub struct Overrides {
    pub server: Option<String>,
    pub bundle: Option<PathBuf>,
    pub fingerprint: Option<String>,
    pub dashboard_listen: Option<String>,
}

impl Overrides {
    pub fn apply(&self, config: &mut ClientConfig) {
        if let Some(server) = &self.server {
            config.server_address = server.clone();
        }
        if let Some(bundle) = &self.bundle {
            config.prekey_bundle = Some(bundle.clone());
        }
        if let Some(fingerprint) = &self.fingerprint {
            if let Some(value) = rvpn_tls::fingerprint_from_str(fingerprint) {
                config.tls_fingerprint = value;
            }
        }
        if let Some(address) = &self.dashboard_listen {
            config.dashboard.enabled = true;
            config.dashboard.listen_address = address.clone();
        }
    }
}

struct Worker {
    stop: watch::Sender<bool>,
    ready: oneshot::Receiver<()>,
    done: oneshot::Receiver<std::result::Result<(), String>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Worker {
    fn start(config: ClientConfig) -> Result<Self> {
        anyhow::ensure!(
            config.performance.worker_threads > 0,
            "performance.worker_threads must be greater than zero"
        );
        let (stop, mut stopped) = watch::channel(false);
        let (ready_tx, ready) = oneshot::channel();
        let (done_tx, done) = oneshot::channel();
        let thread = std::thread::Builder::new().name("rvpn-network".into()).spawn(move || {
            let result = (|| -> Result<()> {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(config.performance.worker_threads).enable_all().build()?;
                let result = runtime.block_on(async {
                    tokio::select! {
                        biased;
                        _ = stopped.changed() => Ok(()),
                        result = async {
                            rvpn_core::crypto::key_files::ensure_identity(&config.identity_key_file, "Client")?;
                            crate::websocket::configure_endpoint_dns(&config)?;
                            if config.tun.enabled {
                                // Validate key/bundle files before acknowledging a TUN generation.
                                crate::server_pool::ServerPool::from_config(&config).await?;
                                crate::run_tun(config, ready_tx).await
                            } else { crate::run_socks5(config, ready_tx).await }
                        } => result,
                    }
                });
                // Cancellation drops the root future (including the TUN handle
                // and PID guard); shutdown drains/aborts every spawned child.
                runtime.shutdown_timeout(Duration::from_secs(2));
                result
            })().map_err(|error| format!("{error:#}"));
            let _ = done_tx.send(result);
        }).context("Failed to start network runtime")?;
        Ok(Self {
            stop,
            ready,
            done,
            thread: Some(thread),
        })
    }

    async fn wait_ready(&mut self) -> Result<()> {
        tokio::select! {
            result = &mut self.ready => match result {
                Ok(()) => Ok(()),
                Err(_) => Err(anyhow::anyhow!((&mut self.done).await.unwrap_or_else(|_| Err("Network worker exited unexpectedly".into())).err().unwrap_or_else(|| "Network stopped before readiness".into()))),
            },
            result = &mut self.done => Err(anyhow::anyhow!(result.unwrap_or_else(|_| Err("Network worker exited unexpectedly".into())).err().unwrap_or_else(|| "Network stopped before readiness".into()))),
        }
    }

    async fn stop(mut self) {
        let _ = self.stop.send(true);
        if let Some(thread) = self.thread.take() {
            if let Err(error) = tokio::task::spawn_blocking(move || thread.join()).await {
                tracing::warn!("Network runtime join: {error}");
            }
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
    }
}

struct PanelListener {
    task: tokio::task::JoinHandle<()>,
    address: String,
}

impl PanelListener {
    async fn stop(mut self) {
        self.task.abort();
        let _ = (&mut self.task).await;
    }
}

impl Drop for PanelListener {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn bind_panel(config: &ClientConfig) -> Result<Option<tokio::net::TcpListener>> {
    if !config.dashboard.enabled {
        return Ok(None);
    }
    let listener = tokio::net::TcpListener::bind(&config.dashboard.listen_address)
        .await
        .with_context(|| {
            format!(
                "Failed to bind control panel to {}",
                config.dashboard.listen_address
            )
        })?;
    Ok(Some(listener))
}

fn serve_panel(
    listener: tokio::net::TcpListener,
    config: &ClientConfig,
    state: Arc<dashboard::DashboardState>,
    panel: Arc<ControlPanel>,
) -> PanelListener {
    let allow = Arc::new(
        config
            .dashboard
            .allow_cidrs
            .iter()
            .filter_map(|cidr| cidr.parse().ok())
            .collect(),
    );
    let local = listener.local_addr().ok();
    if let Some(local) = local {
        println!("Web 控制面板已启动，请在浏览器中访问：{}", panel_url(local));
        tracing::debug!("Control panel listening: {}", panel_url(local));
        if local.ip().is_unspecified() {
            println!("其他设备请使用本机 IP 和端口 {} 访问（受 allow_cidrs 限制）", local.port());
        }
    }
    PanelListener {
        task: tokio::spawn(crate::control_panel::serve(listener, state, allow, panel)),
        address: config.dashboard.listen_address.clone(),
    }
}

fn panel_url(mut address: std::net::SocketAddr) -> String {
    if address.ip().is_unspecified() {
        address.set_ip(if address.is_ipv4() {
            std::net::Ipv4Addr::LOCALHOST.into()
        } else {
            std::net::Ipv6Addr::LOCALHOST.into()
        });
    }
    format!("http://{address}/")
}

#[cfg(test)]
mod tests {
    use super::panel_url;

    #[test]
    fn panel_startup_urls_use_actual_ports_and_reachable_loopback_hosts() {
        for (listen, url) in [
            ("127.0.0.1:9800", "http://127.0.0.1:9800/"),
            ("0.0.0.0:19800", "http://127.0.0.1:19800/"),
            ("[::]:19801", "http://[::1]:19801/"),
            ("192.168.1.2:9800", "http://192.168.1.2:9800/"),
        ] {
            assert_eq!(panel_url(listen.parse().unwrap()), url);
        }
    }
}

async fn start_ready(config: ClientConfig) -> Result<Worker> {
    let mut worker = Worker::start(config)?;
    match tokio::time::timeout(Duration::from_secs(15), worker.wait_ready()).await {
        Ok(Ok(())) => Ok(worker),
        failure => {
            worker.stop().await;
            match failure {
                Ok(Err(error)) => Err(error),
                _ => anyhow::bail!("Network startup timed out"),
            }
        }
    }
}

pub async fn run(
    mut config: ClientConfig,
    path: PathBuf,
    overrides: Overrides,
    logging: Arc<rvpn_logging::ReloadableLogging>,
) -> Result<()> {
    let panel = Arc::new(ControlPanel::new(path, config.clone())?);
    let (sender, mut requests) = mpsc::channel::<ApplyRequest>(8);
    panel.attach_applier(sender);
    let state = dashboard::global().unwrap_or_else(|| Arc::new(dashboard::DashboardState::new()));
    if config.dashboard.enabled {
        dashboard::init(state.clone());
    }
    let sampler = tokio::spawn(dashboard::run_sampler(state.clone()));
    let _sampler_guard = crate::OnDrop::new(move || sampler.abort());
    let mut listener = match bind_panel(&config).await {
        Ok(Some(socket)) => Some(serve_panel(socket, &config, state.clone(), panel.clone())),
        Ok(None) => {
            tracing::info!("Web 控制面板未启用；可在配置文件 [dashboard] 中设置 enabled = true");
            None
        }
        Err(error) => {
            tracing::warn!("{error:#}");
            None
        }
    };
    let mut worker = match start_ready(config.clone()).await {
        Ok(worker) => Some(worker),
        Err(error) => {
            if listener.is_none() {
                return Err(error);
            }
            tracing::error!("VPN stopped; control panel remains available: {error:#}");
            panel.set_runtime_error(format!("{error:#}"));
            None
        }
    };
    let (shutdown, mut stopped) = watch::channel(false);
    let signals = tokio::spawn(crate::handle_signals(shutdown));
    let _signal_guard = crate::OnDrop::new(move || signals.abort());
    loop {
        tokio::select! {
            _ = stopped.changed() => break,
            completed = async { match worker.as_mut() { Some(worker) => (&mut worker.done).await, None => std::future::pending().await } } => {
                if let Some(old) = worker.take() { old.stop().await; }
                let error = match completed { Ok(Err(error)) => error, _ => "VPN network runtime stopped".into() };
                if listener.is_none() { anyhow::bail!(error) }
                tracing::error!("{error}");
                panel.set_runtime_error(error);
            }
            Some(mut request) = requests.recv() => {
                overrides.apply(&mut request.config);
                let candidate = request.config;
                let outcome = async {
                    // Prepare fallible process resources before interrupting traffic.
                    let prepared_log = logging.prepare(&candidate.logging)?;
                    let same_address = candidate.dashboard.enabled && listener.as_ref().is_some_and(|old| old.address == candidate.dashboard.listen_address);
                    // Wildcard/loopback changes on the same port overlap. Stop
                    // only the accept loop; accepted WebSockets stay alive to
                    // receive the save result even while the listener moves.
                    let overlaps = !same_address && candidate.dashboard.enabled && listener.as_ref().is_some_and(|old| {
                        match (old.address.parse::<std::net::SocketAddr>(), candidate.dashboard.listen_address.parse::<std::net::SocketAddr>()) {
                            (Ok(old),Ok(new)) => old.port() == new.port(), _ => false,
                        }
                    });
                    if overlaps { if let Some(old) = listener.take() { old.stop().await; } }
                    let prepared_listener = if same_address { None } else { bind_panel(&candidate).await? };
                    let mut old_network = serde_json::to_value(&config)?;
                    let mut new_network = serde_json::to_value(&candidate)?;
                    for value in [&mut old_network, &mut new_network] { value.as_object_mut().unwrap().remove("logging"); value.as_object_mut().unwrap().remove("dashboard"); }
                    let rebuild = old_network != new_network || worker.is_none();
                    if rebuild {
                        if let Some(old) = worker.take() { old.stop().await; }
                        match start_ready(candidate.clone()).await {
                            Ok(new_worker) => worker = Some(new_worker),
                            Err(error) => {
                                match start_ready(config.clone()).await {
                                    Ok(restored) => worker = Some(restored),
                                    Err(restore) => panel.set_runtime_error(format!("应用失败：{error:#}；恢复网络失败：{restore:#}")),
                                }
                                return Err(error.context("网络未切换到新配置，已尝试恢复原运行配置"));
                            }
                        }
                    }
                    logging.apply(prepared_log)?;
                    if !same_address {
                        if let Some(old) = listener.take() { old.stop().await; }
                        listener = prepared_listener.map(|socket| serve_panel(socket, &candidate, state.clone(), panel.clone()));
                    }
                    config = candidate;
                    panel.set_active(config.clone(), request.revision);
                    tracing::info!("Client configuration applied without process restart (network rebuilt: {rebuild})");
                    Ok::<(),anyhow::Error>(())
                }.await;
                if outcome.is_err() && listener.is_none() && config.dashboard.enabled {
                    // A same-port panel rebind or later network failure may
                    // have released the accept socket. Restore the old address.
                    match bind_panel(&config).await {
                        Ok(Some(socket)) => listener = Some(serve_panel(socket, &config, state.clone(), panel.clone())),
                        Err(error) => { tracing::error!("Could not restore control panel listener: {error:#}"); panel.set_runtime_error(format!("控制面板监听恢复失败：{error:#}")); }
                        _ => {},
                    }
                }
                let _ = request.reply.send(outcome.map_err(|error| format!("{error:#}")));
            }
        }
    }
    if let Some(worker) = worker {
        worker.stop().await;
    }
    Ok(())
}
