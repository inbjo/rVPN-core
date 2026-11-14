//! Embedded React control panel. The CIDR allowlist and same-origin checks
//! apply to both HTTP and WebSocket requests; configuration never uses CORS.
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use ip_network::IpNetwork;
use serde_json::{json, Value};
use sha1::{Digest, Sha1};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Mutex,
};
use tokio_tungstenite::tungstenite::{
    handshake::server::create_response,
    http::Request,
    protocol::{Role, WebSocketConfig},
    Message,
};

use crate::{
    config::ClientConfig,
    dashboard::{now_unix, render_stats_json, DashboardState},
};

const HTML: &[u8] = include_bytes!("../ui-dist/index.html");
const MAX_MESSAGE: usize = 1024 * 1024;

pub struct ControlPanel {
    path: PathBuf,
    active: std::sync::RwLock<(ClientConfig, String)>,
    writes: Mutex<()>,
    runtime_error: std::sync::Mutex<Option<String>>,
    applier: std::sync::Mutex<Option<tokio::sync::mpsc::Sender<ApplyRequest>>>,
    connections: Arc<tokio::sync::Semaphore>,
}

pub struct ApplyRequest {
    pub config: ClientConfig,
    pub revision: String,
    pub reply: tokio::sync::oneshot::Sender<std::result::Result<(), String>>,
}

fn revision(bytes: &[u8]) -> String {
    hex::encode(Sha1::digest(bytes))
}

fn merge_defaults(defaults: &mut Value, input: Value) {
    match (defaults, input) {
        (Value::Object(base), Value::Object(input)) => {
            for (key, value) in input {
                merge_defaults(base.entry(key).or_insert(Value::Null), value);
            }
        }
        (base, input) => *base = input,
    }
}

fn without_nulls(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .filter(|(_, v)| !v.is_null())
                .map(|(k, v)| (k, without_nulls(v)))
                .collect(),
        ),
        Value::Array(array) => Value::Array(array.into_iter().map(without_nulls).collect()),
        other => other,
    }
}

fn validate(value: &Value) -> Result<ClientConfig> {
    let config: ClientConfig = serde_json::from_value(value.clone()).context("配置字段类型错误")?;
    anyhow::ensure!(
        config.performance.worker_threads > 0,
        "performance.worker_threads 必须大于 0"
    );
    let server = url::Url::parse(&config.server_address).context("server_address 不是有效地址")?;
    anyhow::ensure!(
        matches!(server.scheme(), "ws" | "wss") && server.host_str().is_some(),
        "server_address 必须使用 ws:// 或 wss://"
    );
    for (name, address, enabled) in [
        ("socks5", &config.socks5.listen_address, !config.tun.enabled),
        (
            "http_proxy",
            &config.http_proxy.listen_address,
            config.http_proxy.enabled,
        ),
        (
            "dns_proxy",
            &config.dns_proxy.listen_address,
            config.dns_proxy.enabled,
        ),
        (
            "dashboard",
            &config.dashboard.listen_address,
            config.dashboard.enabled,
        ),
    ] {
        if enabled {
            address
                .parse::<SocketAddr>()
                .with_context(|| format!("{name}.listen_address 必须为 IP:端口"))?;
        }
    }
    if config.dns_proxy.enabled {
        rvpn_split_tunnel::dns_cache::DnsUpstreams::new(&config.dns_proxy.nameservers)?;
    }
    config.socks5.validate_pool()?;
    anyhow::ensure!(config.logging.max_files > 0, "logging.max_files 必须大于 0");
    config
        .logging
        .level
        .parse::<tracing_subscriber::filter::LevelFilter>()
        .context("logging.level 无效")?;
    let mut allow = Vec::new();
    for cidr in &config.dashboard.allow_cidrs {
        allow.push(
            cidr.parse::<IpNetwork>()
                .context("dashboard.allow_cidrs 无效")?,
        );
    }
    anyhow::ensure!(
        !config.dashboard.enabled || !allow.is_empty(),
        "启用面板时 allow_cidrs 不能为空"
    );
    anyhow::ensure!(
        !config.tun.enabled || (config.extra_servers.is_empty() && config.routing.is_empty()),
        "TUN 模式不支持多服务器路由"
    );
    for auth in [
        (
            &config.socks5.auth_enabled,
            &config.socks5.auth_username,
            &config.socks5.auth_password,
        ),
        (
            &config.http_proxy.auth_enabled,
            &config.http_proxy.auth_username,
            &config.http_proxy.auth_password,
        ),
    ] {
        anyhow::ensure!(
            !*auth.0
                || (auth.1.as_ref().is_some_and(|s| !s.is_empty())
                    && auth.2.as_ref().is_some_and(|s| !s.is_empty())),
            "开启代理认证时必须填写用户名和密码"
        );
    }
    let mut names = std::collections::HashSet::new();
    for entry in &config.extra_servers {
        anyhow::ensure!(
            !entry.name.is_empty() && entry.name != "default" && names.insert(&entry.name),
            "服务器名称不能为空、重复或使用 default"
        );
        let url = url::Url::parse(&entry.address)?;
        anyhow::ensure!(
            matches!(url.scheme(), "ws" | "wss") && url.host_str().is_some(),
            "服务器地址必须使用 ws:// 或 wss://"
        );
    }
    for (name, rule) in &config.routing {
        anyhow::ensure!(
            name == "default" || names.contains(name),
            "路由引用了不存在的节点: {name}"
        );
        for ip in &rule.ips {
            anyhow::ensure!(
                ip.parse::<std::net::IpAddr>().is_ok() || ip.parse::<IpNetwork>().is_ok(),
                "无效路由 IP 或 CIDR: {ip}"
            );
        }
    }
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    fn panel(directory: &std::path::Path, extension: &str) -> Arc<ControlPanel> {
        let path = directory.join(format!("client.{extension}"));
        std::fs::write(&path, if extension == "json" { "{}" } else { "" }).unwrap();
        let mut active = ClientConfig::default();
        active.dashboard.enabled = true;
        Arc::new(ControlPanel::new(path, active).unwrap())
    }

    #[tokio::test]
    async fn save_round_trips_toml_and_json_and_rejects_stale_revisions() {
        for extension in ["toml", "json"] {
            let directory = tempfile::tempdir().unwrap();
            let panel = panel(directory.path(), extension);
            let before = panel.configuration().unwrap();
            let mut config = before["config"].clone();
            config["prekey_bundle"] = json!("./bundle.json");
            config["logging"]["directory"] = json!("./logs");
            config["future_option"] = json!("preserve me");
            let request =
                json!({"method":"config.save","revision":before["revision"],"config":config});
            let saved = panel.command(&request).await.unwrap();
            assert!(!saved["restart_required"].as_bool().unwrap());
            assert!(saved["pending_changes"].as_bool().unwrap());
            assert_eq!(saved["config"]["future_option"], "preserve me");
            let loaded = ClientConfig::load(&panel.path).unwrap();
            assert_eq!(
                loaded.prekey_bundle.unwrap(),
                directory.path().join("bundle.json")
            );
            assert_eq!(
                loaded.logging.directory.unwrap(),
                directory.path().join("./logs")
            );
            let bytes = std::fs::read(&panel.path).unwrap();
            assert!(panel
                .command(&request)
                .await
                .unwrap_err()
                .to_string()
                .contains("重新加载"));
            assert_eq!(std::fs::read(&panel.path).unwrap(), bytes);
        }
    }

    #[tokio::test]
    async fn snake_case_split_tunnel_fields_remain_editable() {
        let directory = tempfile::tempdir().unwrap();
        let panel = panel(directory.path(), "toml");
        std::fs::write(
            &panel.path,
            "[split_tunnel]\nblock_ads = true\nbuiltin_bypass_countries = ['CN','HK']\n",
        )
        .unwrap();
        let current = panel.configuration().unwrap();
        assert_eq!(current["config"]["split_tunnel"]["blockAds"], true);
        panel.command(&json!({"method":"config.save", "revision":current["revision"], "config":current["config"]})).await.unwrap();
        assert!(
            ClientConfig::load(&panel.path)
                .unwrap()
                .split_tunnel
                .block_ads
        );
    }

    #[tokio::test]
    async fn invalid_config_never_changes_disk() {
        let directory = tempfile::tempdir().unwrap();
        let panel = panel(directory.path(), "toml");
        let current = panel.configuration().unwrap();
        let mut config = current["config"].clone();
        config["server_address"] = json!("https://invalid.example");
        assert!(panel
            .command(
                &json!({"method":"config.save", "revision":current["revision"], "config":config})
            )
            .await
            .is_err());
        assert_eq!(std::fs::read_to_string(&panel.path).unwrap(), "");
    }

    #[test]
    fn host_validation_blocks_rebinding_and_wrong_ports() {
        let local = "127.0.0.1:9800".parse().unwrap();
        assert!(valid_host("127.0.0.1:9800", local));
        assert!(valid_host("localhost:9800", local));
        assert!(!valid_host("evil.example:9800", local));
        assert!(!valid_host("127.0.0.1:9801", local));
        assert!(!valid_host("evil@127.0.0.1:9800", local));
        assert!(valid_host("[::1]:9800", "[::1]:9800".parse().unwrap()));
    }

    async fn start(panel: Arc<ControlPanel>, allow: Vec<IpNetwork>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(serve(
            listener,
            Arc::new(DashboardState::new()),
            Arc::new(allow),
            panel,
        ));
        address
    }

    async fn rpc(
        ws: &mut tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
        message: Value,
    ) -> Value {
        ws.send(Message::Text(message.to_string())).await.unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let event: Value =
                    serde_json::from_str(ws.next().await.unwrap().unwrap().to_text().unwrap())
                        .unwrap();
                if event["type"] == "response" {
                    return event;
                }
            }
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn websocket_reads_validates_and_saves_over_the_wire() {
        let directory = tempfile::tempdir().unwrap();
        let panel = panel(directory.path(), "toml");
        let address = start(panel.clone(), vec!["127.0.0.0/8".parse().unwrap()]).await;
        let mut request = format!("ws://{address}/ws").into_client_request().unwrap();
        request
            .headers_mut()
            .insert("origin", format!("http://{address}").parse().unwrap());
        let (mut ws, _) = tokio_tungstenite::connect_async(request).await.unwrap();
        let session: Value =
            serde_json::from_str(ws.next().await.unwrap().unwrap().to_text().unwrap()).unwrap();
        assert_eq!(session["type"], "session");
        let valid = rpc(
            &mut ws,
            json!({"id":1,"method":"config.validate","config":session["data"]["config"]}),
        )
        .await;
        assert_eq!(valid["ok"], true);
        let mut config = session["data"]["config"].clone();
        config["socks5"]["listen_address"] = json!("127.0.0.1:2080");
        let saved = rpc(&mut ws, json!({"id":2,"method":"config.save","config":config,"revision":session["data"]["revision"]})).await;
        assert_eq!(saved["ok"], true, "{saved}");
        assert_eq!(
            ClientConfig::load(&panel.path)
                .unwrap()
                .socks5
                .listen_address,
            "127.0.0.1:2080"
        );
    }

    #[tokio::test]
    async fn websocket_rejects_foreign_origin_and_disallowed_peers() {
        let directory = tempfile::tempdir().unwrap();
        let panel = panel(directory.path(), "toml");
        for (origin_allowed, cidr) in [(false, "127.0.0.0/8"), (true, "192.168.0.0/16")] {
            let address = start(panel.clone(), vec![cidr.parse().unwrap()]).await;
            let mut request = format!("ws://{address}/ws").into_client_request().unwrap();
            request.headers_mut().insert(
                "origin",
                if origin_allowed {
                    format!("http://{address}")
                } else {
                    "https://evil.example".into()
                }
                .parse()
                .unwrap(),
            );
            let error = tokio_tungstenite::connect_async(request).await.unwrap_err();
            match error {
                tokio_tungstenite::tungstenite::Error::Http(response) => {
                    assert_eq!(response.status(), 403)
                }
                other => panic!("{other}"),
            }
        }
    }

    #[tokio::test]
    async fn embedded_page_and_head_work_without_external_assets() {
        let directory = tempfile::tempdir().unwrap();
        let address = start(
            panel(directory.path(), "toml"),
            vec!["127.0.0.0/8".parse().unwrap()],
        )
        .await;
        for method in ["GET", "HEAD"] {
            let mut socket = TcpStream::connect(address).await.unwrap();
            socket
                .write_all(format!("{method} / HTTP/1.1\r\nHost: {address}\r\n\r\n").as_bytes())
                .await
                .unwrap();
            let mut bytes = Vec::new();
            socket.read_to_end(&mut bytes).await.unwrap();
            let text = String::from_utf8(bytes).unwrap();
            assert!(text.starts_with("HTTP/1.1 200 OK"));
            assert!(text.contains("frame-ancestors 'none'"));
            assert_eq!(text.contains("<div id=\"root\">"), method == "GET");
        }
    }
}

impl ControlPanel {
    pub fn attach_applier(&self, sender: tokio::sync::mpsc::Sender<ApplyRequest>) {
        *self.applier.lock().unwrap_or_else(|e| e.into_inner()) = Some(sender);
    }

    pub fn set_active(&self, config: ClientConfig, revision: String) {
        *self.active.write().unwrap_or_else(|e| e.into_inner()) = (config, revision);
        *self.runtime_error.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    fn peer_allowed(&self, peer: SocketAddr) -> bool {
        let active = self.active.read().unwrap_or_else(|e| e.into_inner());
        active.0.dashboard.enabled
            && active
                .0
                .dashboard
                .allow_cidrs
                .iter()
                .filter_map(|cidr| cidr.parse::<IpNetwork>().ok())
                .any(|net| net.contains(peer.ip()))
    }
    pub fn set_runtime_error(&self, error: String) {
        *self.runtime_error.lock().unwrap_or_else(|e| e.into_inner()) = Some(error);
    }

    fn stats(&self, state: &DashboardState) -> Result<Value> {
        let mut stats: Value = serde_json::from_str(&render_stats_json(state, now_unix()))?;
        stats["runtime_error"] =
            json!(*self.runtime_error.lock().unwrap_or_else(|e| e.into_inner()));
        Ok(stats)
    }

    pub fn new(path: PathBuf, active: ClientConfig) -> Result<Self> {
        let bytes = std::fs::read(&path).context("无法读取控制面板配置文件")?;
        Ok(Self {
            path,
            active: std::sync::RwLock::new((active, revision(&bytes))),
            writes: Mutex::new(()),
            runtime_error: std::sync::Mutex::new(None),
            applier: std::sync::Mutex::new(None),
            connections: Arc::new(tokio::sync::Semaphore::new(32)),
        })
    }

    fn read(&self) -> Result<(Value, String)> {
        let bytes = std::fs::read(&self.path)?;
        let input: Value = if self.path.extension().is_some_and(|ext| ext == "json") {
            serde_json::from_slice(&bytes)?
        } else {
            serde_json::to_value(toml::from_str::<toml::Value>(std::str::from_utf8(&bytes)?)?)?
        };
        // Normalize serde aliases (split_tunnel accepts both snake_case and
        // camelCase) before merging, avoiding duplicate fields on save.
        let parsed: ClientConfig = serde_json::from_value(input.clone())?;
        let mut defaults = serde_json::to_value(parsed)?;
        let mut input = input;
        if let Some(Value::Object(split)) = input.get_mut("split_tunnel") {
            let canonical = defaults["split_tunnel"]
                .as_object()
                .context("Invalid split tunnel config")?;
            let old = std::mem::take(split);
            for (name, value) in old {
                let mut words = name.split('_');
                let mut camel = words.next().unwrap_or("").to_string();
                for word in words {
                    let mut chars = word.chars();
                    if let Some(first) = chars.next() {
                        camel.extend(first.to_uppercase());
                        camel.extend(chars);
                    }
                }
                split.insert(
                    if canonical.contains_key(&camel) {
                        camel
                    } else {
                        name
                    },
                    value,
                );
            }
        }
        merge_defaults(&mut defaults, input);
        Ok((defaults, revision(&bytes)))
    }

    pub fn configuration(&self) -> Result<Value> {
        let (config, revision) = self.read()?;
        let active = self.active.read().unwrap_or_else(|e| e.into_inner());
        let pending = revision != active.1;
        let running = &active.0;
        Ok(
            json!({"config":config, "revision":revision, "path":self.path,
            "restart_required":false, "pending_changes":pending,
            "runtime":{"server_address":running.server_address,"tun":running.tun.enabled,
                "socks5":running.socks5.listen_address,"http_proxy":running.http_proxy.listen_address,
                "dns_proxy":running.dns_proxy.listen_address,"dashboard":running.dashboard}, "version":env!("CARGO_PKG_VERSION")}),
        )
    }

    async fn command(&self, request: &Value) -> Result<Value> {
        match request["method"].as_str().unwrap_or("") {
            "config.get" => self.configuration(),
            "config.validate" => {
                validate(&request["config"])?;
                Ok(json!({"valid":true}))
            }
            "config.save" => {
                validate(&request["config"])?;
                let _lock = self.writes.lock().await;
                let (_, current) = self.read()?;
                anyhow::ensure!(
                    request["revision"].as_str() == Some(&current),
                    "配置已被其他页面或程序修改，请重新加载后再保存"
                );
                let body = if self.path.extension().is_some_and(|ext| ext == "json") {
                    serde_json::to_string_pretty(&request["config"])?
                } else {
                    toml::to_string_pretty(&without_nulls(request["config"].clone()))?
                };
                let previous = std::fs::read(&self.path)?;
                // Preserve file permissions and replace atomically on every OS.
                let parent = self.path.parent().context("配置文件没有父目录")?;
                let mut file = tempfile::NamedTempFile::new_in(parent)?;
                if let Ok(metadata) = std::fs::metadata(&self.path) {
                    file.as_file().set_permissions(metadata.permissions())?;
                }
                use std::io::Write;
                file.write_all(body.as_bytes())?;
                file.as_file().sync_all()?;
                file.persist(&self.path).context("无法保存配置文件")?;
                let applier = self
                    .applier
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone();
                if let Some(applier) = applier {
                    let result = async {
                        let config = ClientConfig::load(&self.path)?;
                        let (reply, receiver) = tokio::sync::oneshot::channel();
                        applier
                            .send(ApplyRequest {
                                config,
                                revision: revision(body.as_bytes()),
                                reply,
                            })
                            .await
                            .map_err(|_| anyhow::anyhow!("配置应用器已停止"))?;
                        // The supervisor always replies, including worker failures.
                        receiver
                            .await
                            .context("配置应用器意外停止")?
                            .map_err(anyhow::Error::msg)
                    }
                    .await;
                    if let Err(error) = result {
                        let mut rollback = tempfile::NamedTempFile::new_in(parent)?;
                        rollback
                            .as_file()
                            .set_permissions(std::fs::metadata(&self.path)?.permissions())?;
                        rollback.write_all(&previous)?;
                        rollback.as_file().sync_all()?;
                        rollback.persist(&self.path).context("无法恢复原配置文件")?;
                        anyhow::bail!("配置应用失败，已恢复原配置文件：{error:#}");
                    }
                }
                tracing::info!("Control panel saved configuration: {}", self.path.display());
                self.configuration()
            }
            "ping" => Ok(json!({"pong":true})),
            _ => anyhow::bail!("不支持的操作"),
        }
    }
}

pub async fn serve(
    listener: TcpListener,
    state: Arc<DashboardState>,
    allow: Arc<Vec<IpNetwork>>,
    panel: Arc<ControlPanel>,
) {
    // Bound concurrent sessions, including slow HTTP readers.
    let limit = panel.connections.clone();
    loop {
        match listener.accept().await {
            Ok((socket, peer)) => {
                let Ok(permit) = Arc::clone(&limit).try_acquire_owned() else {
                    continue;
                };
                let (state, allow, panel) = (state.clone(), allow.clone(), panel.clone());
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(error) = connection(socket, peer, state, allow, panel).await {
                        tracing::debug!("Control panel connection: {error:#}");
                    }
                });
            }
            Err(error) => {
                tracing::warn!("Control panel accept: {error}");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

fn valid_host(host: &str, local: SocketAddr) -> bool {
    let Ok(url) = url::Url::parse(&format!("http://{host}")) else {
        return false;
    };
    if url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || url.port_or_known_default() != Some(local.port())
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return false;
    }
    let Some(name) = url.host_str() else {
        return false;
    };
    let name = name.trim_matches(['[', ']']);
    (name == "localhost" && local.ip().is_loopback())
        || name
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip == local.ip())
}

async fn response(
    socket: &mut TcpStream,
    status: &str,
    mime: &str,
    body: &[u8],
    head: bool,
) -> Result<()> {
    // The production bundle is a single local file; no CDN or external calls.
    // Safari does not consistently map connect-src 'self' to the ws scheme.
    let local = socket.local_addr()?;
    let websocket_sources = if local.ip().is_loopback() {
        format!("ws://{local} ws://localhost:{}", local.port())
    } else {
        format!("ws://{local}")
    };
    let header = format!("HTTP/1.1 {status}\r\nContent-Type: {mime}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; font-src data:; img-src data:; connect-src 'self' {websocket_sources}; frame-ancestors 'none'; base-uri 'none'\r\n\r\n", body.len());
    socket.write_all(header.as_bytes()).await?;
    if !head {
        socket.write_all(body).await?;
    }
    Ok(())
}

async fn connection(
    mut socket: TcpStream,
    peer: SocketAddr,
    state: Arc<DashboardState>,
    allow: Arc<Vec<IpNetwork>>,
    panel: Arc<ControlPanel>,
) -> Result<()> {
    let mut bytes = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let mut chunk = [0u8; 1024];
            let count = socket.read(&mut chunk).await?;
            if count == 0 {
                return Err(anyhow::anyhow!("Incomplete HTTP request"));
            }
            bytes.extend_from_slice(&chunk[..count]);
            anyhow::ensure!(bytes.len() <= 8192, "HTTP headers too large");
            if bytes.windows(4).any(|s| s == b"\r\n\r\n") {
                return Ok(());
            }
        }
    })
    .await??;
    let live_policy = panel
        .applier
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .is_some();
    if !(if live_policy {
        panel.peer_allowed(peer)
    } else {
        allow.iter().any(|net| net.contains(peer.ip()))
    }) {
        return response(
            &mut socket,
            "403 Forbidden",
            "text/plain",
            b"forbidden",
            false,
        )
        .await;
    }
    let end = bytes.windows(4).position(|s| s == b"\r\n\r\n").unwrap() + 4;
    let text = std::str::from_utf8(&bytes[..end])?;
    let mut lines = text.split("\r\n");
    let first: Vec<_> = lines.next().unwrap_or("").split_whitespace().collect();
    anyhow::ensure!(first.len() == 3, "Invalid HTTP request");
    let (method, path) = (first[0], first[1]);
    let mut headers = std::collections::HashMap::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').context("Invalid HTTP header")?;
        anyhow::ensure!(
            headers
                .insert(name.to_ascii_lowercase(), value.trim())
                .is_none(),
            "Duplicate HTTP header"
        );
    }
    let host = headers.get("host").copied().unwrap_or("");
    if !valid_host(host, socket.local_addr()?) {
        return response(
            &mut socket,
            "403 Forbidden",
            "text/plain",
            b"invalid host",
            false,
        )
        .await;
    }
    if path == "/ws" && method == "GET" {
        let expected_origin = format!("http://{host}");
        if headers.get("origin").copied() != Some(expected_origin.as_str()) {
            return response(
                &mut socket,
                "403 Forbidden",
                "text/plain",
                b"invalid origin",
                false,
            )
            .await;
        }
        let mut builder = Request::builder().method("GET").uri(path);
        for (name, value) in &headers {
            builder = builder.header(name, *value);
        }
        let reply = create_response(&builder.body(())?)?;
        let mut header = String::from("HTTP/1.1 101 Switching Protocols\r\n");
        for (name, value) in reply.headers() {
            header.push_str(&format!("{name}: {}\r\n", value.to_str()?));
        }
        header.push_str("\r\n");
        socket.write_all(header.as_bytes()).await?;
        let config = WebSocketConfig {
            max_message_size: Some(MAX_MESSAGE),
            max_frame_size: Some(MAX_MESSAGE),
            ..Default::default()
        };
        let mut ws = tokio_tungstenite::WebSocketStream::from_partially_read(
            socket,
            bytes[end..].to_vec(),
            Role::Server,
            Some(config),
        )
        .await;
        let session = json!({"type":"session","data":panel.configuration()?});
        ws.send(Message::Text(session.to_string())).await?;
        let mut tick = tokio::time::interval(Duration::from_secs(2));
        let mut last_configuration = panel.configuration()?;
        loop {
            if !panel.peer_allowed(peer) {
                ws.close(None).await?;
                break;
            }
            let outgoing = tokio::select! {
                _ = tick.tick() => {
                    let configuration = panel.configuration()?;
                    if configuration != last_configuration {
                        last_configuration = configuration.clone();
                        ws.send(Message::Text(json!({"type":"configuration","data":configuration}).to_string())).await?;
                    }
                    Some(json!({"type":"stats","data":panel.stats(&state)?}))
                },
                incoming = ws.next() => match incoming {
                    Some(Ok(Message::Text(text))) => {
                        if live_policy && !panel.peer_allowed(peer) { ws.close(None).await?; break; }
                        match serde_json::from_str::<Value>(&text) {
                            Ok(request) => {
                                let result = panel.command(&request).await;
                                Some(match result {
                                    Ok(mut data) => {
                                        if request["method"] == "config.save" { data["access_allowed"] = json!(panel.peer_allowed(peer)); }
                                        json!({"type":"response","id":request["id"],"ok":true,"data":data})
                                    },
                                    Err(error) => json!({"type":"response","id":request["id"],"ok":false,"error":format!("{error:#}")}),
                                })
                            }
                            Err(_) => Some(json!({"type":"response","ok":false,"error":"消息必须为 JSON"})),
                        }
                    }
                    Some(Ok(Message::Ping(payload))) => { ws.send(Message::Pong(payload)).await?; None }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(error)) => return Err(error.into()),
                    _ => None,
                }
            };
            if let Some(outgoing) = outgoing {
                tokio::time::timeout(
                    Duration::from_secs(10),
                    ws.send(Message::Text(outgoing.to_string())),
                )
                .await??;
            }
        }
        return Ok(());
    }
    let head = method == "HEAD";
    match (method, path) {
        ("GET" | "HEAD", "/" | "/index.html") => {
            response(
                &mut socket,
                "200 OK",
                "text/html; charset=utf-8",
                HTML,
                head,
            )
            .await
        }
        ("GET" | "HEAD", "/api/stats.json") => {
            response(
                &mut socket,
                "200 OK",
                "application/json",
                render_stats_json(&state, now_unix()).as_bytes(),
                head,
            )
            .await
        }
        _ => {
            response(
                &mut socket,
                "404 Not Found",
                "text/plain",
                b"not found",
                head,
            )
            .await
        }
    }
}
