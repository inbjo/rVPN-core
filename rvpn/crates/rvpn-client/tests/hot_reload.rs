//! Real-process reload tests: no remote VPN server or system service is needed.
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::{
    net::SocketAddr,
    process::{Child, Command, Stdio},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_tungstenite::{
    tungstenite::{client::IntoClientRequest, Message},
    MaybeTlsStream, WebSocketStream,
};

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn address() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

async fn connect(address: SocketAddr) -> (Socket, Value) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let mut request = format!("ws://{address}/ws").into_client_request().unwrap();
            request
                .headers_mut()
                .insert("origin", format!("http://{address}").parse().unwrap());
            if let Ok((mut socket, _)) = tokio_tungstenite::connect_async(request).await {
                let initial: Value =
                    serde_json::from_str(socket.next().await.unwrap().unwrap().to_text().unwrap())
                        .unwrap();
                assert_eq!(initial["type"], "session");
                return (socket, initial["data"].clone());
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    })
    .await
    .unwrap()
}

async fn rpc(socket: &mut Socket, value: Value) -> Value {
    socket.send(Message::Text(value.to_string())).await.unwrap();
    tokio::time::timeout(Duration::from_secs(40), async {
        loop {
            let incoming = socket.next().await.unwrap().unwrap();
            if let Message::Text(text) = incoming {
                let result: Value = serde_json::from_str(&text).unwrap();
                if result["type"] == "response" {
                    return result;
                }
            }
        }
    })
    .await
    .unwrap()
}

async fn save(socket: &mut Socket, current: &mut Value, config: Value) -> Value {
    let result = rpc(
        socket,
        json!({"id":1,"method":"config.save","revision":current["revision"],"config":config}),
    )
    .await;
    if result["ok"] == true {
        *current = result["data"].clone();
    }
    result
}

fn fixture(missing_bundle: bool) -> (tempfile::TempDir, Process, SocketAddr, SocketAddr) {
    fixture_logging(missing_bundle, false)
}

fn fixture_logging(
    missing_bundle: bool,
    file_logging: bool,
) -> (tempfile::TempDir, Process, SocketAddr, SocketAddr) {
    let directory = tempfile::tempdir().unwrap();
    let binary = directory.path().join(
        std::path::Path::new(env!("CARGO_BIN_EXE_rvpn"))
            .file_name()
            .unwrap(),
    );
    std::fs::copy(env!("CARGO_BIN_EXE_rvpn"), &binary).unwrap();
    let server =
        rvpn_core::crypto::X3DHResponder::from_identity(rvpn_core::crypto::IdentityKey::generate());
    std::fs::write(
        directory.path().join("bundle.json"),
        serde_json::to_vec(&server.get_public_bundle()).unwrap(),
    )
    .unwrap();
    let mut config = rvpn_client::config::ClientConfig::default();
    let panel = address();
    let socks = address();
    config.server_address = "wss://127.0.0.1:9/api/v1/ws".into();
    config.data_dir = "./data".into();
    config.identity_key_file = "./identity.key".into();
    config.prekey_bundle = Some(
        if missing_bundle {
            "./missing.json"
        } else {
            "./bundle.json"
        }
        .into(),
    );
    config.dashboard.enabled = true;
    config.dashboard.listen_address = panel.to_string();
    config.socks5.listen_address = socks.to_string();
    config.dns_proxy.enabled = false;
    config.http_proxy.enabled = false;
    config.logging.file_enabled = file_logging;
    if file_logging {
        config.logging.level = "trace".into();
    }
    let path = directory.path().join("client.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
    let child = Process(
        Command::new(binary)
            .args(["-c", path.to_str().unwrap()])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    (directory, child, panel, socks)
}

#[tokio::test]
async fn file_logging_keeps_only_panel_access_information_on_console() {
    let (directory, mut child, panel, socks) = fixture_logging(false, true);
    let (mut socket, mut current) = connect(panel).await;
    // Trigger a successful save to prove runtime messages aren't duplicated.
    let mut config = current["config"].clone();
    config["logging"]["max_files"] = json!(3);
    assert_eq!(save(&mut socket, &mut current, config).await["ok"], true);
    assert!(TcpStream::connect(socks).await.is_ok());
    // The file writer is asynchronous. Wait for the event to reach disk before
    // killing the process, which cannot flush its WorkerGuard on forced exit.
    let logs = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let logs: String = std::fs::read_dir(directory.path())
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .filter(|path| path.extension().is_some_and(|ext| ext == "log"))
                .map(|path| String::from_utf8_lossy(&std::fs::read(path).unwrap()).into_owned())
                .collect();
            if logs.contains("Client configuration applied") {
                break logs;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    })
    .await
    .expect("configuration applied log was not written within 10 seconds");
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    let mut stdout = String::new();
    let mut stderr = String::new();
    use std::io::Read;
    child
        .0
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    child
        .0
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert_eq!(stdout.lines().count(), 1, "{stdout}");
    assert!(stdout.contains(&format!("http://{panel}/")), "{stdout}");
    assert!(stderr.is_empty(), "{stderr}");
    assert!(logs.contains("Client configuration applied"));
    assert!(!logs.contains('\u{1b}'));
}

async fn idle_flow(address: SocketAddr) -> TcpStream {
    let mut flow = TcpStream::connect(address).await.unwrap();
    flow.write_all(&[5, 1, 0]).await.unwrap();
    let mut reply = [0u8; 2];
    flow.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [5, 0]);
    flow
}

#[tokio::test]
async fn saves_apply_rebind_roll_back_and_move_panel_without_changing_pid() {
    let (directory, mut child, panel, socks) = fixture(false);
    let pid = child.0.id();
    let (mut socket, mut current) = connect(panel).await;
    // Startup readiness may follow the panel's first session by a few ms.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if TcpStream::connect(socks).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let mut flow = idle_flow(socks).await;
    let mut config = current["config"].clone();
    config["logging"]["file_enabled"] = json!(true);
    config["logging"]["directory"] = json!("./new-logs");
    config["logging"]["level"] = json!("debug");
    let saved = save(&mut socket, &mut current, config).await;
    assert_eq!(saved["ok"], true, "{saved}");
    assert_eq!(current["pending_changes"], false);
    assert!(directory.path().join("new-logs").is_dir());
    let mut rejected_log = current["config"].clone();
    rejected_log["logging"]["directory"] = json!("./bundle.json");
    assert_eq!(
        save(&mut socket, &mut current, rejected_log).await["ok"],
        false
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), flow.read_u8())
            .await
            .is_err(),
        "Log changes must preserve existing proxy connections"
    );
    let next_socks = address();
    let http = address();
    let dns = address();
    let mut config = current["config"].clone();
    config["socks5"]["listen_address"] = json!(next_socks.to_string());
    config["http_proxy"]["enabled"] = json!(true);
    config["http_proxy"]["listen_address"] = json!(http.to_string());
    config["dns_proxy"]["enabled"] = json!(true);
    config["dns_proxy"]["listen_address"] = json!(dns.to_string());
    config["dns_proxy"]["nameservers"] = json!(["https://1.1.1.1/dns-query"]);
    assert_eq!(save(&mut socket, &mut current, config).await["ok"], true);
    assert_eq!(current["runtime"]["socks5"], next_socks.to_string());
    assert!(TcpStream::connect(socks).await.is_err());
    assert!(TcpStream::connect(next_socks).await.is_ok());
    assert!(TcpStream::connect(http).await.is_ok());
    assert!(tokio::net::UdpSocket::bind(dns).await.is_err());
    let mut one = [0u8];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), flow.read(&mut one))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    // A conflicting new port must restore both disk configuration and old listeners.
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let before = std::fs::read(directory.path().join("client.json")).unwrap();
    let mut config = current["config"].clone();
    config["socks5"]["listen_address"] = json!(occupied.local_addr().unwrap().to_string());
    let rejected = save(&mut socket, &mut current, config).await;
    assert_eq!(rejected["ok"], false, "{rejected}");
    assert!(rejected["error"].as_str().unwrap().contains("恢复"));
    assert_eq!(
        std::fs::read(directory.path().join("client.json")).unwrap(),
        before
    );
    assert!(TcpStream::connect(next_socks).await.is_ok());
    assert!(TcpStream::connect(http).await.is_ok());
    // Switching to TUN and back cancels an in-progress reconnect without
    // requiring a real tunnel or elevated TUN-device privileges in this test.
    let mut config = current["config"].clone();
    config["tun"]["enabled"] = json!(true);
    assert_eq!(save(&mut socket, &mut current, config).await["ok"], true);
    assert_eq!(current["runtime"]["tun"], true);
    assert!(TcpStream::connect(next_socks).await.is_err());
    let mut config = current["config"].clone();
    config["tun"]["enabled"] = json!(false);
    assert_eq!(save(&mut socket, &mut current, config).await["ok"], true);
    assert!(TcpStream::connect(next_socks).await.is_ok());
    // Moving the panel itself does not rebuild or interrupt the VPN network.
    let mut flow = idle_flow(next_socks).await;
    let next_panel = address();
    let mut config = current["config"].clone();
    config["dashboard"]["listen_address"] = json!(next_panel.to_string());
    assert_eq!(save(&mut socket, &mut current, config).await["ok"], true);
    let (mut next_socket, mut current) = connect(next_panel).await;
    assert!(TcpStream::connect(panel).await.is_err());
    assert!(
        tokio::time::timeout(Duration::from_millis(100), flow.read_u8())
            .await
            .is_err()
    );
    // Switching loopback to wildcard on the same port must release/rebind the
    // accept socket while preserving the existing WebSocket and proxy flow.
    let mut config = current["config"].clone();
    config["dashboard"]["listen_address"] = json!(format!("0.0.0.0:{}", next_panel.port()));
    assert_eq!(
        save(&mut next_socket, &mut current, config).await["ok"],
        true
    );
    let (mut next_socket, mut current) = connect(next_panel).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), flow.read_u8())
            .await
            .is_err()
    );
    // Disabling the panel stops the listener after delivering the save result.
    let mut config = current["config"].clone();
    config["dashboard"]["enabled"] = json!(false);
    assert_eq!(
        save(&mut next_socket, &mut current, config).await["ok"],
        true
    );
    assert!(TcpStream::connect(next_panel).await.is_err());
    assert!(child.0.try_wait().unwrap().is_none());
    assert_eq!(child.0.id(), pid);
}

#[tokio::test]
async fn saving_repaired_configuration_recovers_a_stopped_network() {
    let (_directory, mut child, panel, socks) = fixture(true);
    let pid = child.0.id();
    let (mut socket, mut current) = connect(panel).await;
    let mut config = current["config"].clone();
    config["prekey_bundle"] = json!("./bundle.json");
    let saved = save(&mut socket, &mut current, config).await;
    assert_eq!(saved["ok"], true, "{saved}");
    assert_eq!(current["pending_changes"], false);
    assert!(TcpStream::connect(socks).await.is_ok());
    assert!(child.0.try_wait().unwrap().is_none());
    assert_eq!(child.0.id(), pid);
}

#[tokio::test]
async fn access_policy_changes_revoke_existing_and_new_panel_sessions() {
    let (_directory, mut child, panel, socks) = fixture(false);
    let (mut socket, mut current) = connect(panel).await;
    let mut config = current["config"].clone();
    config["dashboard"]["allow_cidrs"] = json!(["192.0.2.0/24"]);
    let saved = save(&mut socket, &mut current, config).await;
    assert_eq!(saved["ok"], true, "{saved}");
    assert_eq!(current["access_allowed"], false);
    tokio::time::timeout(Duration::from_secs(3), async {
        while let Some(message) = socket.next().await {
            if matches!(message.unwrap(), Message::Close(_)) {
                return;
            }
        }
    })
    .await
    .unwrap();
    let mut request = format!("ws://{panel}/ws").into_client_request().unwrap();
    request
        .headers_mut()
        .insert("origin", format!("http://{panel}").parse().unwrap());
    match tokio_tungstenite::connect_async(request).await.unwrap_err() {
        tokio_tungstenite::tungstenite::Error::Http(response) => assert_eq!(response.status(), 403),
        error => panic!("{error}"),
    }
    assert!(TcpStream::connect(socks).await.is_ok());
    assert!(child.0.try_wait().unwrap().is_none());
}
