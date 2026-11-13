//! Native system service registration. Installation does not start the VPN.
use anyhow::{Context, Result};
use clap::Subcommand;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Subcommand)]
pub enum ServiceAction {
    Install,
    Uninstall,
    Start,
    Stop,
    Status,
    /// Internal Windows SCM entry point
    #[command(hide = true)]
    Run {
        #[arg(long)]
        working_directory: PathBuf,
    },
}

fn run(program: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(program)
        .args(args)
        .status()
        .with_context(|| format!("Failed to execute {program}"))?;
    anyhow::ensure!(status.success(), "{program} failed: {status}");
    Ok(())
}

// systemd interprets percent specifiers and dollar expansions inside quotes.
#[cfg(any(target_os = "linux", test))]
fn systemd_quote(value: &str) -> String {
    format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
    )
}

#[cfg(any(target_os = "macos", test))]
fn xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(any(target_os = "linux", test))]
fn unit(exe: &str, config: &str, cwd: &str) -> String {
    format!("[Unit]\nDescription=R-VPN Client\nWants=network-online.target\nAfter=network-online.target\n\n[Service]\nType=simple\nWorkingDirectory={}\nExecStart={} --config {}\nRestart=on-failure\nRestartSec=5\nTimeoutStopSec=30\n\n[Install]\nWantedBy=multi-user.target\n",
        systemd_quote(cwd), systemd_quote(exe).replace('$', "$$"), systemd_quote(config).replace('$', "$$"))
}

#[cfg(any(target_os = "macos", test))]
fn plist(exe: &str, config: &str, cwd: &str) -> String {
    format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>com.rvpn.client</string>\n<key>ProgramArguments</key><array><string>{}</string><string>--config</string><string>{}</string></array>\n<key>WorkingDirectory</key><string>{}</string>\n<key>RunAtLoad</key><true/>\n<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>\n<key>StandardOutPath</key><string>/var/log/rvpn-client.log</string>\n<key>StandardErrorPath</key><string>/var/log/rvpn-client.log</string>\n<key>ThrottleInterval</key><integer>5</integer>\n</dict></plist>\n", xml(exe), xml(config), xml(cwd))
}

#[cfg(unix)]
fn write_definition(path: &Path, contents: &str) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(path)
        .context(
            "Cannot create service definition (already installed, or insufficient privileges)",
        )?;
    file.write_all(contents.as_bytes())?;
    Ok(())
}

pub fn execute(action: &ServiceAction, config: &Path) -> Result<()> {
    if let ServiceAction::Run { working_directory } = action {
        #[cfg(windows)]
        {
            std::env::set_current_dir(working_directory)?;
            return windows::dispatch();
        }
        #[cfg(not(windows))]
        {
            let _ = working_directory;
            anyhow::bail!("service run is only used by Windows SCM");
        }
    }
    // Resolve paths before installing so services don't depend on the manager's CWD.
    let paths = if matches!(action, ServiceAction::Install) {
        let config = config
            .canonicalize()
            .context("Service installation requires an existing config file")?;
        crate::config::ClientConfig::load(&config)?;
        let exe = std::env::current_exe()?;
        let cwd = std::env::current_dir()?;
        for path in [&exe, &config, &cwd] {
            let value = path.to_str().context("Service paths must be UTF-8")?;
            anyhow::ensure!(!value.contains(['\n', '\r', '\0']), "Invalid service path");
        }
        Some((exe, config, cwd))
    } else {
        None
    };

    #[cfg(target_os = "linux")]
    {
        let path = Path::new("/etc/systemd/system/rvpn-client.service");
        match action {
            ServiceAction::Install => {
                let (exe, config, cwd) = paths.unwrap();
                anyhow::ensure!(!path.exists(), "Service already installed; uninstall first");
                write_definition(
                    path,
                    &unit(
                        exe.to_str().unwrap(),
                        config.to_str().unwrap(),
                        cwd.to_str().unwrap(),
                    ),
                )?;
                run("systemctl", &["daemon-reload"])?;
                run("systemctl", &["enable", "rvpn-client"])
            }
            ServiceAction::Uninstall => {
                run("systemctl", &["disable", "--now", "rvpn-client"])?;
                std::fs::remove_file(path)?;
                run("systemctl", &["daemon-reload"])
            }
            ServiceAction::Start => run("systemctl", &["start", "rvpn-client"]),
            ServiceAction::Stop => run("systemctl", &["stop", "rvpn-client"]),
            ServiceAction::Status => run("systemctl", &["status", "--no-pager", "rvpn-client"]),
            ServiceAction::Run { .. } => unreachable!(),
        }
    }
    #[cfg(target_os = "macos")]
    {
        const PLIST: &str = "/Library/LaunchDaemons/com.rvpn.client.plist";
        match action {
            ServiceAction::Install => {
                use std::os::unix::fs::PermissionsExt;
                let (exe, config, cwd) = paths.unwrap();
                anyhow::ensure!(
                    !Path::new(PLIST).exists(),
                    "Service already installed; uninstall first"
                );
                write_definition(
                    Path::new(PLIST),
                    &plist(
                        exe.to_str().unwrap(),
                        config.to_str().unwrap(),
                        cwd.to_str().unwrap(),
                    ),
                )?;
                std::fs::set_permissions(PLIST, std::fs::Permissions::from_mode(0o644))?;
                Ok(())
            }
            ServiceAction::Uninstall => {
                if Command::new("launchctl")
                    .args(["print", "system/com.rvpn.client"])
                    .output()?
                    .status
                    .success()
                {
                    run("launchctl", &["bootout", "system/com.rvpn.client"])?;
                }
                std::fs::remove_file(PLIST)?;
                Ok(())
            }
            ServiceAction::Start => run("launchctl", &["bootstrap", "system", PLIST]),
            ServiceAction::Stop => run("launchctl", &["bootout", "system/com.rvpn.client"]),
            ServiceAction::Status => run("launchctl", &["print", "system/com.rvpn.client"]),
            ServiceAction::Run { .. } => unreachable!(),
        }
    }
    #[cfg(windows)]
    {
        match action {
            ServiceAction::Install => {
                use windows_service::{
                    service::{
                        ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType,
                        ServiceType,
                    },
                    service_manager::{ServiceManager, ServiceManagerAccess},
                };
                let (exe, config, cwd) = paths.unwrap();
                let manager = ServiceManager::local_computer(
                    None::<&str>,
                    ServiceManagerAccess::CREATE_SERVICE,
                )?;
                manager.create_service(
                    &ServiceInfo {
                        name: "rvpn-client".into(),
                        display_name: "R-VPN Client".into(),
                        service_type: ServiceType::OWN_PROCESS,
                        start_type: ServiceStartType::AutoStart,
                        error_control: ServiceErrorControl::Normal,
                        executable_path: exe,
                        launch_arguments: vec![
                            "--config".into(),
                            config.into_os_string(),
                            "service".into(),
                            "run".into(),
                            "--working-directory".into(),
                            cwd.into_os_string(),
                        ],
                        dependencies: vec![],
                        account_name: None,
                        account_password: None,
                    },
                    ServiceAccess::QUERY_STATUS,
                )?;
                Ok(())
            }
            ServiceAction::Uninstall => {
                use windows_service::{
                    service::{ServiceAccess, ServiceState},
                    service_manager::{ServiceManager, ServiceManagerAccess},
                };
                let manager =
                    ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
                let service = manager.open_service(
                    "rvpn-client",
                    ServiceAccess::STOP | ServiceAccess::QUERY_STATUS | ServiceAccess::DELETE,
                )?;
                if service.query_status()?.current_state != ServiceState::Stopped {
                    service.stop()?;
                    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
                    while service.query_status()?.current_state != ServiceState::Stopped {
                        anyhow::ensure!(
                            std::time::Instant::now() < deadline,
                            "Timed out stopping service"
                        );
                        std::thread::sleep(std::time::Duration::from_millis(200));
                    }
                }
                service.delete()?;
                Ok(())
            }
            ServiceAction::Start => run("sc.exe", &["start", "rvpn-client"]),
            ServiceAction::Stop => run("sc.exe", &["stop", "rvpn-client"]),
            ServiceAction::Status => run("sc.exe", &["query", "rvpn-client"]),
            ServiceAction::Run { .. } => unreachable!(),
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = paths;
        anyhow::bail!("System services are unsupported on this platform")
    }
}

#[cfg(windows)]
pub mod windows {
    use super::*;
    use clap::Parser;
    use std::sync::OnceLock;
    use windows_service::{
        define_windows_service,
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
    };
    static STOP: OnceLock<tokio::sync::watch::Sender<bool>> = OnceLock::new();
    define_windows_service!(ffi_main, service_main);

    pub fn dispatch() -> Result<()> {
        service_dispatcher::start("rvpn-client", ffi_main)?;
        Ok(())
    }

    pub fn is_service() -> bool {
        STOP.get().is_some()
    }

    pub async fn wait_stop() {
        if let Some(tx) = STOP.get() {
            let mut rx = tx.subscribe();
            if !*rx.borrow() {
                let _ = rx.changed().await;
            }
        } else {
            std::future::pending::<()>().await;
        }
    }

    fn service_main(_: Vec<std::ffi::OsString>) {
        if let Err(e) = run_service() {
            eprintln!("R-VPN service failed: {e:#}");
        }
    }

    fn run_service() -> Result<()> {
        let (tx, _) = tokio::sync::watch::channel(false);
        let _ = STOP.set(tx);
        let handle = service_control_handler::register("rvpn-client", |event| match event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                STOP.get().unwrap().send_replace(true);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        })?;
        let status = |state, exit_code| ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: if state == ServiceState::Running {
                ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
            } else {
                ServiceControlAccept::empty()
            },
            exit_code,
            checkpoint: 0,
            wait_hint: std::time::Duration::default(),
            process_id: None,
        };
        handle.set_service_status(status(ServiceState::Running, ServiceExitCode::Win32(0)))?;
        let result = (|| {
            let mut args = crate::Args::parse();
            args.command = None;
            tokio::runtime::Runtime::new()?.block_on(crate::async_main(args))
        })();
        handle.set_service_status(status(
            ServiceState::Stopped,
            ServiceExitCode::Win32(if result.is_ok() { 0 } else { 1 }),
        ))?;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn service_cli_and_dns_config_are_backwards_compatible() {
        for action in ["install", "uninstall", "start", "stop", "status"] {
            let args =
                crate::Args::try_parse_from(["rvpn", "--config", "custom.toml", "service", action])
                    .unwrap();
            assert_eq!(args.config, PathBuf::from("custom.toml"));
            assert!(matches!(
                args.command,
                Some(crate::Commands::Service { .. })
            ));
        }
        let old: crate::config::ClientConfig = toml::from_str("").unwrap();
        assert!(!old.dns_proxy.nameservers.is_empty());
        let config: crate::config::ClientConfig = toml::from_str("[dns_proxy]\nenabled = true\nnameservers = ['https://1.1.1.1/dns-query', '223.5.5.5:53']\n").unwrap();
        assert!(
            rvpn_split_tunnel::dns_cache::DnsUpstreams::new(&config.dns_proxy.nameservers).is_ok()
        );
    }

    #[test]
    fn service_definitions_escape_paths() {
        let text = unit("/opt/my vpn/rvpn", "/tmp/a%$\".toml", "/opt/my vpn");
        assert!(text.contains("ExecStart=\"/opt/my vpn/rvpn\" --config \"/tmp/a%%$$\\\".toml\""));
        assert!(plist("/a&b", "/c<d", "/e").contains("<string>/a&amp;b</string>"));
    }
}
