//! Console and daily file logging shared by foreground and service startup.
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tracing::{info, warn, Level, Subscriber};
use tracing_appender::{
    non_blocking::{NonBlockingBuilder, WorkerGuard},
    rolling::{RollingFileAppender, Rotation},
};
use tracing_subscriber::{filter::LevelFilter, prelude::*};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    /// Write daily files in addition to the console.
    pub file_enabled: bool,
    /// None means beside the executable; explicit relative paths use the config directory.
    pub directory: Option<PathBuf>,
    /// off, error, warn, info, debug, or trace. CLI -v/-vv overrides this.
    pub level: String,
    /// Maximum number of daily log files to retain (must be positive).
    pub max_files: usize,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            file_enabled: true,
            directory: None,
            level: "info".into(),
            max_files: 7,
        }
    }
}

impl LoggingConfig {
    pub fn resolve_directory(&mut self, base: &Path) {
        if let Some(directory) = &mut self.directory {
            if directory.is_relative() {
                *directory = base.join(&*directory);
            }
        }
    }

    fn level(&self, verbose: u8) -> Result<LevelFilter> {
        let configured = self
            .level
            .parse::<LevelFilter>()
            .context("Invalid logging.level (expected off/error/warn/info/debug/trace)")?;
        Ok(match verbose {
            0 => configured,
            1 => LevelFilter::from_level(Level::DEBUG),
            _ => LevelFilter::from_level(Level::TRACE),
        })
    }
}

fn console_layer<S>() -> impl tracing_subscriber::Layer<S>
where
    S: Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    tracing_subscriber::fmt::layer()
        // Shared span formatting must never inject terminal escapes into files.
        .with_ansi(false)
        .with_target(false)
        .with_thread_ids(false)
        .with_file(true)
        .with_line_number(true)
}

fn file_subscriber(
    directory: &Path,
    filter: LevelFilter,
    prefix: &str,
    max_files: usize,
) -> Result<(Box<dyn Subscriber + Send + Sync>, WorkerGuard)> {
    let appender = RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .filename_prefix(prefix)
        .filename_suffix("log")
        .max_log_files(max_files)
        .build(directory)
        .with_context(|| format!("Failed to create log in {}", directory.display()))?;
    let (writer, guard) = NonBlockingBuilder::default()
        .buffered_lines_limit(8192)
        .lossy(false)
        .finish(appender);
    let subscriber = tracing_subscriber::registry()
        .with(filter)
        .with(console_layer())
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(writer)
                .with_ansi(false)
                .with_target(false)
                .with_thread_ids(false)
                .with_file(true)
                .with_line_number(true),
        );
    Ok((Box::new(subscriber), guard))
}

pub fn init(config: &LoggingConfig, verbose: u8, prefix: &str) -> Result<Option<WorkerGuard>> {
    let filter = config.level(verbose)?;
    anyhow::ensure!(
        config.max_files > 0,
        "logging.max_files must be greater than zero"
    );
    let executable = std::env::current_exe().context("Failed to locate executable")?;
    let directory = config.directory.as_deref().unwrap_or(
        executable
            .parent()
            .context("Executable has no parent directory")?,
    );
    let file_result = if config.file_enabled {
        Some(file_subscriber(directory, filter, prefix, config.max_files))
    } else {
        None
    };
    match file_result {
        Some(Ok((subscriber, guard))) => {
            tracing::subscriber::set_global_default(subscriber)
                .map_err(|error| anyhow::anyhow!("Failed to initialize logging: {error}"))?;
            info!(
                "File logging enabled: {} (UTC daily rotation, up to {} files)",
                directory.join(format!("{prefix}.YYYY-MM-DD.log")).display(),
                config.max_files
            );
            Ok(Some(guard))
        }
        failure => {
            // Installing under a protected directory must not prevent the VPN
            // from starting. Explain missing file output in the console log.
            let subscriber = tracing_subscriber::registry()
                .with(filter)
                .with(console_layer());
            tracing::subscriber::set_global_default(subscriber)
                .map_err(|error| anyhow::anyhow!("Failed to initialize logging: {error}"))?;
            if let Some(Err(error)) = failure {
                warn!("File logging unavailable; using console only: {error:#}");
            }
            Ok(None)
        }
    }
}

type DynamicLayer = Box<dyn tracing_subscriber::Layer<tracing_subscriber::Registry> + Send + Sync>;

/// A prepared replacement owns its writer until it is installed or discarded.
pub struct PreparedLogging {
    layer: DynamicLayer,
    guard: Option<WorkerGuard>,
}

pub struct ReloadableLogging {
    handle: tracing_subscriber::reload::Handle<DynamicLayer, tracing_subscriber::Registry>,
    guard: std::sync::Mutex<Option<WorkerGuard>>,
    verbose: u8,
    prefix: String,
}

fn prepare_logging(config: &LoggingConfig, verbose: u8, prefix: &str) -> Result<PreparedLogging> {
    anyhow::ensure!(
        config.max_files > 0,
        "logging.max_files must be greater than zero"
    );
    let filter = config.level(verbose)?;
    // Use a subscriber-wide LevelFilter layer. Replacing `Filtered` would
    // require a new registry FilterId, which reload::Handle cannot register.
    let dependency_filter = tracing_subscriber::filter::filter_fn(|metadata| {
        let target = metadata.target();
        // The CLI binary is named `rvpn`; library crates use `rvpn_*`.
        target == "rvpn"
            || target.starts_with("rvpn::")
            || target.starts_with("rvpn_")
            || *metadata.level() <= Level::WARN
    });
    // Client file logging replaces console output; the browser URL is printed
    // separately even when logs are disabled or the level is set to off.
    let mut output: DynamicLayer = console_layer().boxed();
    let mut guard = None;
    if config.file_enabled {
        let executable = std::env::current_exe()?;
        let directory = config
            .directory
            .as_deref()
            .unwrap_or(executable.parent().context("Executable has no parent")?);
        std::fs::create_dir_all(directory)
            .with_context(|| format!("Failed to create log directory {}", directory.display()))?;
        let appender = RollingFileAppender::builder()
            .rotation(Rotation::DAILY)
            .filename_prefix(prefix)
            .filename_suffix("log")
            .max_log_files(config.max_files)
            .build(directory)
            .with_context(|| format!("Failed to create log in {}", directory.display()))?;
        let (writer, worker) = NonBlockingBuilder::default()
            .buffered_lines_limit(8192)
            .lossy(false)
            .finish(appender);
        guard = Some(worker);
        output = tracing_subscriber::fmt::layer()
            .with_writer(writer)
            .with_ansi(false)
            .with_target(false)
            .with_file(true)
            .with_line_number(true)
            .boxed();
    }
    Ok(PreparedLogging {
        // Compose sequentially so a filter's `Interest::never()` cannot be
        // overridden by a formatter's `Interest::always()` in a Vec of layers.
        layer: filter.and_then(dependency_filter).and_then(output).boxed(),
        guard,
    })
}

impl ReloadableLogging {
    /// Prepare first; an invalid/unwritable destination never replaces a working logger.
    pub fn prepare(&self, config: &LoggingConfig) -> Result<PreparedLogging> {
        prepare_logging(config, self.verbose, &self.prefix)
    }

    pub fn apply(&self, prepared: PreparedLogging) -> Result<()> {
        let mut guard = self.guard.lock().unwrap_or_else(|e| e.into_inner());
        self.handle
            .reload(prepared.layer)
            .map_err(|error| anyhow::anyhow!("Failed to reload logging: {error}"))?;
        // Flush the old worker after redirecting new events to the new writer.
        *guard = prepared.guard;
        Ok(())
    }
}

pub fn init_reloadable(
    config: &LoggingConfig,
    verbose: u8,
    prefix: &str,
) -> Result<ReloadableLogging> {
    let (prepared, warning) = match prepare_logging(config, verbose, prefix) {
        Ok(prepared) => (prepared, None),
        Err(error) if config.file_enabled => {
            let mut fallback = config.clone();
            fallback.file_enabled = false;
            (prepare_logging(&fallback, verbose, prefix)?, Some(error))
        }
        Err(error) => return Err(error),
    };
    let (layer, handle) = tracing_subscriber::reload::Layer::new(prepared.layer);
    tracing::subscriber::set_global_default(tracing_subscriber::registry().with(layer))
        .map_err(|error| anyhow::anyhow!("Failed to initialize logging: {error}"))?;
    if let Some(error) = warning {
        warn!("File logging unavailable; using console only: {error:#}");
    } else if config.file_enabled {
        let executable = std::env::current_exe()?;
        let directory = config
            .directory
            .as_deref()
            .unwrap_or(executable.parent().context("Executable has no parent")?);
        info!(
            "File logging enabled: {} (UTC daily rotation, up to {} files)",
            directory.join(format!("{prefix}.YYYY-MM-DD.log")).display(),
            config.max_files
        );
    }
    Ok(ReloadableLogging {
        handle,
        guard: std::sync::Mutex::new(prepared.guard),
        verbose,
        prefix: prefix.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reload_switches_between_console_and_file_without_disabling_events() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = LoggingConfig {
            file_enabled: false,
            directory: Some(directory.path().into()),
            ..Default::default()
        };
        let prepared = prepare_logging(&config, 0, "rvpn-client").unwrap();
        let (layer, handle) = tracing_subscriber::reload::Layer::new(prepared.layer);
        let subscriber = tracing_subscriber::registry().with(layer);
        let controller = ReloadableLogging {
            handle,
            guard: std::sync::Mutex::new(prepared.guard),
            verbose: 0,
            prefix: "rvpn-client".into(),
        };
        let check_enabled = || {
            assert!(tracing::enabled!(target: "rvpn", Level::ERROR));
            assert!(tracing::enabled!(target: "rvpn::runtime_control", Level::INFO));
            assert!(tracing::enabled!(target: "rvpn_client", Level::INFO));
            assert!(tracing::enabled!(target: "h2", Level::WARN));
            assert!(!tracing::enabled!(target: "rvpn", Level::DEBUG));
            assert!(!tracing::enabled!(target: "h2", Level::INFO));
        };
        tracing::subscriber::with_default(subscriber, || {
            check_enabled();
            config.file_enabled = true;
            controller
                .apply(controller.prepare(&config).unwrap())
                .unwrap();
            check_enabled();
            info!(target: "rvpn", "file output after console");
            config.file_enabled = false;
            controller
                .apply(controller.prepare(&config).unwrap())
                .unwrap();
            check_enabled();
        });
        drop(controller);
        assert!(read_logs(directory.path()).contains("file output after console"));
    }

    #[test]
    fn reload_respects_filters_at_reused_callsites() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = LoggingConfig {
            directory: Some(directory.path().join("initial")),
            ..Default::default()
        };
        let prepared = prepare_logging(&config, 0, "rvpn-client").unwrap();
        let (layer, handle) = tracing_subscriber::reload::Layer::new(prepared.layer);
        let subscriber = tracing_subscriber::registry().with(layer);
        let controller = ReloadableLogging {
            handle,
            guard: std::sync::Mutex::new(prepared.guard),
            verbose: 0,
            prefix: "rvpn-client".into(),
        };
        let emit = || {
            tracing::debug!("application debug");
            info!("application info");
            tracing::warn!("application warning");
            tracing::debug!(target: "rvpn", "binary debug");
            tracing::info!(target: "rvpn::runtime_control", "binary module info");
            tracing::debug!(target: "h2", "dependency debug");
            tracing::info!(target: "h2", "dependency info");
            tracing::warn!(target: "h2", "dependency warning");
        };
        tracing::subscriber::with_default(subscriber, || {
            emit();
            for level in ["debug", "warn", "off", "trace", "info"] {
                config.level = level.into();
                config.directory = Some(directory.path().join(level));
                controller
                    .apply(controller.prepare(&config).unwrap())
                    .unwrap();
                emit();
            }
        });
        drop(controller);
        for level in ["initial", "debug", "warn", "off", "trace", "info"] {
            let logs = read_logs(&directory.path().join(level));
            assert_eq!(
                logs.contains("application debug"),
                matches!(level, "debug" | "trace"),
                "{level}"
            );
            assert_eq!(
                logs.contains("application info"),
                !matches!(level, "warn" | "off"),
                "{level}"
            );
            assert_eq!(
                logs.contains("application warning"),
                level != "off",
                "{level}"
            );
            assert_eq!(
                logs.contains("binary debug"),
                matches!(level, "debug" | "trace"),
                "{level}"
            );
            assert_eq!(
                logs.contains("binary module info"),
                !matches!(level, "warn" | "off"),
                "{level}"
            );
            assert_eq!(
                logs.contains("dependency warning"),
                level != "off",
                "{level}"
            );
            assert!(!logs.contains("dependency debug"), "{level}");
            assert!(!logs.contains("dependency info"), "{level}");
        }
    }

    #[test]
    fn reload_changes_level_and_destination_and_rejects_invalid_destination() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = LoggingConfig {
            directory: Some(directory.path().join("first")),
            ..Default::default()
        };
        let prepared = prepare_logging(&config, 0, "rvpn-client").unwrap();
        let (layer, handle) = tracing_subscriber::reload::Layer::new(prepared.layer);
        let subscriber = tracing_subscriber::registry().with(layer);
        let controller = ReloadableLogging {
            handle,
            guard: std::sync::Mutex::new(prepared.guard),
            verbose: 0,
            prefix: "rvpn-client".into(),
        };
        tracing::subscriber::with_default(subscriber, || {
            info!("before live reload");
            config.directory = Some(directory.path().join("second"));
            config.level = "debug".into();
            controller
                .apply(controller.prepare(&config).unwrap())
                .unwrap();
            tracing::debug!("after live reload");
            tracing::debug!(target: "h2", "noisy dependency details");
            tracing::warn!(target: "h2", "important dependency warning");
            let span = tracing::info_span!("test_span", peer = "client");
            let _entered = span.enter();
            info!("span message without terminal codes");
            let occupied = directory.path().join("occupied");
            std::fs::write(&occupied, "not a directory").unwrap();
            config.directory = Some(occupied);
            assert!(controller.prepare(&config).is_err());
            tracing::debug!("old logger still works");
        });
        drop(controller);
        let first = read_logs(&directory.path().join("first"));
        let second = read_logs(&directory.path().join("second"));
        assert!(first.contains("before live reload"));
        assert!(!first.contains("after live reload"));
        assert!(second.contains("after live reload"));
        assert!(second.contains("old logger still works"));
        assert!(!second.contains("noisy dependency details"));
        assert!(second.contains("important dependency warning"));
        assert!(!second.contains('\u{1b}'));
    }

    #[test]
    fn retention_keeps_other_program_logs() {
        let directory = tempfile::tempdir().unwrap();
        for day in 1..=9 {
            std::fs::write(
                directory
                    .path()
                    .join(format!("rvpn-client.2000-01-{day:02}.log")),
                "old",
            )
            .unwrap();
        }
        let server_log = directory.path().join("rvpn-server.2000-01-01.log");
        std::fs::write(&server_log, "server logs").unwrap();
        let (_, guard) =
            file_subscriber(directory.path(), LevelFilter::INFO, "rvpn-client", 3).unwrap();
        drop(guard);
        let count = std::fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name.to_string_lossy().starts_with("rvpn-client."))
            .count();
        assert!((1..=3).contains(&count));
        assert_eq!(std::fs::read_to_string(server_log).unwrap(), "server logs");
    }

    #[test]
    fn config_defaults_overrides_and_relative_directories() {
        let default: LoggingConfig = toml::from_str("").unwrap();
        assert!(default.file_enabled);
        assert!(default.directory.is_none());
        assert_eq!(default.max_files, 7);
        assert_eq!(default.level(0).unwrap(), LevelFilter::INFO);
        let mut config: LoggingConfig = toml::from_str(
            "file_enabled = false\ndirectory = './logs'\nlevel = 'warn'\nmax_files = 3\n",
        )
        .unwrap();
        assert!(!config.file_enabled);
        assert_eq!(config.max_files, 3);
        assert_eq!(config.level(0).unwrap(), LevelFilter::WARN);
        assert_eq!(config.level(1).unwrap(), LevelFilter::DEBUG);
        assert_eq!(config.level(2).unwrap(), LevelFilter::TRACE);
        let base = tempfile::tempdir().unwrap();
        config.resolve_directory(base.path());
        assert_eq!(
            config.directory.as_ref().unwrap(),
            &base.path().join("./logs")
        );
        config.level = "invalid".into();
        assert!(config.level(0).is_err());
    }

    fn read_logs(directory: &Path) -> String {
        std::fs::read_dir(directory)
            .unwrap()
            .map(|entry| std::fs::read_to_string(entry.unwrap().path()).unwrap())
            .collect()
    }

    #[test]
    fn logs_are_flushed_on_exit_and_appended_on_restart() {
        let directory = tempfile::tempdir().unwrap();
        for run in 0..2 {
            let (subscriber, guard) =
                file_subscriber(directory.path(), LevelFilter::INFO, "rvpn", 7).unwrap();
            tracing::subscriber::with_default(subscriber, || {
                info!("startup number {run}");
                tracing::debug!("hidden debug message");
                tracing::error!("startup failed: missing bundle");
            });
            drop(guard);
        }
        let logs = read_logs(directory.path());
        assert!(logs.contains("startup number 0"));
        assert!(logs.contains("startup number 1"));
        assert_eq!(logs.matches("startup failed: missing bundle").count(), 2);
        assert!(!logs.contains("hidden debug message"));
        assert!(!logs.contains('\u{1b}'));
        let names: Vec<_> = std::fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(names
            .iter()
            .all(|name| name.starts_with("rvpn.") && name.ends_with(".log")));
    }

    #[test]
    fn verbose_logging_includes_debug_messages() {
        let directory = tempfile::tempdir().unwrap();
        let (subscriber, guard) =
            file_subscriber(directory.path(), LevelFilter::DEBUG, "rvpn", 7).unwrap();
        tracing::subscriber::with_default(subscriber, || {
            tracing::debug!("visible debug message");
            tracing::trace!("hidden trace message");
        });
        drop(guard);
        let logs = read_logs(directory.path());
        assert!(logs.contains("visible debug message"));
        assert!(!logs.contains("hidden trace message"));
    }

    #[test]
    fn invalid_log_directory_reports_path() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("not-a-directory");
        std::fs::write(&file, "occupied").unwrap();
        let error = file_subscriber(&file, LevelFilter::INFO, "rvpn", 7)
            .err()
            .unwrap();
        assert!(format!("{error:#}").contains(&file.display().to_string()));
    }
}
