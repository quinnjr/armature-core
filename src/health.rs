//! Health check module for application monitoring and Kubernetes probes.
//!
//! This module provides health check endpoints compatible with Kubernetes
//! liveness, readiness, and startup probes, as well as general health monitoring.
//!
//! ## Quick Start
//!
//! ```rust
//! use armature_core::health::{HealthService, HealthIndicator, HealthCheckResult, HealthStatus};
//! use async_trait::async_trait;
//!
//! // Create a custom health indicator
//! struct DatabaseHealthIndicator;
//!
//! #[async_trait]
//! impl HealthIndicator for DatabaseHealthIndicator {
//!     fn name(&self) -> &str {
//!         "database"
//!     }
//!
//!     async fn check(&self) -> HealthCheckResult {
//!         // Check database connectivity
//!         HealthCheckResult::up("database")
//!             .with_detail("type", "postgresql")
//!             .with_detail("pool_size", "10")
//!     }
//! }
//! ```
//!
//! ## Kubernetes Probes
//!
//! The health module provides three endpoints for Kubernetes:
//!
//! - `/health/live` - Liveness probe: Is the application running?
//! - `/health/ready` - Readiness probe: Is the application ready to serve traffic?
//! - `/health` - Full health check with all indicators
//!
//! ## Built-in Indicators
//!
//! - `MemoryHealthIndicator` - Checks memory usage
//! - `DiskHealthIndicator` - Checks disk space
//! - `UptimeHealthIndicator` - Reports application uptime

use async_trait::async_trait;
use futures_util::future::join_all;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

/// Health status of a component or the overall application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HealthStatus {
    /// Component is functioning normally
    Up,
    /// Component is not functioning
    Down,
    /// Component is functioning but with issues
    Degraded,
    /// Component status is unknown
    #[default]
    Unknown,
}

impl HealthStatus {
    /// Returns true if the status indicates the component is healthy
    pub fn is_healthy(&self) -> bool {
        matches!(self, HealthStatus::Up | HealthStatus::Degraded)
    }

    /// Returns the HTTP status code for this health status
    pub fn http_status_code(&self) -> u16 {
        match self {
            HealthStatus::Up => 200,
            HealthStatus::Degraded => 200,
            HealthStatus::Down => 503,
            HealthStatus::Unknown => 503,
        }
    }
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HealthStatus::Up => write!(f, "UP"),
            HealthStatus::Down => write!(f, "DOWN"),
            HealthStatus::Degraded => write!(f, "DEGRADED"),
            HealthStatus::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

/// Result of a health check for a single component.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResult {
    /// Name of the component being checked
    pub name: String,
    /// Current health status
    pub status: HealthStatus,
    /// Additional details about the component
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub details: HashMap<String, String>,
    /// Time taken to perform the health check (in milliseconds)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    /// Error message if the check failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Timestamp of the check
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<u64>,
}

impl HealthCheckResult {
    /// Creates a new health check result with UP status
    pub fn up(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: HealthStatus::Up,
            details: HashMap::new(),
            duration_ms: None,
            error: None,
            timestamp: Some(current_timestamp()),
        }
    }

    /// Creates a new health check result with DOWN status
    pub fn down(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: HealthStatus::Down,
            details: HashMap::new(),
            duration_ms: None,
            error: None,
            timestamp: Some(current_timestamp()),
        }
    }

    /// Creates a new health check result with DEGRADED status
    pub fn degraded(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: HealthStatus::Degraded,
            details: HashMap::new(),
            duration_ms: None,
            error: None,
            timestamp: Some(current_timestamp()),
        }
    }

    /// Creates a new health check result with UNKNOWN status
    pub fn unknown(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: HealthStatus::Unknown,
            details: HashMap::new(),
            duration_ms: None,
            error: None,
            timestamp: Some(current_timestamp()),
        }
    }

    /// Adds a detail to the health check result
    pub fn with_detail(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.details.insert(key.into(), value.into());
        self
    }

    /// Sets the error message
    pub fn with_error(mut self, error: impl Into<String>) -> Self {
        self.error = Some(error.into());
        self.status = HealthStatus::Down;
        self
    }

    /// Sets the duration in milliseconds
    pub fn with_duration(mut self, duration: Duration) -> Self {
        self.duration_ms = Some(duration.as_millis() as u64);
        self
    }
}

/// Aggregated health response for the entire application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Overall health status
    pub status: HealthStatus,
    /// Individual component health checks
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub components: HashMap<String, HealthCheckResult>,
    /// Application information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub info: Option<HealthInfo>,
    /// Timestamp of the health check
    pub timestamp: u64,
}

impl HealthResponse {
    /// Creates a new health response
    pub fn new(status: HealthStatus) -> Self {
        Self {
            status,
            components: HashMap::new(),
            info: None,
            timestamp: current_timestamp(),
        }
    }

    /// Adds a component health check result
    pub fn with_component(mut self, result: HealthCheckResult) -> Self {
        self.components.insert(result.name.clone(), result);
        self
    }

    /// Sets the application info
    pub fn with_info(mut self, info: HealthInfo) -> Self {
        self.info = Some(info);
        self
    }

    /// Strip component details and application info, keeping only the
    /// overall status and timestamp.
    ///
    /// For probes reachable without authentication: component details name
    /// internal dependencies, versions, paths and error text that help an
    /// attacker map the deployment.
    pub fn summary_only(mut self) -> Self {
        self.components.clear();
        self.info = None;
        self
    }

    /// Calculates the overall status from component statuses
    pub fn calculate_status(&mut self) {
        if self.components.is_empty() {
            self.status = HealthStatus::Up;
            return;
        }

        let has_down = self
            .components
            .values()
            .any(|c| c.status == HealthStatus::Down);
        let has_degraded = self
            .components
            .values()
            .any(|c| c.status == HealthStatus::Degraded);
        let has_unknown = self
            .components
            .values()
            .any(|c| c.status == HealthStatus::Unknown);

        self.status = if has_down {
            HealthStatus::Down
        } else if has_degraded {
            HealthStatus::Degraded
        } else if has_unknown {
            HealthStatus::Unknown
        } else {
            HealthStatus::Up
        };
    }
}

/// Application information included in health responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthInfo {
    /// Application name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Application version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Application description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Uptime in seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime_seconds: Option<u64>,
}

impl HealthInfo {
    /// Creates new health info with the given name
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: Some(name.into()),
            version: None,
            description: None,
            uptime_seconds: None,
        }
    }

    /// Sets the version
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Sets the description
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Sets the uptime
    pub fn with_uptime(mut self, uptime: Duration) -> Self {
        self.uptime_seconds = Some(uptime.as_secs());
        self
    }
}

/// Trait for implementing custom health indicators.
///
/// Health indicators are used to check the health of individual components
/// such as databases, caches, external services, etc.
///
/// ## Example
///
/// ```rust
/// use armature_core::health::{HealthIndicator, HealthCheckResult};
/// use async_trait::async_trait;
///
/// struct RedisHealthIndicator {
///     // Redis connection would go here
/// }
///
/// #[async_trait]
/// impl HealthIndicator for RedisHealthIndicator {
///     fn name(&self) -> &str {
///         "redis"
///     }
///
///     async fn check(&self) -> HealthCheckResult {
///         // In a real implementation, you would ping Redis
///         HealthCheckResult::up("redis")
///             .with_detail("version", "7.0.0")
///     }
///
///     fn is_critical(&self) -> bool {
///         true // Application cannot function without Redis
///     }
/// }
/// ```
#[async_trait]
pub trait HealthIndicator: Send + Sync {
    /// Returns the name of this health indicator
    fn name(&self) -> &str;

    /// Performs the health check and returns the result
    async fn check(&self) -> HealthCheckResult;

    /// Returns whether this indicator is critical for application health.
    /// If a critical indicator fails, the overall status will be DOWN.
    fn is_critical(&self) -> bool {
        false
    }

    /// Returns whether this indicator should be included in readiness checks.
    fn include_in_readiness(&self) -> bool {
        true
    }

    /// Returns whether this indicator should be included in liveness checks.
    fn include_in_liveness(&self) -> bool {
        false
    }
}

/// Memory health indicator that checks system memory usage.
pub struct MemoryHealthIndicator {
    /// Threshold percentage above which status becomes DEGRADED
    pub degraded_threshold: f64,
    /// Threshold percentage above which status becomes DOWN
    pub critical_threshold: f64,
}

impl Default for MemoryHealthIndicator {
    fn default() -> Self {
        Self {
            degraded_threshold: 80.0,
            critical_threshold: 95.0,
        }
    }
}

impl MemoryHealthIndicator {
    /// Creates a new memory health indicator with default thresholds
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new memory health indicator with custom thresholds
    pub fn with_thresholds(degraded: f64, critical: f64) -> Self {
        Self {
            degraded_threshold: degraded,
            critical_threshold: critical,
        }
    }
}

#[async_trait]
impl HealthIndicator for MemoryHealthIndicator {
    fn name(&self) -> &str {
        "memory"
    }

    async fn check(&self) -> HealthCheckResult {
        let start = Instant::now();

        // Get memory info (platform-specific implementation)
        #[cfg(target_os = "linux")]
        let (total, available) = get_linux_memory_info();

        #[cfg(not(target_os = "linux"))]
        let (total, available) = (0u64, 0u64);

        let duration = start.elapsed();

        if total == 0 {
            return HealthCheckResult::unknown("memory")
                .with_detail("reason", "Unable to read memory info")
                .with_duration(duration);
        }

        let used = total.saturating_sub(available);
        let usage_percent = (used as f64 / total as f64) * 100.0;

        let status = if usage_percent >= self.critical_threshold {
            HealthStatus::Down
        } else if usage_percent >= self.degraded_threshold {
            HealthStatus::Degraded
        } else {
            HealthStatus::Up
        };

        let mut result = HealthCheckResult {
            name: "memory".to_string(),
            status,
            details: HashMap::new(),
            duration_ms: Some(duration.as_millis() as u64),
            error: None,
            timestamp: Some(current_timestamp()),
        };

        result
            .details
            .insert("total_mb".to_string(), format!("{}", total / (1024 * 1024)));
        result.details.insert(
            "available_mb".to_string(),
            format!("{}", available / (1024 * 1024)),
        );
        result
            .details
            .insert("used_mb".to_string(), format!("{}", used / (1024 * 1024)));
        result
            .details
            .insert("usage_percent".to_string(), format!("{:.1}", usage_percent));

        result
    }
}

/// Disk health indicator that checks available disk space.
///
/// At most one disk probe runs at a time per indicator: checks that arrive
/// while one is in flight wait for that probe's result rather than starting
/// another, so a hung filesystem cannot pile up stuck blocking threads.
pub struct DiskHealthIndicator {
    /// Path to check disk space for
    pub path: String,
    /// Threshold percentage of used space above which status becomes DEGRADED
    pub degraded_threshold: f64,
    /// Threshold percentage of used space above which status becomes DOWN
    pub critical_threshold: f64,
    probe: DiskProbe,
}

impl Default for DiskHealthIndicator {
    fn default() -> Self {
        Self {
            path: "/".to_string(),
            degraded_threshold: 80.0,
            critical_threshold: 95.0,
            probe: DiskProbe::new(read_disk_info),
        }
    }
}

/// `(total, available)` bytes for a path, or `None` if unreadable.
type DiskInfo = Option<(u64, u64)>;

/// A probe running on the blocking pool, shareable between the checks
/// waiting on it.
type SharedProbe = futures_util::future::Shared<futures_util::future::BoxFuture<'static, DiskInfo>>;

/// Single-flight runner for the blocking disk probe.
///
/// `statvfs` on a hung filesystem (a stale NFS mount) blocks its thread until
/// the filesystem answers, and neither the health service's timeout nor
/// dropping the future can cancel a `spawn_blocking` task. Spawning one per
/// check would let a public health endpoint pile up stuck threads until the
/// blocking pool is exhausted. Instead the in-flight probe is shared: checks
/// that arrive while it runs await the same result (each still bounded by its
/// own timeout, so a hung filesystem reads as DOWN), and a new probe starts
/// only once the previous one has returned.
struct DiskProbe {
    read: Arc<dyn Fn(&str) -> DiskInfo + Send + Sync>,
    in_flight: std::sync::Mutex<Option<SharedProbe>>,
}

impl DiskProbe {
    fn new(read: impl Fn(&str) -> DiskInfo + Send + Sync + 'static) -> Self {
        Self {
            read: Arc::new(read),
            in_flight: std::sync::Mutex::new(None),
        }
    }

    /// The running probe's result, starting a probe if none is running.
    fn sample(&self, path: &str) -> SharedProbe {
        use futures_util::FutureExt;

        // A poisoned lock only means a panic elsewhere mid-update; the slot
        // is still a valid `Option`.
        let mut slot = self
            .in_flight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(probe) = slot.as_ref()
            && probe.peek().is_none()
        {
            return probe.clone();
        }
        let read = Arc::clone(&self.read);
        let path = path.to_owned();
        let probe = tokio::task::spawn_blocking(move || read(&path))
            .map(|joined| joined.ok().flatten())
            .boxed()
            .shared();
        *slot = Some(probe.clone());
        probe
    }
}

/// Disk totals for `path` (blocking).
fn read_disk_info(path: &str) -> DiskInfo {
    #[cfg(unix)]
    {
        get_unix_disk_info(path)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

impl DiskHealthIndicator {
    /// Creates a new disk health indicator for the given path
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            ..Default::default()
        }
    }

    /// Creates a new disk health indicator with custom thresholds
    pub fn with_thresholds(mut self, degraded: f64, critical: f64) -> Self {
        self.degraded_threshold = degraded;
        self.critical_threshold = critical;
        self
    }
}

#[async_trait]
impl HealthIndicator for DiskHealthIndicator {
    fn name(&self) -> &str {
        "disk"
    }

    async fn check(&self) -> HealthCheckResult {
        let start = Instant::now();

        // `statvfs` is a blocking syscall that can hang for as long as the
        // filesystem does (a stale NFS mount), so it runs on the blocking pool
        // rather than stalling an executor thread — and every request queued
        // behind it — for the duration, and only one at a time (see
        // `DiskProbe`). The indicator's timeout still bounds how long the
        // check itself waits.
        let disk_info = self.probe.sample(&self.path).await;

        let duration = start.elapsed();

        match disk_info {
            Some((total, available)) => {
                let used = total.saturating_sub(available);
                let usage_percent = if total > 0 {
                    (used as f64 / total as f64) * 100.0
                } else {
                    0.0
                };

                let status = if usage_percent >= self.critical_threshold {
                    HealthStatus::Down
                } else if usage_percent >= self.degraded_threshold {
                    HealthStatus::Degraded
                } else {
                    HealthStatus::Up
                };

                let mut result = HealthCheckResult {
                    name: "disk".to_string(),
                    status,
                    details: HashMap::new(),
                    duration_ms: Some(duration.as_millis() as u64),
                    error: None,
                    timestamp: Some(current_timestamp()),
                };

                result.details.insert("path".to_string(), self.path.clone());
                result.details.insert(
                    "total_gb".to_string(),
                    format!("{:.1}", total as f64 / 1_073_741_824.0),
                );
                result.details.insert(
                    "available_gb".to_string(),
                    format!("{:.1}", available as f64 / 1_073_741_824.0),
                );
                result.details.insert(
                    "used_gb".to_string(),
                    format!("{:.1}", used as f64 / 1_073_741_824.0),
                );
                result
                    .details
                    .insert("usage_percent".to_string(), format!("{:.1}", usage_percent));

                result
            }
            None => HealthCheckResult::unknown("disk")
                .with_detail("path", &self.path)
                .with_detail("reason", "Unable to read disk info")
                .with_duration(duration),
        }
    }
}

/// Uptime health indicator that reports application uptime.
pub struct UptimeHealthIndicator {
    start_time: Instant,
}

impl Default for UptimeHealthIndicator {
    fn default() -> Self {
        Self::new()
    }
}

impl UptimeHealthIndicator {
    /// Creates a new uptime indicator, recording the current time as start time
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
        }
    }
}

#[async_trait]
impl HealthIndicator for UptimeHealthIndicator {
    fn name(&self) -> &str {
        "uptime"
    }

    async fn check(&self) -> HealthCheckResult {
        let uptime = self.start_time.elapsed();
        let uptime_secs = uptime.as_secs();

        let days = uptime_secs / 86400;
        let hours = (uptime_secs % 86400) / 3600;
        let minutes = (uptime_secs % 3600) / 60;
        let seconds = uptime_secs % 60;

        HealthCheckResult::up("uptime")
            .with_detail("uptime_seconds", uptime_secs.to_string())
            .with_detail(
                "uptime_human",
                format!("{}d {}h {}m {}s", days, hours, minutes, seconds),
            )
    }

    fn include_in_liveness(&self) -> bool {
        true
    }
}

/// Default per-indicator time limit; see [`HealthService::with_indicator_timeout`].
pub const DEFAULT_INDICATOR_TIMEOUT: Duration = Duration::from_secs(5);

/// Service for managing and executing health checks.
pub struct HealthService {
    indicators: RwLock<Vec<Arc<dyn HealthIndicator>>>,
    info: RwLock<Option<HealthInfo>>,
    start_time: Instant,
    indicator_timeout: Duration,
}

impl Default for HealthService {
    fn default() -> Self {
        Self::new()
    }
}

impl HealthService {
    /// Creates a new health service
    pub fn new() -> Self {
        Self {
            indicators: RwLock::new(Vec::new()),
            info: RwLock::new(None),
            start_time: Instant::now(),
            indicator_timeout: DEFAULT_INDICATOR_TIMEOUT,
        }
    }

    /// Bound each indicator's `check()` to `timeout` (default
    /// [`DEFAULT_INDICATOR_TIMEOUT`]). An indicator that does not answer in
    /// time is reported `Down`. Without a bound, one hung dependency stalls
    /// every probe request, and probes piling up on it exhaust the server.
    pub fn with_indicator_timeout(mut self, timeout: Duration) -> Self {
        self.indicator_timeout = timeout;
        self
    }

    /// Run `indicators` concurrently, each under the configured timeout.
    async fn run_indicators(
        &self,
        indicators: Vec<Arc<dyn HealthIndicator>>,
    ) -> Vec<HealthCheckResult> {
        let limit = self.indicator_timeout;
        let futures: Vec<_> = indicators
            .into_iter()
            .map(|indicator| async move {
                let start = Instant::now();
                match tokio::time::timeout(limit, indicator.check()).await {
                    Ok(mut result) => {
                        if result.duration_ms.is_none() {
                            result.duration_ms = Some(start.elapsed().as_millis() as u64);
                        }
                        result
                    }
                    Err(_) => {
                        let mut result = HealthCheckResult::down(indicator.name())
                            .with_error(format!("timed out after {} ms", limit.as_millis()));
                        result.duration_ms = Some(start.elapsed().as_millis() as u64);
                        result
                    }
                }
            })
            .collect();
        join_all(futures).await
    }

    /// [`check`](Self::check) reduced to the overall status, for endpoints
    /// served without authentication. See [`HealthResponse::summary_only`].
    pub async fn check_summary(&self) -> HealthResponse {
        self.check().await.summary_only()
    }

    /// Creates a health service with default indicators (memory, disk, uptime)
    pub fn with_defaults() -> Self {
        // Note: indicators are added asynchronously, so use builder pattern for sync construction
        Self::new()
    }

    /// Registers a health indicator
    pub async fn register(&self, indicator: impl HealthIndicator + 'static) {
        let mut indicators = self.indicators.write().await;
        indicators.push(Arc::new(indicator));
    }

    /// Sets the application info
    pub async fn set_info(&self, info: HealthInfo) {
        let mut app_info = self.info.write().await;
        *app_info = Some(info);
    }

    /// Performs a full health check on all registered indicators
    pub async fn check(&self) -> HealthResponse {
        let indicators = self.indicators.read().await;
        let mut response = HealthResponse::new(HealthStatus::Up);

        // Add info with uptime
        if let Some(mut info) = self.info.read().await.clone() {
            info.uptime_seconds = Some(self.start_time.elapsed().as_secs());
            response.info = Some(info);
        }

        // Run all health checks concurrently, each under the timeout.
        let all: Vec<_> = indicators.iter().cloned().collect();
        drop(indicators);
        let results = self.run_indicators(all).await;

        for result in results {
            response.components.insert(result.name.clone(), result);
        }

        response.calculate_status();
        response
    }

    /// Performs a liveness check (minimal check to verify the app is running)
    pub async fn check_liveness(&self) -> HealthResponse {
        let indicators = self.indicators.read().await;
        let mut response = HealthResponse::new(HealthStatus::Up);

        // Only include liveness indicators
        let liveness_indicators: Vec<_> = indicators
            .iter()
            .filter(|i| i.include_in_liveness())
            .cloned()
            .collect();

        drop(indicators);
        let results = self.run_indicators(liveness_indicators).await;

        for result in results {
            response.components.insert(result.name.clone(), result);
        }

        // Liveness is UP if the application is responding
        response.status = HealthStatus::Up;
        response
    }

    /// Performs a readiness check (checks if the app can serve traffic)
    pub async fn check_readiness(&self) -> HealthResponse {
        let indicators = self.indicators.read().await;
        let mut response = HealthResponse::new(HealthStatus::Up);

        // Only include readiness indicators
        let readiness_indicators: Vec<_> = indicators
            .iter()
            .filter(|i| i.include_in_readiness())
            .cloned()
            .collect();

        drop(indicators);
        let results = self.run_indicators(readiness_indicators).await;

        for result in results {
            response.components.insert(result.name.clone(), result);
        }

        response.calculate_status();
        response
    }

    /// [`check_liveness`](Self::check_liveness) reduced to its overall status,
    /// for a probe endpoint served without authentication. See
    /// [`HealthResponse::summary_only`].
    pub async fn check_liveness_summary(&self) -> HealthResponse {
        self.check_liveness().await.summary_only()
    }

    /// [`check_readiness`](Self::check_readiness) reduced to its overall
    /// status, for a probe endpoint served without authentication. See
    /// [`HealthResponse::summary_only`].
    pub async fn check_readiness_summary(&self) -> HealthResponse {
        self.check_readiness().await.summary_only()
    }

    /// Returns the number of registered indicators
    pub async fn indicator_count(&self) -> usize {
        self.indicators.read().await.len()
    }
}

// Platform-specific implementations

#[cfg(target_os = "linux")]
fn get_linux_memory_info() -> (u64, u64) {
    use std::fs;

    let meminfo = match fs::read_to_string("/proc/meminfo") {
        Ok(content) => content,
        Err(_) => return (0, 0),
    };

    let mut total: u64 = 0;
    let mut available: u64 = 0;

    for line in meminfo.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let value: u64 = parts[1].parse().unwrap_or(0) * 1024; // Convert from kB to bytes
            match parts[0] {
                "MemTotal:" => total = value,
                "MemAvailable:" => available = value,
                _ => {}
            }
        }
    }

    (total, available)
}

/// Total and available bytes on the filesystem holding `path`, via
/// `statvfs(3)`.
///
/// A direct syscall rather than spawning `df`: no `PATH` lookup (a planted
/// `df` earlier in `PATH` would run with the server's privileges), no argument
/// parsing (a `path` starting with `-` was read as an option), and no
/// locale-dependent output to parse.
#[cfg(unix)]
fn get_unix_disk_info(path: &str) -> Option<(u64, u64)> {
    let c_path = std::ffi::CString::new(path).ok()?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `c_path` is a valid NUL-terminated string that outlives the
    // call, and `stat` points to writable storage of the right type.
    let rc = unsafe { libc::statvfs(c_path.as_ptr(), stat.as_mut_ptr()) };
    if rc != 0 {
        return None;
    }
    // SAFETY: statvfs returned 0, so it fully initialized `stat`.
    let stat = unsafe { stat.assume_init() };
    // The field widths differ across platforms (u32 on some, u64 on others).
    #[allow(clippy::unnecessary_cast)]
    let (frsize, blocks, avail) = (
        stat.f_frsize as u64,
        stat.f_blocks as u64,
        stat.f_bavail as u64,
    );
    Some((blocks.saturating_mul(frsize), avail.saturating_mul(frsize)))
}

/// Returns the current Unix timestamp in seconds
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Builder for creating a HealthService with fluent API
pub struct HealthServiceBuilder {
    indicators: Vec<Arc<dyn HealthIndicator>>,
    info: Option<HealthInfo>,
    indicator_timeout: Duration,
}

impl Default for HealthServiceBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl HealthServiceBuilder {
    /// Creates a new builder
    pub fn new() -> Self {
        Self {
            indicators: Vec::new(),
            info: None,
            indicator_timeout: DEFAULT_INDICATOR_TIMEOUT,
        }
    }

    /// Per-indicator time limit; see [`HealthService::with_indicator_timeout`].
    pub fn with_indicator_timeout(mut self, timeout: Duration) -> Self {
        self.indicator_timeout = timeout;
        self
    }

    /// Adds a health indicator
    pub fn with_indicator(mut self, indicator: impl HealthIndicator + 'static) -> Self {
        self.indicators.push(Arc::new(indicator));
        self
    }

    /// Adds default indicators (memory, disk, uptime)
    pub fn with_defaults(self) -> Self {
        self.with_indicator(MemoryHealthIndicator::default())
            .with_indicator(DiskHealthIndicator::default())
            .with_indicator(UptimeHealthIndicator::default())
    }

    /// Sets the application info
    pub fn with_info(mut self, info: HealthInfo) -> Self {
        self.info = Some(info);
        self
    }

    /// Builds the health service
    pub fn build(self) -> HealthService {
        HealthService {
            indicators: RwLock::new(self.indicators),
            info: RwLock::new(self.info),
            start_time: Instant::now(),
            indicator_timeout: self.indicator_timeout,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct HangingIndicator;

    #[async_trait]
    impl HealthIndicator for HangingIndicator {
        fn name(&self) -> &str {
            "hangs"
        }
        async fn check(&self) -> HealthCheckResult {
            std::future::pending().await
        }
        fn include_in_liveness(&self) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn test_hung_indicator_times_out_as_down() {
        let service = HealthService::new().with_indicator_timeout(Duration::from_millis(20));
        service.register(HangingIndicator).await;
        service.register(UptimeHealthIndicator::new()).await;

        let response = tokio::time::timeout(Duration::from_secs(5), service.check())
            .await
            .expect("a hung indicator must not stall the health check");
        assert_eq!(response.components["hangs"].status, HealthStatus::Down);
        assert_eq!(response.status, HealthStatus::Down);

        let live = tokio::time::timeout(Duration::from_secs(5), service.check_liveness())
            .await
            .unwrap();
        assert_eq!(live.components["hangs"].status, HealthStatus::Down);
    }

    #[tokio::test]
    async fn test_probe_summaries_hide_details() {
        let service = HealthService::new();
        service.register(UptimeHealthIndicator::new()).await;
        for summary in [
            service.check_liveness_summary().await,
            service.check_readiness_summary().await,
        ] {
            assert!(summary.components.is_empty());
            assert!(summary.info.is_none());
            assert_eq!(summary.status, HealthStatus::Up);
        }
    }

    #[tokio::test]
    async fn test_summary_only_hides_details() {
        let service = HealthService::new();
        service.register(UptimeHealthIndicator::new()).await;
        service
            .set_info(HealthInfo::new("svc").with_version("1.2.3"))
            .await;
        let summary = service.check_summary().await;
        assert!(summary.components.is_empty());
        assert!(summary.info.is_none());
        let json = serde_json::to_string(&summary).unwrap();
        assert!(!json.contains("1.2.3"));
    }

    #[test]
    fn test_health_status_is_healthy() {
        assert!(HealthStatus::Up.is_healthy());
        assert!(HealthStatus::Degraded.is_healthy());
        assert!(!HealthStatus::Down.is_healthy());
        assert!(!HealthStatus::Unknown.is_healthy());
    }

    #[test]
    fn test_health_status_http_codes() {
        assert_eq!(HealthStatus::Up.http_status_code(), 200);
        assert_eq!(HealthStatus::Degraded.http_status_code(), 200);
        assert_eq!(HealthStatus::Down.http_status_code(), 503);
        assert_eq!(HealthStatus::Unknown.http_status_code(), 503);
    }

    #[test]
    fn test_health_check_result_builders() {
        let up = HealthCheckResult::up("test");
        assert_eq!(up.status, HealthStatus::Up);
        assert_eq!(up.name, "test");

        let down = HealthCheckResult::down("test");
        assert_eq!(down.status, HealthStatus::Down);

        let degraded = HealthCheckResult::degraded("test");
        assert_eq!(degraded.status, HealthStatus::Degraded);

        let unknown = HealthCheckResult::unknown("test");
        assert_eq!(unknown.status, HealthStatus::Unknown);
    }

    #[test]
    fn test_health_check_result_with_details() {
        let result = HealthCheckResult::up("database")
            .with_detail("type", "postgresql")
            .with_detail("pool_size", "10");

        assert_eq!(result.details.get("type"), Some(&"postgresql".to_string()));
        assert_eq!(result.details.get("pool_size"), Some(&"10".to_string()));
    }

    #[test]
    fn test_health_check_result_with_error() {
        let result = HealthCheckResult::up("database").with_error("Connection failed");

        assert_eq!(result.status, HealthStatus::Down);
        assert_eq!(result.error, Some("Connection failed".to_string()));
    }

    #[test]
    fn test_health_response_calculate_status() {
        let mut response = HealthResponse::new(HealthStatus::Up)
            .with_component(HealthCheckResult::up("db"))
            .with_component(HealthCheckResult::up("cache"));

        response.calculate_status();
        assert_eq!(response.status, HealthStatus::Up);

        // Add a down component
        response
            .components
            .insert("external".to_string(), HealthCheckResult::down("external"));
        response.calculate_status();
        assert_eq!(response.status, HealthStatus::Down);
    }

    #[test]
    fn test_health_info_builder() {
        let info = HealthInfo::new("my-app")
            .with_version("1.0.0")
            .with_description("Test application");

        assert_eq!(info.name, Some("my-app".to_string()));
        assert_eq!(info.version, Some("1.0.0".to_string()));
        assert_eq!(info.description, Some("Test application".to_string()));
    }

    #[tokio::test]
    async fn test_health_service_register() {
        let service = HealthService::new();
        service.register(UptimeHealthIndicator::new()).await;

        assert_eq!(service.indicator_count().await, 1);
    }

    #[tokio::test]
    async fn test_health_service_check() {
        let service = HealthServiceBuilder::new()
            .with_indicator(UptimeHealthIndicator::new())
            .build();

        let response = service.check().await;
        assert_eq!(response.status, HealthStatus::Up);
        assert!(response.components.contains_key("uptime"));
    }

    #[tokio::test]
    async fn test_health_service_builder() {
        let service = HealthServiceBuilder::new()
            .with_info(HealthInfo::new("test-app").with_version("1.0.0"))
            .with_indicator(UptimeHealthIndicator::new())
            .build();

        let response = service.check().await;
        assert!(response.info.is_some());
        assert_eq!(response.info.unwrap().name, Some("test-app".to_string()));
    }

    #[test]
    fn test_health_status_display() {
        assert_eq!(format!("{}", HealthStatus::Up), "UP");
        assert_eq!(format!("{}", HealthStatus::Down), "DOWN");
        assert_eq!(format!("{}", HealthStatus::Degraded), "DEGRADED");
        assert_eq!(format!("{}", HealthStatus::Unknown), "UNKNOWN");
    }

    #[tokio::test]
    async fn test_uptime_indicator() {
        let indicator = UptimeHealthIndicator::new();

        // Wait a tiny bit to ensure uptime is measurable
        tokio::time::sleep(Duration::from_millis(10)).await;

        let result = indicator.check().await;
        assert_eq!(result.status, HealthStatus::Up);
        assert!(result.details.contains_key("uptime_seconds"));
        assert!(result.details.contains_key("uptime_human"));
    }

    #[tokio::test]
    async fn test_memory_indicator() {
        let indicator = MemoryHealthIndicator::default();
        let result = indicator.check().await;

        // On non-Linux systems, this will return Unknown
        #[cfg(target_os = "linux")]
        {
            assert!(result.details.contains_key("total_mb"));
            assert!(result.details.contains_key("available_mb"));
        }
    }

    /// L10: disk info comes from statvfs, not a spawned `df`, so an
    /// option-looking or NUL-containing path cannot be misinterpreted.
    #[cfg(unix)]
    #[test]
    fn test_disk_info_uses_statvfs() {
        let (total, avail) = get_unix_disk_info("/").expect("statvfs on /");
        assert!(total > 0 && avail <= total);
        assert!(get_unix_disk_info("--version").is_none());
        assert!(get_unix_disk_info("/\0").is_none());
        assert!(get_unix_disk_info("/nonexistent/armature/path").is_none());
    }

    /// A hung filesystem must not cost one stuck blocking thread per health
    /// request: checks that arrive while a probe is stuck share it, and a new
    /// probe starts only after it returns.
    #[tokio::test]
    async fn test_disk_probe_is_single_flight() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let calls = Arc::new(AtomicUsize::new(0));
        let (release, gate) = std::sync::mpsc::channel::<()>();
        let gate = std::sync::Mutex::new(gate);
        let indicator = DiskHealthIndicator {
            probe: DiskProbe::new({
                let calls = Arc::clone(&calls);
                move |_path: &str| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    // Hang like a stale mount until released.
                    let _ = gate.lock().unwrap().recv();
                    Some((100, 90))
                }
            }),
            ..DiskHealthIndicator::new("/")
        };

        for _ in 0..5 {
            let timed_out =
                tokio::time::timeout(Duration::from_millis(20), indicator.check()).await;
            assert!(timed_out.is_err(), "the probe is hung");
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1, "one probe, not five");

        // The filesystem answers: the stuck probe's result is used, then the
        // next check starts a fresh probe.
        release.send(()).unwrap();
        let result = indicator.check().await;
        assert_eq!(result.status, HealthStatus::Up);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        release.send(()).unwrap();
        let result = indicator.check().await;
        assert_eq!(result.status, HealthStatus::Up);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_disk_indicator() {
        let indicator = DiskHealthIndicator::new("/");
        let result = indicator.check().await;

        #[cfg(unix)]
        {
            assert!(result.details.contains_key("path"));
        }
    }

    #[test]
    fn test_health_response_serialization() {
        let response =
            HealthResponse::new(HealthStatus::Up).with_component(HealthCheckResult::up("test"));

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"status\":\"UP\""));
    }
}
