//! Resolver file watcher for hot-reload
//!
//! Watches a file for changes and updates the resolver database.
//! File format: one resolver per line
//! Format: <transport>:<address>[:<tags>]
//! Example:
//!   dns_udp:1.1.1.1:53
//!   doh:https://cloudflare-dns.com/dns-query:cloudflare,fast
//!   doq:dns.adguard-dns.com:853

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::fs;
use tokio::time::{interval, Duration};

use super::{ResolverDb, ResolverRecord};
use crate::transport::TransportType;

/// File watcher configuration
#[derive(Debug, Clone)]
pub struct FileWatcherConfig {
    /// Path to resolver file
    pub path: PathBuf,
    /// Poll interval
    pub poll_interval: Duration,
    /// Auto-reload on change
    pub auto_reload: bool,
}

impl Default for FileWatcherConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("resolvers.txt"),
            poll_interval: Duration::from_secs(30),
            auto_reload: true,
        }
    }
}

/// Parse a resolver line
/// Format: <transport>:<address>[:<tags>]
pub fn parse_resolver_line(line: &str) -> Option<(TransportType, String, Vec<String>)> {
    let line = line.trim();
    
    // Skip empty lines and comments
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    let parts: Vec<&str> = line.splitn(3, ':').collect();
    if parts.len() < 2 {
        return None;
    }

    let transport: TransportType = parts[0].parse().ok()?;
    
    // Handle address (may contain : for ports or URLs)
    let address = if parts.len() >= 2 {
        // For DoH, the URL contains ://, so we need to rejoin
        if transport == TransportType::DoH {
            // DoH format: doh:https://example.com/dns-query:tags
            // parts[1] = "https"
            // The rest of the line after "doh:" is the URL (and optional tags)
            let after_transport = &line[parts[0].len() + 1..];
            let tag_start = after_transport.rfind(':');
            
            // Check if the last : is part of a URL or tags
            if let Some(pos) = tag_start {
                let potential_url = &after_transport[..pos];
                let potential_tags = &after_transport[pos + 1..];
                
                // If potential_tags looks like tags (no /), treat as tags
                if !potential_tags.contains('/') && !potential_tags.is_empty() 
                    && !potential_tags.starts_with('/') {
                    return Some((
                        transport,
                        potential_url.to_string(),
                        potential_tags.split(',').map(|s| s.trim().to_string()).collect(),
                    ));
                }
            }
            after_transport.to_string()
        } else {
            // For other transports: transport:host:port[:tags]
            if parts.len() >= 3 {
                // Check if third part is port or tags
                if let Ok(_port) = parts[2].parse::<u16>() {
                    format!("{}:{}", parts[1], parts[2])
                } else {
                    // Third part is tags
                    return Some((
                        transport,
                        format!("{}:53", parts[1]), // Default port
                        parts[2].split(',').map(|s| s.trim().to_string()).collect(),
                    ));
                }
            } else {
                format!("{}:53", parts[1]) // Default port
            }
        }
    } else {
        return None;
    };

    // Parse tags if present (fourth part for non-DoH)
    let tags = if !transport.to_string().contains("doh") && parts.len() > 3 {
        parts[3].split(',').map(|s| s.trim().to_string()).collect()
    } else {
        Vec::new()
    };

    Some((transport, address, tags))
}

/// Load resolvers from a file
pub async fn load_from_file(path: &Path) -> Result<Vec<(TransportType, String, Vec<String>)>, std::io::Error> {
    let content = fs::read_to_string(path).await?;
    
    let resolvers: Vec<_> = content
        .lines()
        .filter_map(parse_resolver_line)
        .collect();

    Ok(resolvers)
}

/// File watcher for resolver database
pub struct ResolverFileWatcher {
    config: FileWatcherConfig,
    db: Arc<ResolverDb>,
    last_modified: RwLock<Option<std::time::SystemTime>>,
    running: RwLock<bool>,
}

impl ResolverFileWatcher {
    pub fn new(config: FileWatcherConfig, db: Arc<ResolverDb>) -> Self {
        Self {
            config,
            db,
            last_modified: RwLock::new(None),
            running: RwLock::new(false),
        }
    }

    /// Load resolvers from file (one-time)
    pub async fn load(&self) -> Result<usize, std::io::Error> {
        let resolvers = load_from_file(&self.config.path).await?;
        let count = resolvers.len();

        for (transport, address, tags) in resolvers {
            let id = self.db.add_resolver(transport, address.clone()).await
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
            
            // Update tags if present
            if !tags.is_empty() {
                if let Ok(mut record) = self.db.get_resolver(id).await {
                    record.tags = tags;
                    let _ = self.db.update_resolver(record).await;
                }
            }
        }

        // Update last modified time
        if let Ok(metadata) = fs::metadata(&self.config.path).await {
            if let Ok(modified) = metadata.modified() {
                *self.last_modified.write().await = Some(modified);
            }
        }

        log::info!("Loaded {} resolvers from {:?}", count, self.config.path);
        Ok(count)
    }

    /// Start watching for file changes
    pub async fn start_watching(&self) {
        if !self.config.auto_reload {
            return;
        }

        *self.running.write().await = true;
        
        let mut interval = interval(self.config.poll_interval);
        
        while *self.running.read().await {
            interval.tick().await;

            // Check if file has changed
            if let Ok(metadata) = fs::metadata(&self.config.path).await {
                if let Ok(modified) = metadata.modified() {
                    let last = self.last_modified.read().await;
                    
                    if last.map(|l| modified > l).unwrap_or(true) {
                        drop(last);
                        
                        log::info!("Resolver file changed, reloading...");
                        
                        // Clear and reload
                        self.db.clear().await;
                        if let Err(e) = self.load().await {
                            log::error!("Failed to reload resolvers: {}", e);
                        }
                    }
                }
            }
        }
    }

    /// Stop watching
    pub async fn stop(&self) {
        *self.running.write().await = false;
    }
}

/// Parse resolver from JSON
/// Format: {"addr": "1.1.1.1:53", "transport": "dns_udp", "tags": ["tag1"]}
pub fn parse_resolver_json(json: &str) -> Option<(TransportType, String, Vec<String>)> {
    let value: serde_json::Value = serde_json::from_str(json).ok()?;
    
    let transport_str = value.get("transport")?.as_str()?;
    let transport: TransportType = transport_str.parse().ok()?;
    
    let addr = value.get("addr")?.as_str()?.to_string();
    
    let tags: Vec<String> = value.get("tags")
        .and_then(|t| t.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();

    Some((transport, addr, tags))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_resolver_line() {
        // DNS-UDP
        let (t, a, tags) = parse_resolver_line("dns_udp:1.1.1.1:53").unwrap();
        assert_eq!(t, TransportType::DnsUdp);
        assert_eq!(a, "1.1.1.1:53");
        assert!(tags.is_empty());

        // DNS-UDP with default port
        let (t, a, _) = parse_resolver_line("dns:8.8.8.8").unwrap();
        assert_eq!(t, TransportType::DnsUdp);
        assert_eq!(a, "8.8.8.8:53");

        // DoH
        let (t, a, _) = parse_resolver_line("doh:https://cloudflare-dns.com/dns-query").unwrap();
        assert_eq!(t, TransportType::DoH);
        assert!(a.starts_with("https://"));

        // DoQ
        let (t, a, _) = parse_resolver_line("doq:dns.adguard-dns.com:853").unwrap();
        assert_eq!(t, TransportType::DoQ);
        assert_eq!(a, "dns.adguard-dns.com:853");

        // Comments and empty lines
        assert!(parse_resolver_line("# comment").is_none());
        assert!(parse_resolver_line("").is_none());
        assert!(parse_resolver_line("  ").is_none());
    }

    #[test]
    fn test_parse_resolver_json() {
        let json = r#"{"addr": "1.1.1.1:53", "transport": "dns_udp", "tags": ["fast", "reliable"]}"#;
        let (t, a, tags) = parse_resolver_json(json).unwrap();
        
        assert_eq!(t, TransportType::DnsUdp);
        assert_eq!(a, "1.1.1.1:53");
        assert_eq!(tags, vec!["fast", "reliable"]);
    }
}
