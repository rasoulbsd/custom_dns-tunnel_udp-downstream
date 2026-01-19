use anyhow::{Context, Result};
use clap::Parser;
use dns_tunnel::{
    config::{load_client_config, ResponseMode, ClientConfig},
    dns_codec::DnsCodec,
    packet::{fragment_packet, PacketReassembler},
    utils::{get_random_port, rotate_resolver},
};
use hickory_proto::{
    op::Message,
    serialize::binary::{BinDecodable, BinEncodable, BinEncoder},
};
use log::{debug, error, info, warn};
use rand::Rng;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};

#[derive(Parser)]
#[command(name = "dns-tunnel-client")]
#[command(about = "DNS Tunnel Client (Iran side)")]
struct Args {
    #[arg(short, long)]
    config: Option<String>,
    #[arg(short = 'a', long, default_value = "127.0.0.1")]
    local_addr: String,
    #[arg(short = 'p', long)]
    local_port: Option<u16>,
    #[arg(short, long)]
    domains: Vec<String>,
    #[arg(short, long)]
    resolvers: Vec<String>,
    #[arg(long, default_value = "63")]
    max_subdomain_length: usize,
    #[arg(long)]
    no_rotate_resolvers: bool,
    #[arg(long)]
    randomize_local_port: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();
    
    let mut config = if let Some(config_path) = args.config {
        load_client_config(Some(config_path.into()))?
    } else {
        ClientConfig::default()
    };

    // Override with CLI args
    if !args.domains.is_empty() {
        config.domains = args.domains;
    }
    if !args.resolvers.is_empty() {
        config.resolvers = args.resolvers
            .iter()
            .map(|r| r.parse())
            .collect::<Result<Vec<_>, _>>()
            .context("Invalid resolver address")?;
    }
    if args.max_subdomain_length > 0 {
        config.max_subdomain_length = args.max_subdomain_length;
    }
    config.rotate_resolvers = !args.no_rotate_resolvers;
    config.randomize_local_port = args.randomize_local_port;

    // Note: min_subdomain_length and response_mode should be set in config file

    // Set local UDP address and port
    // Use config's local_udp if no CLI args provided, otherwise use CLI args
    // Check if user provided CLI args (not just defaults)
    let local_udp: SocketAddr = if args.local_port.is_some() {
        // User provided port via CLI, use CLI args
    let local_port = if config.randomize_local_port {
        get_random_port()
    } else {
        args.local_port.unwrap_or_else(|| {
            config.local_udp.port()
        })
    };
        format!("{}:{}", args.local_addr, local_port)
            .parse()
            .context("Invalid local UDP address")?
    } else {
        // No CLI port provided, use config's local_udp (respects 0.0.0.0 if set in config)
        if config.randomize_local_port {
            let port = get_random_port();
            format!("{}:{}", config.local_udp.ip(), port)
        .parse()
                .context("Invalid local UDP address")?
        } else {
            // Use config's address and port directly (this respects 0.0.0.0 from config)
            config.local_udp
        }
    };

    info!("Starting DNS Tunnel Client");
    info!("Local UDP: {}", local_udp);
    info!("Plain mode: {} (bypasses DNS encoding)", config.plain_mode);
    if config.plain_mode {
        warn!("PLAIN MODE ENABLED: Sending raw UDP packets directly (no DNS encoding)");
    }
    info!("Domains: {:?}", config.domains);
    info!("Resolvers: {:?}", config.resolvers);
    
    // Extract server addresses to filter out (prevent loops)
    let mut server_addresses: Vec<SocketAddr> = config.resolvers.clone();
    if let Some(udp_addr) = config.server_udp_addr {
        if !server_addresses.contains(&udp_addr) {
            server_addresses.push(udp_addr);
        }
    }
    info!("Server addresses (will be filtered from local UDP): {:?}", server_addresses);
    info!("Server UDP address (for UDP uplink): {:?}", config.server_udp_addr);
    info!("Max subdomain length: {} (DNS label limit: 63)", config.max_subdomain_length);
    if config.max_subdomain_length > 63 {
        warn!("max_subdomain_length ({}) exceeds DNS label limit (63), will be capped", config.max_subdomain_length);
    }
    info!("Min subdomain length: {}", config.min_subdomain_length);
    info!("Uplink mode: {:?} (how client sends to server)", config.uplink_mode);
    info!("Response mode: {:?} (what responses client listens for)", config.response_mode);
    info!("Resolver rotation: {}", config.rotate_resolvers);

    if config.domains.is_empty() {
        anyhow::bail!("At least one domain must be specified");
    }
    if config.resolvers.is_empty() {
        anyhow::bail!("At least one resolver must be specified");
    }

    // Bind local UDP socket for receiving from applications
    let udp_socket = Arc::new(UdpSocket::bind(&local_udp)
        .await
        .context("Failed to bind local UDP socket")?);
    info!("Bound to local UDP: {}", local_udp);
    
    // Create separate sockets for DNS queries and responses
    // This allows better separation for monitoring and debugging
    let dns_query_socket = Arc::new(UdpSocket::bind("0.0.0.0:0")
        .await
        .context("Failed to bind DNS query socket")?);
    
    // Separate socket for receiving DNS responses (if DNS or hybrid mode)
    // This makes it easier to monitor DNS traffic separately from UDP
    let dns_response_socket = if matches!(config.response_mode, ResponseMode::Dns | ResponseMode::Hybrid | ResponseMode::HybridAlias) {
        Some(Arc::new(UdpSocket::bind("0.0.0.0:0")
            .await
            .context("Failed to bind DNS response socket")?))
    } else {
        None
    };

    let codec = Arc::new(DnsCodec::new_with_min(config.max_subdomain_length, config.min_subdomain_length));
    let reassembler = Arc::new(Mutex::new(PacketReassembler::new()));
    let pending_requests: Arc<Mutex<HashMap<u16, (SocketAddr, u16)>>> = Arc::new(Mutex::new(HashMap::new()));
    let resolver_index = Arc::new(Mutex::new(0usize));
    
    // Deduplication: track packet_ids that have been successfully reassembled
    // This prevents processing duplicate responses when using hybrid mode
    use std::collections::HashSet;
    let processed_response_ids: Arc<Mutex<HashSet<u16>>> = Arc::new(Mutex::new(HashSet::new()));

    // Spawn task to receive DNS responses on the query socket (if DNS or hybrid mode)
    // CRITICAL: We MUST receive responses on the SAME socket we send queries from,
    // because the server replies to the query source port. Using a separate socket
    // causes port mismatch (server sends to query port, but we listen on response port).
    if matches!(config.response_mode, ResponseMode::Dns | ResponseMode::Hybrid | ResponseMode::HybridAlias) {
        let dns_query_sock_for_response = dns_query_socket.clone();
        let codec_dns = codec.clone();
        let reassembler_dns = reassembler.clone();
        let pending_requests_dns = pending_requests.clone();
        let processed_response_ids_dns = processed_response_ids.clone();
        let udp_socket_dns = udp_socket.clone();
        let domains = config.domains.clone();
        
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            let query_socket_addr = dns_query_sock_for_response.local_addr().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
            info!("[DNS-RESPONSE] Listening for responses on query socket: {}", query_socket_addr);
            loop {
                match dns_query_sock_for_response.recv_from(&mut buf).await {
                    Ok((len, dns_source)) => {
                        let response_data = &buf[..len];
                        info!("[DNS-RESPONSE] Received {} bytes from {} on query socket", len, dns_source);
                    
                        match Message::from_bytes(response_data) {
                            Ok(message) => {
                                match codec_dns.decode_from_dns_response(&message, &domains) {
                                    Ok(Some(packet)) => {
                                        // Deduplication: skip if already processed
                                        {
                                            let processed = processed_response_ids_dns.lock().await;
                                            if processed.contains(&packet.packet_id) {
                                                debug!("[DNS-RESPONSE] Skipping packet_id {} (already processed)", packet.packet_id);
                                                continue;
                                            }
                                        }
                                        
                                        info!("[DNS-RESPONSE] Decoded: packet_id={}, fragment={}/{}", 
                                               packet.packet_id, packet.fragment_id + 1, packet.total_fragments);
                                        
                                        let mut reass = reassembler_dns.lock().await;
                                        if let Some(reassembled_data) = reass.add_fragment(packet.clone()) {
                                            // Find the original source
                                            let mut pending = pending_requests_dns.lock().await;
                                            if let Some((original_source, _)) = pending.remove(&packet.packet_id) {
                                                // Mark as processed
                                                {
                                                    let mut processed = processed_response_ids_dns.lock().await;
                                                    processed.insert(packet.packet_id);
                                                    if processed.len() > 1000 { processed.clear(); }
                                                }
                                                // Forward reassembled packet to original source
                                                if let Err(e) = udp_socket_dns.send_to(&reassembled_data, original_source).await {
                                                    error!("Failed to send reassembled packet: {}", e);
                                                } else {
                                                    info!("[DNS-RESPONSE] Sent reassembled packet {} ({} bytes) to {}", 
                                                          packet.packet_id, reassembled_data.len(), original_source);
                                                }
                                            } else {
                                                debug!("[DNS-RESPONSE] No pending request for packet_id {} (likely already handled by UDP)", packet.packet_id);
                                            }
                                        }
                                    }
                                    Ok(None) => {
                                        // Not a tunnel DNS response, ignore
                                        debug!("[DNS-RESPONSE] Does not match tunnel format");
                                    }
                                    Err(e) => {
                                        debug!("[DNS-RESPONSE] Failed to decode: {}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                debug!("[DNS-RESPONSE] Failed to parse: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("[DNS-RESPONSE] Error receiving on query socket: {}", e);
                        sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        });
    }
    
    // Also spawn task on separate dns_response_socket if it exists (for backward compatibility)
    // But responses should primarily come through dns_query_socket
    if let Some(dns_response_sock) = dns_response_socket {
        let codec_dns = codec.clone();
        let reassembler_dns = reassembler.clone();
        let pending_requests_dns = pending_requests.clone();
        let processed_response_ids_dns = processed_response_ids.clone();
        let udp_socket_dns = udp_socket.clone();
        let domains = config.domains.clone();
        
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            let response_socket_addr = dns_response_sock.local_addr().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
            warn!("[DNS-RESPONSE] Also listening on separate response socket: {} (responses should come through query socket)", response_socket_addr);
            loop {
                match dns_response_sock.recv_from(&mut buf).await {
                    Ok((len, dns_source)) => {
                        let response_data = &buf[..len];
                        info!("[DNS-RESPONSE] Received {} bytes from {} on separate response socket", len, dns_source);
                    
                        match Message::from_bytes(response_data) {
                        Ok(message) => {
                            match codec_dns.decode_from_dns_response(&message, &domains) {
                                Ok(Some(packet)) => {
                                    // Deduplication: skip if already processed
                                    {
                                        let processed = processed_response_ids_dns.lock().await;
                                        if processed.contains(&packet.packet_id) {
                                            debug!("[DNS-RESPONSE] Skipping packet_id {} (already processed)", packet.packet_id);
                                            continue;
                                        }
                                    }
                                    
                                    info!("[DNS-RESPONSE] Decoded: packet_id={}, fragment={}/{}", 
                                           packet.packet_id, packet.fragment_id + 1, packet.total_fragments);
                                    
                                    let mut reass = reassembler_dns.lock().await;
                                    if let Some(reassembled_data) = reass.add_fragment(packet.clone()) {
                                        // Find the original source
                                        let mut pending = pending_requests_dns.lock().await;
                                        if let Some((original_source, _)) = pending.remove(&packet.packet_id) {
                                            // Mark as processed
                                            {
                                                let mut processed = processed_response_ids_dns.lock().await;
                                                processed.insert(packet.packet_id);
                                                if processed.len() > 1000 { processed.clear(); }
                                            }
                                            // Forward reassembled packet to original source
                                            if let Err(e) = udp_socket_dns.send_to(&reassembled_data, original_source).await {
                                                error!("Failed to send reassembled packet: {}", e);
                                            } else {
                                                info!("[DNS-RESPONSE] Sent reassembled packet {} ({} bytes) to {}", 
                                                      packet.packet_id, reassembled_data.len(), original_source);
                                            }
                                        } else {
                                            debug!("[DNS-RESPONSE] No pending request for packet_id {} (likely already handled by UDP)", packet.packet_id);
                                        }
                                    }
                                }
                                Ok(None) => {
                                    // Not a tunnel DNS response, ignore
                                    debug!("[DNS-RESPONSE] Does not match tunnel format");
                                }
                                Err(e) => {
                                    debug!("[DNS-RESPONSE] Failed to decode: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            debug!("[DNS-RESPONSE] Failed to parse: {}", e);
                        }
                    }
                }
                Err(e) => {
                    error!("[DNS-RESPONSE] Error receiving: {}", e);
                    sleep(Duration::from_millis(100)).await;
                }
            }
        }
        });
    }

    // Main loop: receive packets and handle both local UDP and DNS responses
    let mut buf = vec![0u8; 65535];
    let mut packet_id_counter = 0u16;
    
    loop {
        match udp_socket.recv_from(&mut buf).await {
            Ok((len, source)) => {
                let data = &buf[..len];
                debug!("Received {} bytes from {}", len, source);
                
                // Plain mode: treat all UDP as direct responses
                if config.plain_mode {
                    let data_preview = String::from_utf8_lossy(&data[..data.len().min(10)]);
                    info!("[PLAIN-MODE] Received {} bytes from {}: {:?}", len, source, data_preview);
                    // In plain mode, forward directly to original source
                    let mut pending = pending_requests.lock().await;
                    // Use packet_id 0 for plain mode matching
                    if let Some((original_source, _)) = pending.remove(&0) {
                        if let Err(e) = udp_socket.send_to(data, original_source).await {
                            error!("[PLAIN-MODE] Failed to forward to {}: {}", original_source, e);
                        } else {
                            info!("[PLAIN-MODE] Forwarded {} bytes to {}", len, original_source);
                        }
                    } else {
                        debug!("[PLAIN-MODE] No pending request for packet_id 0, treating as local UDP");
                    }
                    continue;
                }
                
                // #region agent log
                use std::io::Write;
                if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open("/mnt/c/Users/rasoo/Desktop/Github/dns-tunnel/.cursor/debug.log") {
                    let _ = writeln!(f, r#"{{"hypothesisId":"C","location":"client.rs:257","message":"packet_received","data":{{"source":"{}","len":{},"first_bytes":"{:?}"}},"timestamp":{}}}"#, source, len, &data[..len.min(8)], std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis());
                }
                // #endregion
                
                // Check if this is a UDP response from server or a local UDP packet
                // Server responses will be UDP packets with our tunnel format (4-byte header)
                // Local UDP packets from applications won't have this format
                // We check if it's a valid tunnel packet by trying to decode it
                // Only check if data is at least 4 bytes (header size)
                let decoded_packet = if data.len() >= 4 {
                    codec.decode_udp_packet(data).ok().flatten()
                } else {
                    None
                };
                
                // If it decodes as a tunnel packet (has valid structure), it's from the server
                // Even if packet_id is not in pending_requests (might be duplicate or already processed)
                let is_tunnel_packet = decoded_packet.is_some();
                
                if is_tunnel_packet {
                    if let Some(packet) = decoded_packet {
                        // Deduplication: skip if already processed
                        {
                            let processed = processed_response_ids.lock().await;
                            if processed.contains(&packet.packet_id) {
                                debug!("[UDP-RESPONSE] Skipping packet_id {} (already processed)", packet.packet_id);
                                continue;
                            }
                        }
                        
                        // #region agent log
                        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open("/mnt/c/Users/rasoo/Desktop/Github/dns-tunnel/.cursor/debug.log") {
                            let _ = writeln!(f, r#"{{"hypothesisId":"A","location":"client.rs:280","message":"udp_tunnel_decoded","data":{{"packet_id":{},"fragment":{},"total":{}}},"timestamp":{}}}"#, packet.packet_id, packet.fragment_id, packet.total_fragments, std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis());
                        }
                        // #endregion
                        
                        // Check if packet_id is in pending requests
                        let mut pending = pending_requests.lock().await;
                        let has_pending = pending.contains_key(&packet.packet_id);
                        debug!("Decoded tunnel packet: packet_id={}, fragment={}/{}, has_pending={}", 
                               packet.packet_id, packet.fragment_id + 1, packet.total_fragments, has_pending);
                        
                        if has_pending {
                            // Valid response - process it
                            info!("[UDP-RESPONSE] Received: packet_id={}, fragment={}/{}", 
                               packet.packet_id, packet.fragment_id + 1, packet.total_fragments);
                        let mut reass = reassembler.lock().await;
                        if let Some(reassembled_data) = reass.add_fragment(packet.clone()) {
                            // Find the original source
                            if let Some((original_source, _)) = pending.remove(&packet.packet_id) {
                                    // Mark as processed BEFORE sending
                                    {
                                        let mut processed = processed_response_ids.lock().await;
                                        processed.insert(packet.packet_id);
                                        // #region agent log
                                        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open("/mnt/c/Users/rasoo/Desktop/Github/dns-tunnel/.cursor/debug.log") {
                                            let _ = writeln!(f, r#"{{"hypothesisId":"DEDUP","location":"client.rs:udp_mark","message":"marked_processed","data":{{"packet_id":{},"set_size":{}}},"timestamp":{}}}"#, packet.packet_id, processed.len(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis());
                                        }
                                        // #endregion
                                        if processed.len() > 1000 { processed.clear(); }
                                    }
                                // Forward reassembled packet to original source
                                    drop(pending); // Release lock before async operation
                                if let Err(e) = udp_socket.send_to(&reassembled_data, original_source).await {
                                    error!("Failed to send reassembled packet: {}", e);
                                    } else {
                                        info!("[UDP-RESPONSE] Sent reassembled packet {} ({} bytes) to {}", 
                                              packet.packet_id, reassembled_data.len(), original_source);
                                    }
                                } else {
                                    debug!("[UDP-RESPONSE] No pending request for packet_id {} (likely already handled)", packet.packet_id);
                                }
                            }
                        } else {
                            // Tunnel packet structure but packet_id not in pending - likely duplicate or already processed
                            debug!("Ignoring tunnel packet with packet_id {} (not in pending_requests, likely duplicate)", packet.packet_id);
                        }
                    }
                } else {
                    // Not a UDP tunnel packet
                    // #region agent log
                    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open("/mnt/c/Users/rasoo/Desktop/Github/dns-tunnel/.cursor/debug.log") {
                        let _ = writeln!(f, r#"{{"hypothesisId":"B","location":"client.rs:312","message":"not_udp_tunnel","data":{{"source":"{}","len":{}}},"timestamp":{}}}"#, source, len, std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis());
                    }
                    // #endregion
                    
                    // First, try to parse as DNS response (regardless of source)
                    // This is the most reliable way to detect DNS responses
                    let dns_parse_result = Message::from_bytes(data);
                    // #region agent log
                    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open("/mnt/c/Users/rasoo/Desktop/Github/dns-tunnel/.cursor/debug.log") {
                        let _ = writeln!(f, r#"{{"hypothesisId":"D","location":"client.rs:320","message":"dns_parse_attempt","data":{{"success":{},"source":"{}"}},"timestamp":{}}}"#, dns_parse_result.is_ok(), source, std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis());
                    }
                    // #endregion
                    if let Ok(message) = dns_parse_result {
                        let decode_result = codec.decode_from_dns_response(&message, &config.domains);
                        // #region agent log
                        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open("/mnt/c/Users/rasoo/Desktop/Github/dns-tunnel/.cursor/debug.log") {
                            let _ = writeln!(f, r#"{{"hypothesisId":"D","location":"client.rs:326","message":"dns_decode_result","data":{{"result":"{:?}"}},"timestamp":{}}}"#, decode_result.as_ref().map(|o| o.is_some()), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis());
                        }
                        // #endregion
                        if let Ok(Some(packet)) = decode_result {
                            // Deduplication: skip if already processed
                            {
                                let processed = processed_response_ids.lock().await;
                                // #region agent log
                                if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open("/mnt/c/Users/rasoo/Desktop/Github/dns-tunnel/.cursor/debug.log") {
                                    let _ = writeln!(f, r#"{{"hypothesisId":"DEDUP","location":"client.rs:dns_main","message":"dedup_check","data":{{"packet_id":{},"is_processed":{},"set_size":{}}},"timestamp":{}}}"#, packet.packet_id, processed.contains(&packet.packet_id), processed.len(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis());
                                }
                                // #endregion
                                if processed.contains(&packet.packet_id) {
                                    info!("[DNS-RESPONSE] Skipping packet_id {} (already processed)", packet.packet_id);
                                    continue;
                                }
                            }
                            
                            info!("[DNS-RESPONSE] Decoded from main socket: packet_id={}, fragment={}/{}", 
                                   packet.packet_id, packet.fragment_id + 1, packet.total_fragments);
                            
                            let mut reass = reassembler.lock().await;
                            if let Some(reassembled_data) = reass.add_fragment(packet.clone()) {
                                let mut pending = pending_requests.lock().await;
                                if let Some((original_source, _)) = pending.remove(&packet.packet_id) {
                                    // Mark as processed
                                    {
                                        let mut processed = processed_response_ids.lock().await;
                                        processed.insert(packet.packet_id);
                                        if processed.len() > 1000 { processed.clear(); }
                                    }
                                    drop(pending);
                                    if let Err(e) = udp_socket.send_to(&reassembled_data, original_source).await {
                                        error!("Failed to send reassembled packet: {}", e);
                                    } else {
                                        info!("[DNS-RESPONSE] Sent reassembled packet {} ({} bytes) to {}", 
                                              packet.packet_id, reassembled_data.len(), original_source);
                                    }
                                } else {
                                    debug!("[DNS-RESPONSE] No pending request for packet_id {} (likely already handled by UDP)", packet.packet_id);
                                }
                            }
                            continue;
                        }
                    }
                    
                    // Not a tunnel packet or DNS response - check if from known server address
                    // Only filter out packets from EXACT server addresses (IP+port match)
                    let is_from_exact_server = server_addresses.iter().any(|&addr| 
                        addr.ip() == source.ip() && addr.port() == source.port()
                    );
                    if is_from_exact_server {
                        debug!("Ignoring non-tunnel packet from server address {}", source);
                        continue;
                    }
                    
                    // This is a local UDP packet from an application
                    let data_preview = String::from_utf8_lossy(&data[..data.len().min(10)]);
                    info!("[UDP-LOCAL] Received {} bytes from application {}: {:?}", len, source, data_preview);

                    // Plain mode: send raw UDP directly
                    if config.plain_mode {
                        // In plain mode, send raw UDP to first resolver (server address)
                        if let Some(server_addr) = config.resolvers.first() {
                            info!("[PLAIN-MODE] Sending {} bytes directly to {}: {:?}", data.len(), server_addr, data_preview);
                            if let Err(e) = dns_query_socket.send_to(data, server_addr).await {
                                error!("[PLAIN-MODE] Failed to send to {}: {}", server_addr, e);
                            } else {
                                info!("[PLAIN-MODE] Sent {} bytes to {}", data.len(), server_addr);
                            }
                        } else {
                            error!("[PLAIN-MODE] No resolver/server address configured!");
                        }
                        continue;
                    }

                    // Generate packet ID
                    let packet_id = packet_id_counter;
                    packet_id_counter = packet_id_counter.wrapping_add(1);

                    // Store pending request
                    {
                        let mut pending = pending_requests.lock().await;
                        pending.insert(packet_id, (source, 0));
                    }

                    // Select domain for DNS queries
                    let domain = &config.domains[rand::thread_rng().gen_range(0..config.domains.len())];
                    // Note: resolver selection is computed but we send to all resolvers (spam mode)
                    let _resolver = if config.rotate_resolvers {
                        let mut idx = resolver_index.lock().await;
                        *idx = (*idx + 1) % config.resolvers.len();
                        rotate_resolver(&config.resolvers, *idx)
                    } else {
                        &config.resolvers[rand::thread_rng().gen_range(0..config.resolvers.len())]
                    };

                    // Send based on uplink_mode
                    match config.uplink_mode {
                        ResponseMode::Udp => {
                            // UDP uplink: send raw tunnel packets directly to server
                            let server_udp = match config.server_udp_addr {
                                Some(addr) => addr,
                                None => {
                                    error!("[UDP-UPLINK] server_udp_addr not configured! Cannot send UDP uplink.");
                                    continue;
                                }
                            };
                            
                            let max_chunk = 65507 - 4; // Max UDP minus header
                            let fragments = fragment_packet(data, max_chunk);
                            let total_fragments = fragments.len() as u8;
                            
                            info!("[UDP-UPLINK] Fragmenting packet {} into {} fragments", packet_id, total_fragments);
                            
                            for (fragment_id, fragment_data) in fragments.iter().enumerate() {
                                let udp_packet = codec.encode_udp_packet(
                                    fragment_data,
                                    packet_id,
                                    fragment_id as u8,
                                    total_fragments,
                                );
                                
                                if let Err(e) = dns_query_socket.send_to(&udp_packet, server_udp).await {
                                    warn!("[UDP-UPLINK] Failed to send to {}: {}", server_udp, e);
                                } else {
                                    info!("[UDP-UPLINK] Sent fragment {}/{} ({} bytes) to {}", 
                                           fragment_id + 1, total_fragments, udp_packet.len(), server_udp);
                                }
                            }
                        }
                        ResponseMode::Dns => {
                            // DNS uplink: send as DNS queries
                            let max_chunk = codec.max_payload_per_query();
                            let fragments = fragment_packet(data, max_chunk);
                            let total_fragments = fragments.len() as u8;
                            
                            info!("[DNS-UPLINK] Fragmenting packet {} into {} fragments", packet_id, total_fragments);
                            
                    for (fragment_id, fragment_data) in fragments.iter().enumerate() {
                        match codec.encode_to_dns_query(
                            fragment_data,
                            domain,
                            packet_id,
                            fragment_id as u8,
                            total_fragments,
                        ) {
                            Ok(dns_query) => {
                                let mut buf = Vec::new();
                                let mut encoder = BinEncoder::new(&mut buf);
                                if let Err(e) = dns_query.emit(&mut encoder) {
                                    error!("Failed to encode DNS query: {}", e);
                                    continue;
                                }

                                    let query_bytes = encoder.into_bytes();
                                    
                                        // Send to all resolvers (spam)
                                    for resolver in &config.resolvers {
                                            if let Err(e) = dns_query_socket.send_to(&query_bytes, resolver).await {
                                                warn!("[DNS-UPLINK] Failed to send to {}: {}", resolver, e);
                                        } else {
                                                info!("[DNS-UPLINK] Sent fragment {}/{} ({} bytes) to {}", 
                                                   fragment_id + 1, total_fragments, query_bytes.len(), resolver);
                                        }
                                    }
                            }
                            Err(e) => {
                                error!("Failed to encode packet to DNS: {}", e);
                            }
                                }
                            }
                        }
                        ResponseMode::Hybrid | ResponseMode::HybridAlias => {
                            // Hybrid uplink: send both UDP packets (to server_udp_addr) and DNS queries (to resolvers)
                            
                            // UDP part (faster, may be blocked)
                            if let Some(server_udp) = config.server_udp_addr {
                                let max_chunk_udp = 65507 - 4;
                                let fragments_udp = fragment_packet(data, max_chunk_udp);
                                let total_fragments_udp = fragments_udp.len() as u8;
                                
                                for (fragment_id, fragment_data) in fragments_udp.iter().enumerate() {
                                    let udp_packet = codec.encode_udp_packet(
                                        fragment_data,
                                        packet_id,
                                        fragment_id as u8,
                                        total_fragments_udp,
                                    );
                                    
                                    if let Err(e) = dns_query_socket.send_to(&udp_packet, server_udp).await {
                                        warn!("[HYBRID-UPLINK] UDP failed to {}: {}", server_udp, e);
                                    } else {
                                        debug!("[HYBRID-UPLINK] UDP fragment {}/{} to {}", 
                                               fragment_id + 1, total_fragments_udp, server_udp);
                                    }
                                }
                                info!("[HYBRID-UPLINK] Sent {} UDP fragments to {}", total_fragments_udp, server_udp);
                            } else {
                                warn!("[HYBRID-UPLINK] server_udp_addr not set, skipping UDP uplink");
                            }
                            
                            // DNS part (more reliable, slower)
                            let max_chunk_dns = codec.max_payload_per_query();
                            let fragments_dns = fragment_packet(data, max_chunk_dns);
                            let total_fragments_dns = fragments_dns.len() as u8;
                            
                            info!("[HYBRID-UPLINK] Sending packet {} via DNS ({} fragments)", 
                                  packet_id, total_fragments_dns);
                            
                            for (fragment_id, fragment_data) in fragments_dns.iter().enumerate() {
                                match codec.encode_to_dns_query(
                                    fragment_data,
                                    domain,
                                    packet_id,
                                    fragment_id as u8,
                                    total_fragments_dns,
                                ) {
                                    Ok(dns_query) => {
                                        let mut buf = Vec::new();
                                        let mut encoder = BinEncoder::new(&mut buf);
                                        if let Err(e) = dns_query.emit(&mut encoder) {
                                            error!("Failed to encode DNS query: {}", e);
                                            continue;
                                        }

                                        let query_bytes = encoder.into_bytes();
                                        
                                        for resolver in &config.resolvers {
                                            if let Err(e) = dns_query_socket.send_to(&query_bytes, resolver).await {
                                                warn!("[HYBRID-UPLINK] DNS failed to {}: {}", resolver, e);
                                            } else {
                                                debug!("[HYBRID-UPLINK] DNS fragment {}/{} to {}", 
                                                       fragment_id + 1, total_fragments_dns, resolver);
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        error!("Failed to encode packet to DNS: {}", e);
                                    }
                                }
                            }
                            
                            info!("[HYBRID-UPLINK] Sent packet {} via DNS ({} fragments)", 
                                  packet_id, total_fragments_dns);
                        }
                    }
                }
            }
            Err(e) => {
                error!("Error receiving UDP packet: {}", e);
                sleep(Duration::from_millis(100)).await;
            }
        }
    }
}
