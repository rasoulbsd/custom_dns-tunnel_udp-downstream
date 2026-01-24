use anyhow::{Context, Result};
use clap::Parser;
use dns_tunnel::{
    config::{load_server_config, ResponseMode, ServerConfig, BroadcastMode},
    dns_codec::{DnsCodec, TunnelRecordType},
    packet::{fragment_packet, PacketReassembler},
    session::{SessionManager, SessionType},
    socks5::{Socks5Server, Socks5Connection, Command, ReplyCode},
    utils::get_random_port,
};
use futures::future::join_all;
use hickory_proto::{
    op::{Message, ResponseCode},
    serialize::binary::{BinDecodable, BinEncodable, BinEncoder},
};
use log::{debug, error, info, warn};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration, Instant};
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;

#[derive(Parser)]
#[command(name = "dns-tunnel-server")]
#[command(about = "DNS Tunnel Server (VPS side)")]
struct Args {
    #[arg(short, long)]
    config: Option<String>,
    #[arg(short = 'b', long, default_value = "0.0.0.0")]
    dns_bind_addr: String,
    #[arg(short = 'p', long)]
    dns_port: Option<u16>,
    #[arg(short, long)]
    target_udp: Option<String>,
    #[arg(long)]
    client_udp_port: Option<u16>,
    #[arg(short, long)]
    domains: Vec<String>,
    #[arg(long, default_value = "63")]
    max_subdomain_length: usize,
    #[arg(long)]
    randomize_dns_port: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();
    
    let mut config = if let Some(config_path) = args.config {
        load_server_config(Some(config_path.into()))?
    } else {
        ServerConfig::default()
    };

    // Override with CLI args
    if !args.domains.is_empty() {
        config.domains = args.domains;
    }
    if args.max_subdomain_length > 0 {
        config.max_subdomain_length = args.max_subdomain_length;
    }
    config.randomize_dns_port = args.randomize_dns_port;

    // Set DNS bind port
    let dns_port = if config.randomize_dns_port {
        get_random_port()
    } else {
        args.dns_port.unwrap_or_else(|| {
            config.dns_bind.port()
        })
    };
    let dns_bind: SocketAddr = format!("{}:{}", args.dns_bind_addr, dns_port)
        .parse()
        .context("Invalid DNS bind address")?;

    // Set target UDP
    let target_udp = if let Some(target) = args.target_udp {
        Some(target.parse().context("Invalid target UDP address")?)
    } else {
        config.target_udp
    };
    
    // Set client UDP port
    if let Some(port) = args.client_udp_port {
        config.client_udp_port = Some(port);
    }

    info!("Starting DNS Tunnel Server");
    info!("DNS bind: {}", dns_bind);
    info!("Target UDP: {:?}", target_udp);
    info!("Client UDP port: {:?}", config.client_udp_port);
    info!("Domains: {:?}", config.domains);
    info!("Max subdomain length: {} (DNS label limit: 63)", config.max_subdomain_length);
    if config.max_subdomain_length > 63 {
        warn!("max_subdomain_length ({}) exceeds DNS label limit (63), will be capped", config.max_subdomain_length);
    }
    info!("Response mode from config: {:?}", config.response_mode);
    info!("Plain mode: {} (bypasses DNS decoding)", config.plain_mode);
    if config.plain_mode {
        warn!("PLAIN MODE ENABLED: Receiving raw UDP packets directly (no DNS decoding)");
    }

    if config.domains.is_empty() {
        anyhow::bail!("At least one domain must be specified");
    }

    // Bind DNS socket
    let dns_socket = Arc::new(UdpSocket::bind(&dns_bind)
        .await
        .context("Failed to bind DNS socket")?);
    info!("Bound to DNS: {}", dns_bind);

    // Create target UDP socket if specified
    let target_socket = if let Some(_target) = target_udp {
        Some(Arc::new(UdpSocket::bind("0.0.0.0:0")
            .await
            .context("Failed to bind target UDP socket")?))
    } else {
        None
    };

    let codec = Arc::new(DnsCodec::new_with_min(config.max_subdomain_length, config.min_subdomain_length));
    let reassembler = Arc::new(Mutex::new(PacketReassembler::with_nack_config(
        config.nack_delay_ms,
        config.nack_interval_ms,
    )));
    
    // Parse configured record types for multi-record broadcast responses
    let record_types: Vec<TunnelRecordType> = config.record_types.iter()
        .filter_map(|s| TunnelRecordType::from_str(s))
        .collect();
    let record_types = if record_types.is_empty() {
        vec![TunnelRecordType::TXT]
    } else {
        record_types
    };
    info!("[BROADCAST] Response record types: {:?}, Mode: {:?}", 
          config.record_types, config.broadcast_mode);
    let record_types = Arc::new(record_types);
    let broadcast_mode = config.broadcast_mode.clone();
    
    // Map: packet_id -> (reply_addr, query_id, domain)
    //
    // - For DNS uplink, reply_addr is the resolver/client socket that sent the DNS query (IP:port).
    //   When using public resolvers (1.1.1.1/8.8.8.8), this will be the resolver's source port, and we MUST reply there.
    // - For UDP uplink, reply_addr is currently the client's configured UDP response address (IP:client_udp_port),
    //   and query_id is 0 (no DNS query id).
    let pending_requests: Arc<Mutex<HashMap<u16, (SocketAddr, u16, String)>>> = Arc::new(Mutex::new(HashMap::new()));
    // Queue for matching responses from target_udp to packet_id
    // For echo servers: we can use hash-based matching (exact data match)
    // For real services (OpenVPN, etc): we use FIFO queue (responses come in order)
    // Hybrid approach: try hash first, fallback to FIFO
    let data_hash_to_packet: Arc<Mutex<HashMap<u64, (u16, SocketAddr, Instant)>>> = Arc::new(Mutex::new(HashMap::new()));
    // FIFO queue for non-echo services: (packet_id, client_udp_addr, timestamp, data_hash)
    let response_queue: Arc<Mutex<VecDeque<(u16, SocketAddr, Instant, u64)>>> = Arc::new(Mutex::new(VecDeque::new()));
    
    // Deduplication: track packet_ids that have been fully reassembled and forwarded
    // This prevents processing the same packet twice when client sends via both UDP and DNS (hybrid uplink)
    use std::collections::HashSet;
    let processed_packet_ids: Arc<Mutex<HashSet<u16>>> = Arc::new(Mutex::new(HashSet::new()));
    
    // Create a UDP socket for sending responses directly to client (used in UDP and hybrid modes)
    let client_response_socket = if matches!(config.response_mode, ResponseMode::Udp | ResponseMode::Hybrid | ResponseMode::HybridAlias) {
        Some(Arc::new(UdpSocket::bind("0.0.0.0:0")
            .await
            .context("Failed to bind client response UDP socket")?))
    } else {
        None
    };
    
    // Clone DNS socket for sending DNS responses (used in DNS and hybrid modes)
    let dns_socket_for_response = if matches!(config.response_mode, ResponseMode::Dns | ResponseMode::Hybrid | ResponseMode::HybridAlias) {
        Some(dns_socket.clone())
    } else {
        None
    };
    
    info!("UDP response socket available: {} (mode: {:?})", client_response_socket.is_some(), config.response_mode);
    info!("DNS response socket available: {} (mode: {:?})", dns_socket_for_response.is_some(), config.response_mode);

    // Create a separate UDP socket for receiving raw UDP queries (uplink_mode: udp)
    // Server always listens for both UDP and DNS queries regardless of response_mode
    // This is on a DIFFERENT port than client_udp_port (which is for sending responses)
    let udp_query_port = config.udp_query_port.unwrap_or(5354);
    let udp_query_bind: SocketAddr = format!("0.0.0.0:{}", udp_query_port).parse().unwrap();
    let udp_query_socket = Arc::new(UdpSocket::bind(&udp_query_bind)
        .await
        .context("Failed to bind UDP query socket")?);
    info!("Bound UDP query listener: {} (for UDP uplink from client)", udp_query_bind);
    info!("Client response port: {} (responses sent to client's IP + this port)", config.client_udp_port.unwrap_or(5353));

    // Spawn task to receive raw UDP queries (for uplink_mode: udp or hybrid)
    {
        let udp_query_socket = udp_query_socket.clone();
        let codec = codec.clone();
        let reassembler = reassembler.clone();
        let pending_requests = pending_requests.clone();
        let target_socket = target_socket.clone();
        let data_hash_to_packet = data_hash_to_packet.clone();
        let response_queue = response_queue.clone();
        let processed_packet_ids = processed_packet_ids.clone();
        let target_udp = config.target_udp;
        let domains = config.domains.clone();
        let client_udp_port = config.client_udp_port.unwrap_or(5353);
        
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            
            loop {
                match udp_query_socket.recv_from(&mut buf).await {
                    Ok((len, udp_source)) => {
                        let query_data = &buf[..len];
                        let data_preview = String::from_utf8_lossy(&query_data[..query_data.len().min(10)]);
                        info!("[UDP-QUERY] Received {} bytes from {}: {:?}", len, udp_source, data_preview);
                        
                        // Build client UDP address for responses
                        // Use client's IP but configured client_udp_port (where client is listening)
                        let client_udp_addr = SocketAddr::new(udp_source.ip(), client_udp_port);
                        
                        // Try to decode as a tunnel packet (has 4-byte header)
                        match codec.decode_udp_packet(query_data) {
                            Ok(Some(mut packet)) => {
                                packet.source = udp_source;
                                
                                info!("[UDP-QUERY] Decoded: packet_id={}, fragment={}/{}", 
                                       packet.packet_id, packet.fragment_id + 1, packet.total_fragments);
                                
                                // Store pending request for response matching
                                // Use query_id = 0 for UDP queries (no DNS query ID)
                                // Store client_udp_addr (configured port) not udp_source (ephemeral port)
                                let domain = domains.first().cloned().unwrap_or_else(|| "example.com".to_string());
                                {
                                    let mut pending = pending_requests.lock().await;
                                    pending.insert(packet.packet_id, (client_udp_addr, 0, domain));
                                }
                                
                                // Reassemble packet
                                let mut reass = reassembler.lock().await;
                                if let Some(reassembled_data) = reass.add_fragment(packet.clone()) {
                                    // Deduplication: check if this packet_id was already processed
                                    {
                                        let mut processed = processed_packet_ids.lock().await;
                                        if processed.contains(&packet.packet_id) {
                                            info!("[UDP-QUERY] Skipping duplicate packet_id {} (already processed)", packet.packet_id);
                                            continue;
                                        }
                                        // Mark as processed
                                        processed.insert(packet.packet_id);
                                        // Clean up old entries (keep last 1000)
                                        if processed.len() > 1000 {
                                            processed.clear();
                                        }
                                    }
                                    
                                    info!("[UDP-QUERY] Reassembled packet {} ({} bytes)", packet.packet_id, reassembled_data.len());
                                    
                                    // Forward to target UDP
                                    if let Some(ref target_sock) = target_socket {
                                        if let Some(target_addr) = target_udp {
                                            // Compute hash for response matching
                                            use std::hash::{Hash, Hasher};
                                            use std::collections::hash_map::DefaultHasher;
                                            let mut hasher = DefaultHasher::new();
                                            reassembled_data.hash(&mut hasher);
                                            let data_hash = hasher.finish();
                                            
                                            let now = tokio::time::Instant::now();
                                            
                                            // Store client_udp_addr (configured port) not udp_source
                                            {
                                                let mut hash_map = data_hash_to_packet.lock().await;
                                                hash_map.insert(data_hash, (packet.packet_id, client_udp_addr, now));
                                                info!("[UDP-QUERY] Stored in hash_map: packet_id={}, hash={}, client={}", 
                                                      packet.packet_id, data_hash, client_udp_addr);
                                            }
                                            {
                                                let mut queue = response_queue.lock().await;
                                                queue.push_back((packet.packet_id, client_udp_addr, now, data_hash));
                                                info!("[UDP-QUERY] Stored in queue: packet_id={}, client={}", 
                                                      packet.packet_id, client_udp_addr);
                                            }
                                            
                                            info!("[UDP-QUERY] Forwarding {} bytes to target {}", reassembled_data.len(), target_addr);
                                            if let Err(e) = target_sock.send_to(&reassembled_data, target_addr).await {
                                                error!("[UDP-QUERY] Failed to forward to target: {}", e);
                                                // Remove from maps on error
                                                let mut hash_map = data_hash_to_packet.lock().await;
                                                hash_map.remove(&data_hash);
                                                let mut queue = response_queue.lock().await;
                                                queue.retain(|(pid, _, _, h)| *pid != packet.packet_id && *h != data_hash);
                                            } else {
                                                info!("[UDP-QUERY] Forwarded packet {} to {}", packet.packet_id, target_addr);
                                            }
                                        }
                                    } else {
                                        debug!("[UDP-QUERY] No target UDP configured");
                                    }
                                }
                            }
                            Ok(None) => {
                                debug!("[UDP-QUERY] Not a valid tunnel packet (no header or invalid)");
                            }
                            Err(e) => {
                                warn!("[UDP-QUERY] Failed to decode: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("[UDP-QUERY] Error receiving: {}", e);
                        sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        });
    }

    // Spawn task to receive UDP responses from target
    if let Some(ref target_sock) = target_socket {
        if let Some(_target_addr) = config.target_udp {
            let target_sock = target_sock.clone();
            let codec = codec.clone();
            let client_response_socket = client_response_socket.clone();
            let dns_socket_for_response = dns_socket_for_response.clone();
            let response_mode = config.response_mode.clone();
            let plain_mode = config.plain_mode;
            let domains_for_response = config.domains.clone(); // Used for spam mode DNS responses
            let record_types_clone = record_types.clone(); // For multi-record type broadcast
            let broadcast_mode_clone = broadcast_mode.clone();
            let data_hash_to_packet = data_hash_to_packet.clone();
            let response_queue = response_queue.clone();
            let pending_requests_for_response = pending_requests.clone();
            
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65507];
                const RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
                
                loop {
                    match target_sock.recv_from(&mut buf).await {
                        Ok((len, src)) => {
                            let data = &buf[..len];
                            info!("[TARGET] Received {} bytes from target {}: {:?}", len, src, &data[..len.min(32)]);

                            // Compute hash of received data
                            let mut hasher = DefaultHasher::new();
                            data.hash(&mut hasher);
                            let data_hash = hasher.finish();
                            
                            let now = Instant::now();
                            let mut hash_map = data_hash_to_packet.lock().await;
                            let mut queue = response_queue.lock().await;
                            
                            // Clean up old entries
                            hash_map.retain(|_, (_, _, timestamp)| {
                                now.duration_since(*timestamp) < RESPONSE_TIMEOUT
                            });
                            queue.retain(|(_, _, timestamp, _)| {
                                now.duration_since(*timestamp) < RESPONSE_TIMEOUT
                            });
                            
                            // Try hash-based matching first (for echo servers)
                            info!("[TARGET] Looking for match: hash={}, hash_map_size={}, queue_size={}", 
                                  data_hash, hash_map.len(), queue.len());
                            let matched = if let Some((original_packet_id, client_udp_addr, _)) = hash_map.remove(&data_hash) {
                                info!("[TARGET] Hash match found: packet_id={}, client={}", original_packet_id, client_udp_addr);
                                // Also remove from queue if it exists there
                                queue.retain(|(pid, _, _, h)| *pid != original_packet_id && *h != data_hash);
                                Some((original_packet_id, client_udp_addr))
                            } else {
                                // Fallback to FIFO queue matching (for real services like OpenVPN)
                                // Responses typically come back in order for stateful protocols
                                if let Some((packet_id, client_udp_addr, _, queue_hash)) = queue.pop_front() {
                                    info!("[TARGET] FIFO queue match: packet_id={}, client={}", packet_id, client_udp_addr);
                                    // Also remove from hash_map if it exists there
                                    hash_map.remove(&queue_hash);
                                    Some((packet_id, client_udp_addr))
                                } else {
                                    warn!("[TARGET] No match found for hash {} (hash_map: {}, queue: {})", 
                                          data_hash, hash_map.len(), queue.len());
                                    None
                                }
                            };
                            
                            if let Some((original_packet_id, client_udp_addr)) = matched {
                                // Get reply_addr, query_id and domain from pending_requests FIRST
                                // CRITICAL: For DNS responses, we MUST use the actual DNS query source (with ephemeral port),
                                // NOT the client_udp_addr from hash_map (which uses client_udp_port=53)
                                let (reply_addr, query_id, _domain) = {
                                    let pending = pending_requests_for_response.lock().await;
                                    if let Some((reply, qid, dom)) = pending.get(&original_packet_id) {
                                        (*reply, *qid, dom.clone())
                                    } else {
                                        warn!("[TARGET] No pending request found for packet_id: {} (pending_requests keys: {:?})", original_packet_id, pending.keys().collect::<Vec<_>>());
                                        continue;
                                    }
                                };
                                
                                info!("Matched target response to packet_id: {}, sending to reply_addr={} (client_udp_addr={}, mode: {:?}, plain: {})", 
                                      original_packet_id, reply_addr, client_udp_addr, response_mode, plain_mode);
                                
                                // Plain mode: send raw UDP directly
                                if plain_mode {
                                    let data_preview = String::from_utf8_lossy(&data[..data.len().min(10)]);
                                    info!("[PLAIN-MODE] Sending {} bytes directly to {}: {:?}", data.len(), client_udp_addr, data_preview);
                                    if let Some(ref sock) = client_response_socket {
                                        let local_addr = sock.local_addr().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
                                        if let Err(e) = sock.send_to(data, client_udp_addr).await {
                                            error!("[PLAIN-MODE] Failed to send to {} from {}: {}", client_udp_addr, local_addr, e);
                                        } else {
                                            info!("[PLAIN-MODE] Sent {} bytes from {} to {}", data.len(), local_addr, client_udp_addr);
                                        }
                                    } else {
                                        warn!("[PLAIN-MODE] client_response_socket is None!");
                                    }
                                    continue;
                                }
                                
                                info!("UDP socket available: {}, DNS socket available: {}", 
                                      client_response_socket.is_some(), dns_socket_for_response.is_some());
                                
                                // Use the ORIGINAL packet_id so client can match it
                                let response_packet_id = original_packet_id;

                                // Send responses based on configured mode
                                info!("[DEBUG] About to match response_mode: {:?}", response_mode);
                                match response_mode {
                                    ResponseMode::Udp => {
                                        // UDP only mode - PARALLEL SENDING
                                        info!("[UDP-RESPONSE] Mode: UDP only (parallel), client_response_socket is_some: {}", client_response_socket.is_some());
                                        let max_chunk = 65507 - 4; // Max UDP size minus header
                                        let fragments = fragment_packet(data, max_chunk);
                                        let total_fragments = fragments.len() as u8;
                                        
                                        info!("[UDP-RESPONSE] Fragmenting into {} fragments (parallel send)", total_fragments);
                                        
                                        if let Some(ref sock) = client_response_socket {
                                            info!("[UDP-RESPONSE] Sending {} fragments to {} in parallel", total_fragments, client_udp_addr);
                                            
                                            // Prepare all UDP packets first
                                            let mut udp_packets: Vec<(u8, Vec<u8>)> = Vec::new();
                                for (fragment_id, fragment_data) in fragments.iter().enumerate() {
                                    let udp_packet = codec.encode_udp_packet(
                                        fragment_data,
                                        response_packet_id,
                                        fragment_id as u8,
                                        total_fragments,
                                    );
                                                udp_packets.push((fragment_id as u8, udp_packet));
                                            }
                                            
                                            // Send all fragments in parallel
                                            let sock_clone = Arc::clone(sock);
                                            let send_tasks: Vec<_> = udp_packets.into_iter().map(|(frag_id, packet)| {
                                                let sock = Arc::clone(&sock_clone);
                                                let addr = client_udp_addr;
                                                let total = total_fragments;
                                                tokio::spawn(async move {
                                                    match sock.send_to(&packet, addr).await {
                                                        Ok(_) => {
                                                            debug!("[UDP-RESPONSE] Sent fragment {}/{} ({} bytes) to {}", 
                                                                   frag_id + 1, total, packet.len(), addr);
                                                            Ok(())
                                                        }
                                                        Err(e) => {
                                                            warn!("Failed to send UDP response fragment {} to {}: {}", frag_id + 1, addr, e);
                                                            Err(e)
                                                        }
                                                    }
                                                })
                                            }).collect();
                                            
                                            let results = join_all(send_tasks).await;
                                            let success = results.iter().filter(|r| r.is_ok() && r.as_ref().unwrap().is_ok()).count();
                                            info!("[UDP-RESPONSE] Sent {}/{} fragments successfully", success, total_fragments);
                                        } else {
                                            warn!("[UDP-RESPONSE] client_response_socket is None! Cannot send UDP response.");
                                        }
                                    }
                                    ResponseMode::Dns => {
                                        // DNS only mode - SPAM MODE: send for ALL domains x ALL record types in PARALLEL
                                        let num_record_types = record_types_clone.len();
                                        info!("[DNS-RESPONSE] Mode: DNS only (parallel spam: {} domains x {} record types)", 
                                              domains_for_response.len(), num_record_types);
                                        let max_chunk = domains_for_response
                                            .iter()
                                            .map(|d| codec.max_payload_per_query_for_domain(d))
                                            .min()
                                            .unwrap_or_else(|| codec.max_payload_per_query());
                                        let fragments = fragment_packet(data, max_chunk);
                                        let total_fragments = fragments.len() as u8;
                                        
                                        let total_sends = match broadcast_mode_clone {
                                            BroadcastMode::Full => total_fragments as usize * domains_for_response.len() * num_record_types,
                                            BroadcastMode::Rotate | BroadcastMode::Single => total_fragments as usize * domains_for_response.len(),
                                        };
                                        
                                        info!("[DNS-RESPONSE] Fragmenting into {} fragments x {} domains x {} types = {} total sends", 
                                              total_fragments, domains_for_response.len(), num_record_types, total_sends);
                                        
                                        if let Some(ref sock) = dns_socket_for_response {
                                            // DNS replies only make sense if we have a real DNS query_id.
                                            if query_id == 0 {
                                                warn!("[DNS-RESPONSE] Skipping DNS response for packet_id {}: query_id=0 (not a DNS uplink)", response_packet_id);
                                                continue;
                                            }
                                            
                                            // Pre-encode all DNS responses for all domains, record types, and fragments
                                            let mut dns_packets: Vec<(String, u8, Vec<u8>)> = Vec::new();
                                            let mut type_idx = 0usize;
                                            
                                            for spam_domain in &domains_for_response {
                                                for (fragment_id, fragment_data) in fragments.iter().enumerate() {
                                                    // Determine which record types to use
                                                    let types_to_use: Vec<TunnelRecordType> = match broadcast_mode_clone {
                                                        BroadcastMode::Full => record_types_clone.to_vec(),
                                                        BroadcastMode::Rotate => {
                                                            let t = record_types_clone[type_idx % num_record_types];
                                                            type_idx += 1;
                                                            vec![t]
                                                        }
                                                        BroadcastMode::Single => vec![record_types_clone[0]],
                                                    };
                                                    
                                                    for record_type in types_to_use {
                                                        match codec.encode_to_dns_response_typed(
                                                        fragment_data,
                                                        spam_domain,
                                                        response_packet_id,
                                                        fragment_id as u8,
                                                        total_fragments,
                                                        query_id,
                                                            record_type,
                                                    ) {
                                                        Ok(dns_response) => {
                                                            let mut buf = Vec::new();
                                                            let mut encoder = BinEncoder::new(&mut buf);
                                                            if let Err(e) = dns_response.emit(&mut encoder) {
                                                                warn!("Failed to encode DNS response: {}", e);
                                                                continue;
                                                            }
                                                            dns_packets.push((spam_domain.clone(), fragment_id as u8, encoder.into_bytes().to_vec()));
                                                        }
                                                        Err(e) => {
                                                                warn!("Failed to encode DNS response ({:?}): {}", record_type, e);
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            
                                            // Send all DNS responses in parallel
                                            let sock_clone = Arc::clone(sock);
                                            let total = total_fragments;
                                            let send_tasks: Vec<_> = dns_packets.into_iter().map(|(domain, frag_id, packet)| {
                                                let sock = Arc::clone(&sock_clone);
                                                let addr = reply_addr;
                                                tokio::spawn(async move {
                                                    match sock.send_to(&packet, addr).await {
                                                        Ok(_) => {
                                                            debug!("[DNS-RESPONSE] Sent fragment {}/{} ({} bytes) to {} (domain: {})", 
                                                                   frag_id + 1, total, packet.len(), addr, domain);
                                                            Ok(())
                                                        }
                                                        Err(e) => {
                                                            warn!("[DNS-RESPONSE] Failed to send fragment {} to {}: {}", frag_id + 1, addr, e);
                                                            Err(e)
                                                        }
                                                    }
                                                })
                                            }).collect();
                                            
                                            let results = join_all(send_tasks).await;
                                            let success = results.iter().filter(|r| r.is_ok() && r.as_ref().unwrap().is_ok()).count();
                                            info!("[DNS-RESPONSE] Sent {}/{} packets successfully (parallel spam)", 
                                                  success, total_fragments as usize * domains_for_response.len());
                                        }
                                    }
                                    ResponseMode::Hybrid | ResponseMode::HybridAlias => {
                                        // Hybrid mode: send both UDP and DNS in PARALLEL with multi-record type broadcast
                                        let num_record_types = record_types_clone.len();
                                        let max_chunk_udp = 65507 - 4; // Max UDP size minus header
                                        let fragments_udp = fragment_packet(data, max_chunk_udp);
                                        let total_fragments_udp = fragments_udp.len() as u8;
                                        
                                        let max_chunk_dns = domains_for_response
                                            .iter()
                                            .map(|d| codec.max_payload_per_query_for_domain(d))
                                            .min()
                                            .unwrap_or_else(|| codec.max_payload_per_query());
                                        let fragments_dns = fragment_packet(data, max_chunk_dns);
                                        let total_fragments_dns = fragments_dns.len() as u8;
                                        
                                        let dns_multiplier = match broadcast_mode_clone {
                                            BroadcastMode::Full => domains_for_response.len() * num_record_types,
                                            BroadcastMode::Rotate | BroadcastMode::Single => domains_for_response.len(),
                                        };
                                        let total_sends = total_fragments_udp as usize + 
                                            (if query_id != 0 { total_fragments_dns as usize * dns_multiplier } else { 0 });
                                        info!("[HYBRID-RESPONSE] Parallel send: {} UDP + {} DNS x {} domains x {} types = {} total", 
                                              total_fragments_udp, total_fragments_dns, domains_for_response.len(), num_record_types, total_sends);
                                        
                                        // Collect all send tasks for parallel execution
                                        let mut all_tasks: Vec<tokio::task::JoinHandle<Result<(), std::io::Error>>> = Vec::new();
                                        
                                        // Prepare and spawn UDP send tasks
                                        if let Some(ref sock) = client_response_socket {
                                            let sock_clone = Arc::clone(sock);
                                            for (fragment_id, fragment_data) in fragments_udp.iter().enumerate() {
                                                let udp_packet = codec.encode_udp_packet(
                                                    fragment_data,
                                                    response_packet_id,
                                                    fragment_id as u8,
                                                    total_fragments_udp,
                                                );
                                                
                                                let sock = Arc::clone(&sock_clone);
                                                let addr = client_udp_addr;
                                                let total = total_fragments_udp;
                                                let frag_id = fragment_id as u8;
                                                all_tasks.push(tokio::spawn(async move {
                                                    match sock.send_to(&udp_packet, addr).await {
                                                        Ok(_) => {
                                                            debug!("[HYBRID-UDP] Sent fragment {}/{} to {}", frag_id + 1, total, addr);
                                                            Ok(())
                                                        }
                                                        Err(e) => {
                                                            warn!("[HYBRID-UDP] Failed to send fragment {} to {}: {}", frag_id + 1, addr, e);
                                                            Err(e)
                                                        }
                                                    }
                                                }));
                                            }
                                        }
                                        
                                        // Prepare and spawn DNS send tasks (spam mode - all domains x all record types)
                                        if let Some(ref sock) = dns_socket_for_response {
                                            if query_id != 0 {
                                                let sock_clone = Arc::clone(sock);
                                                let mut type_idx = 0usize;
                                                
                                                for spam_domain in &domains_for_response {
                                                    for (fragment_id, fragment_data) in fragments_dns.iter().enumerate() {
                                                        // Determine which record types to use
                                                        let types_to_use: Vec<TunnelRecordType> = match broadcast_mode_clone {
                                                            BroadcastMode::Full => record_types_clone.to_vec(),
                                                            BroadcastMode::Rotate => {
                                                                let t = record_types_clone[type_idx % num_record_types];
                                                                type_idx += 1;
                                                                vec![t]
                                                            }
                                                            BroadcastMode::Single => vec![record_types_clone[0]],
                                                        };
                                                        
                                                        for record_type in types_to_use {
                                                            match codec.encode_to_dns_response_typed(
                                                            fragment_data,
                                                            spam_domain,
                                                            response_packet_id,
                                                            fragment_id as u8,
                                                            total_fragments_dns,
                                                            query_id,
                                                                record_type,
                                                        ) {
                                                            Ok(dns_response) => {
                                                                let mut buf = Vec::new();
                                                                let mut encoder = BinEncoder::new(&mut buf);
                                                                if let Err(e) = dns_response.emit(&mut encoder) {
                                                                    warn!("Failed to encode DNS response: {}", e);
                                                                    continue;
                                                                }
                                                                let response_bytes = encoder.into_bytes().to_vec();
                                                                
                                                                let sock = Arc::clone(&sock_clone);
                                                                let addr = reply_addr;
                                                                let total = total_fragments_dns;
                                                                let frag_id = fragment_id as u8;
                                                                let domain = spam_domain.clone();
                                                                all_tasks.push(tokio::spawn(async move {
                                                                    match sock.send_to(&response_bytes, addr).await {
                                                                        Ok(_) => {
                                                                            debug!("[HYBRID-DNS] Sent fragment {}/{} to {} (domain: {})", 
                                                                                   frag_id + 1, total, addr, domain);
                                                                            Ok(())
                                                                        }
                                                                        Err(e) => {
                                                                            warn!("[HYBRID-DNS] Failed to send fragment {} to {}: {}", frag_id + 1, addr, e);
                                                                            Err(e)
                                                                        }
                                                                    }
                                                                }));
                                                            }
                                                            Err(e) => {
                                                                    warn!("Failed to encode DNS response ({:?}): {}", record_type, e);
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                    } else {
                                                debug!("[HYBRID-RESPONSE] Skipping DNS for packet_id {}: query_id=0", response_packet_id);
                                            }
                                        }
                                        
                                        // Wait for all sends to complete in parallel
                                        let results = join_all(all_tasks).await;
                                        let success = results.iter().filter(|r| r.is_ok() && r.as_ref().unwrap().is_ok()).count();
                                        info!("[HYBRID-RESPONSE] Sent {}/{} packets successfully (parallel)", success, total_sends);
                                    }
                                }
                            } else {
                                warn!("No matching packet_id found for target response (hash: {})", data_hash);
                            }
                        }
                        Err(e) => {
                            error!("Error receiving from target: {}", e);
                            sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
            });
        }
    }

    // Session manager for bi-directional SOCKS5 connections
    let session_manager: Arc<Mutex<SessionManager>> = Arc::new(Mutex::new(SessionManager::new()));
    
    // Spawn SOCKS5 server if configured (for reverse proxy functionality)
    if let Some(socks5_addr) = config.socks5_bind {
        let session_manager_socks = session_manager.clone();
        let _dns_socket_socks = dns_socket.clone();
        let _codec_socks = codec.clone();
        let _domains_socks = config.domains.clone();
        
        tokio::spawn(async move {
            match Socks5Server::bind(socks5_addr).await {
                Ok(socks5_server) => {
                    info!("[SOCKS5] Reverse proxy server started on {}", socks5_addr);
                    
                    loop {
                        match socks5_server.accept().await {
                            Ok((stream, client_addr)) => {
                                info!("[SOCKS5] Reverse: Accepted connection from {}", client_addr);
                                
                                let session_manager = session_manager_socks.clone();
                                
                                tokio::spawn(async move {
                                    if let Err(e) = handle_server_socks5_client(
                                        stream,
                                        client_addr,
                                        session_manager,
                                    ).await {
                                        warn!("[SOCKS5] Reverse: Client {} error: {}", client_addr, e);
                                    }
                                });
                            }
                            Err(e) => {
                                error!("[SOCKS5] Reverse: Accept error: {}", e);
                                sleep(Duration::from_millis(100)).await;
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("[SOCKS5] Failed to bind reverse proxy server on {}: {}", socks5_addr, e);
                }
            }
        });
    }

    // Main loop: receive DNS queries (or plain UDP in plain mode) and forward as UDP
    let mut buf = vec![0u8; 65535];
    
    loop {
        match dns_socket.recv_from(&mut buf).await {
            Ok((len, dns_source)) => {
                let query_data = &buf[..len];
                
                // Plain mode: treat incoming data as raw UDP packet
                if config.plain_mode {
                    let data_preview = String::from_utf8_lossy(&query_data[..query_data.len().min(10)]);
                    info!("[PLAIN-MODE] Received {} bytes from {}: {:?}", len, dns_source, data_preview);
                    
                    // Build client UDP address from source IP and configured port
                    let client_udp_port = config.client_udp_port.unwrap_or(5353);
                    let client_udp_addr = SocketAddr::new(dns_source.ip(), client_udp_port);
                    
                    // Forward to target UDP
                    if let Some(ref target_sock) = target_socket {
                        if let Some(target_addr) = config.target_udp {
                            info!("[PLAIN-MODE] Forwarding {} bytes to target {}", len, target_addr);
                            
                            // For plain mode, use packet_id 0 and simple matching
                            let packet_id = 0u16;
                            
                            // Store in hash map for response matching
                            let mut hasher = DefaultHasher::new();
                            query_data.hash(&mut hasher);
                            let data_hash = hasher.finish();
                            
                            let now = Instant::now();
                            {
                                let mut hash_map = data_hash_to_packet.lock().await;
                                hash_map.insert(data_hash, (packet_id, client_udp_addr, now));
                            }
                            {
                                let mut queue = response_queue.lock().await;
                                queue.push_back((packet_id, client_udp_addr, now, data_hash));
                            }
                            
                            if let Err(e) = target_sock.send_to(query_data, target_addr).await {
                                error!("[PLAIN-MODE] Failed to forward to target: {}", e);
                            } else {
                                info!("[PLAIN-MODE] Forwarded {} bytes to {}", len, target_addr);
                            }
                        }
                    }
                    continue;
                }
                
                match Message::from_bytes(query_data) {
                    Ok(message) => {
                        info!("[DNS-QUERY] Received from {} ({} bytes)", dns_source, len);
                        match codec.decode_from_dns_query(&message, &config.domains) {
                            Ok(Some(mut packet)) => {
                                // Set the actual source from DNS query
                                packet.source = dns_source;
                                
                                info!("[DNS-QUERY] Decoded from {}: packet_id={}, fragment={}/{}", 
                                       dns_source, packet.packet_id, packet.fragment_id + 1, packet.total_fragments);

                                // Extract domain from query for DNS responses
                                let domain = if let Some(query) = message.queries().first() {
                                    let query_name = query.name().to_ascii().trim_end_matches('.').to_string();
                                    // Find matching domain
                                    config.domains.iter()
                                        .find(|d| query_name.ends_with(d.as_str()))
                                        .cloned()
                                        .unwrap_or_else(|| config.domains[0].clone())
                                } else {
                                    config.domains[0].clone()
                                };

                                // Store pending request for DNS response (if needed)
                                // CRITICAL: Store the actual DNS query source (with ephemeral port) for DNS responses
                                // This is required for public resolvers (1.1.1.1, 8.8.8.8) to work correctly
                                {
                                    let mut pending = pending_requests.lock().await;
                                    debug!("[DNS-QUERY] Storing reply_addr={} for packet_id={} (query_id={}) - will send DNS responses to this address", dns_source, packet.packet_id, message.id());
                                    pending.insert(packet.packet_id, (dns_source, message.id(), domain));
                                }

                                // Reassemble packet
                                let mut reass = reassembler.lock().await;
                                if let Some(reassembled_data) = reass.add_fragment(packet.clone()) {
                                    // Deduplication: check if this packet_id was already processed
                                    {
                                        let mut processed = processed_packet_ids.lock().await;
                                        if processed.contains(&packet.packet_id) {
                                            info!("[DNS-QUERY] Skipping duplicate packet_id {} (already processed)", packet.packet_id);
                                            continue;
                                        }
                                        // Mark as processed
                                        processed.insert(packet.packet_id);
                                        // Clean up old entries (keep last 1000)
                                        if processed.len() > 1000 {
                                            processed.clear();
                                        }
                                    }
                                    
                                    info!("[DNS-QUERY] Reassembled packet {} ({} bytes)", packet.packet_id, reassembled_data.len());

                                    // Build client UDP address from DNS source IP and configured port
                                    let client_udp_port = config.client_udp_port.unwrap_or(5353);
                                    let client_udp_addr = SocketAddr::new(dns_source.ip(), client_udp_port);

                                    // Forward to target UDP
                                    if let Some(ref target_sock) = target_socket {
                                        if let Some(target_addr) = config.target_udp {
                                            // Compute hash of data for hash-based matching (echo servers)
                                            let mut hasher = DefaultHasher::new();
                                            reassembled_data.hash(&mut hasher);
                                            let data_hash = hasher.finish();
                                            
                                            let now = Instant::now();
                                            
                                            // Store in both hash map (for echo servers) and queue (for real services)
                                            {
                                                let mut hash_map = data_hash_to_packet.lock().await;
                                                hash_map.insert(data_hash, (packet.packet_id, client_udp_addr, now));
                                                info!("[FORWARD] Stored in hash_map: packet_id={}, hash={}, client={}", 
                                                      packet.packet_id, data_hash, client_udp_addr);
                                            }
                                            {
                                                let mut queue = response_queue.lock().await;
                                                queue.push_back((packet.packet_id, client_udp_addr, now, data_hash));
                                                info!("[FORWARD] Stored in queue: packet_id={}, hash={}, client={}", 
                                                      packet.packet_id, data_hash, client_udp_addr);
                                            }
                                            
                                            info!("[FORWARD] Sending {} bytes to target {}", reassembled_data.len(), target_addr);
                                            if let Err(e) = target_sock.send_to(&reassembled_data, target_addr).await {
                                                error!("Failed to forward packet to target: {}", e);
                                                // Remove from both maps on error
                                                let mut hash_map = data_hash_to_packet.lock().await;
                                                hash_map.remove(&data_hash);
                                                let mut queue = response_queue.lock().await;
                                                queue.retain(|(pid, _, _, h)| *pid != packet.packet_id && *h != data_hash);
                                            } else {
                                                info!("Forwarded packet {} (hash: {}) to {}", packet.packet_id, data_hash, target_addr);
                                            }
                                        }
                                    } else {
                                        // No target specified, just log
                                        debug!("No target UDP configured, packet would be forwarded here");
                                    }
                                    
                                    // Don't remove from pending_requests yet - we need it for response matching
                                    // It will be removed when we receive the response from target
                                }
                            }
                            Ok(None) => {
                                // Not a tunnel packet (domain doesn't match or query format invalid)
                                debug!("[DNS-QUERY] Does not match tunnel format or domain");
                                // Send empty response
                                let mut response = Message::new();
                                response.set_id(message.id());
                                response.set_message_type(hickory_proto::op::MessageType::Response);
                                response.set_response_code(ResponseCode::NXDomain);
                                
                                let mut buf = Vec::new();
                                let mut encoder = BinEncoder::new(&mut buf);
                                if response.emit(&mut encoder).is_ok() {
                                    let _ = dns_socket.send_to(&encoder.into_bytes(), dns_source).await;
                                }
                            }
                            Err(e) => {
                                warn!("Failed to decode DNS query from {}: {} (query: {:?})", 
                                      dns_source, e, message.queries().first().map(|q| q.name().to_ascii()));
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to parse DNS query: {}", e);
                    }
                }
            }
            Err(e) => {
                error!("Error receiving DNS query: {}", e);
                sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// Handle a SOCKS5 client connection on the server side (reverse proxy)
/// This allows connections from the server side to be forwarded through the tunnel to the client
async fn handle_server_socks5_client(
    stream: TcpStream,
    client_addr: SocketAddr,
    session_manager: Arc<Mutex<SessionManager>>,
) -> anyhow::Result<()> {
    use tokio::sync::mpsc;
    
    let mut conn = Socks5Connection::from_stream(stream, client_addr).await
        .context("SOCKS5 handshake failed")?;
    
    match conn.request.command {
        Command::Connect => {
            // Resolve target address
            let target_addr = conn.request.target.resolve().await
                .context("Failed to resolve target address")?;
            
            info!("[SOCKS5-REVERSE] CONNECT request: {} -> {}", client_addr, target_addr);
            
            // For reverse SOCKS5, we need to forward the connection through the tunnel
            // to the client, which will then connect to the target
            let (data_tx, mut data_rx) = mpsc::channel::<Vec<u8>>(256);
            let session_id = {
                let mut mgr = session_manager.lock().await;
                mgr.create_session(SessionType::Tcp, Some(target_addr), data_tx)
            };
            
            // In a full implementation, we would:
            // 1. Send a SYN packet through the tunnel to the client
            // 2. Wait for SYN-ACK from client confirming connection to target
            // 3. Then send success to the SOCKS5 client
            // 4. Forward data bi-directionally
            
            // For now, we send success immediately (simplified)
            conn.send_success(target_addr).await.context("Failed to send SOCKS5 success")?;
            
            let (mut read_half, mut write_half) = conn.stream.into_split();
            
            // Read from SOCKS5 client, forward through tunnel
            let _session_id_read = session_id;
            let _session_manager_read = session_manager.clone();
            
            let read_task = tokio::spawn(async move {
                let mut buf = vec![0u8; 65535];
                loop {
                    match read_half.read(&mut buf).await {
                        Ok(0) => {
                            debug!("[SOCKS5-REVERSE] Client closed connection");
                            break;
                        }
                        Ok(n) => {
                            // In full implementation, forward data through tunnel
                            let _data = &buf[..n];
                            debug!("[SOCKS5-REVERSE] Received {} bytes from client", n);
                            // TODO: Send through tunnel to client
                        }
                        Err(e) => {
                            warn!("[SOCKS5-REVERSE] Read error: {}", e);
                            break;
                        }
                    }
                }
            });
            
            // Write data from tunnel to SOCKS5 client
            let write_task = tokio::spawn(async move {
                while let Some(data) = data_rx.recv().await {
                    if let Err(e) = write_half.write_all(&data).await {
                        warn!("[SOCKS5-REVERSE] Write error: {}", e);
                        break;
                    }
                }
            });
            
            tokio::select! {
                _ = read_task => {}
                _ = write_task => {}
            }
            
            // Clean up session
            {
                let mut mgr = session_manager.lock().await;
                mgr.close(session_id);
            }
            
            info!("[SOCKS5-REVERSE] Connection closed: {} (session {})", client_addr, session_id);
        }
        Command::UdpAssociate | Command::Bind => {
            conn.send_failure(ReplyCode::CommandNotSupported).await
                .context("Failed to send SOCKS5 failure")?;
        }
    }
    
    Ok(())
}
