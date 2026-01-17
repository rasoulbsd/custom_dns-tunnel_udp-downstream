use anyhow::{Context, Result};
use clap::Parser;
use dns_tunnel::{
    config::{load_server_config, ServerConfig},
    dns_codec::DnsCodec,
    packet::{fragment_packet, PacketReassembler},
    utils::get_random_port,
};
use hickory_proto::{
    op::{Message, ResponseCode},
    serialize::binary::{BinDecodable, BinEncodable, BinEncoder},
};
use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
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
    info!("Max subdomain length: {}", config.max_subdomain_length);

    if config.domains.is_empty() {
        anyhow::bail!("At least one domain must be specified");
    }

    // Bind DNS socket
    let dns_socket = UdpSocket::bind(&dns_bind)
        .await
        .context("Failed to bind DNS socket")?;
    info!("Bound to DNS: {}", dns_bind);

    // Create target UDP socket if specified
    let target_socket = if let Some(_target) = target_udp {
        Some(Arc::new(UdpSocket::bind("0.0.0.0:0")
            .await
            .context("Failed to bind target UDP socket")?))
    } else {
        None
    };

    let codec = Arc::new(DnsCodec::new(config.max_subdomain_length));
    let reassembler = Arc::new(Mutex::new(PacketReassembler::new()));
    // Map: packet_id -> (dns_source, query_id)
    let pending_requests: Arc<Mutex<HashMap<u16, (SocketAddr, u16)>>> = Arc::new(Mutex::new(HashMap::new()));
    // Map: data_hash -> (packet_id, client_udp_addr, timestamp) for matching responses from target_udp
    // This allows us to match echo responses to the correct packet_id using data hash
    let data_hash_to_packet: Arc<Mutex<HashMap<u64, (u16, SocketAddr, Instant)>>> = Arc::new(Mutex::new(HashMap::new()));
    
    // Create a UDP socket for sending responses directly to client
    let client_response_socket = Arc::new(UdpSocket::bind("0.0.0.0:0")
        .await
        .context("Failed to bind client response UDP socket")?);

    // Spawn task to receive UDP responses from target
    if let Some(ref target_sock) = target_socket {
        if let Some(_target_addr) = config.target_udp {
            let target_sock = target_sock.clone();
            let codec = codec.clone();
            let client_response_socket = client_response_socket.clone();
            let data_hash_to_packet = data_hash_to_packet.clone();
            
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65507];
                const RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
                
                loop {
                    match target_sock.recv_from(&mut buf).await {
                        Ok((len, _src)) => {
                            let data = &buf[..len];
                            debug!("Received {} bytes from target", len);

                            // Compute hash of received data to match with outgoing request
                            let mut hasher = DefaultHasher::new();
                            data.hash(&mut hasher);
                            let data_hash = hasher.finish();
                            
                            // Find the original packet_id and client UDP address
                            let mut hash_map = data_hash_to_packet.lock().await;
                            
                            // Clean up old entries
                            let now = Instant::now();
                            hash_map.retain(|_, (_, _, timestamp)| {
                                now.duration_since(*timestamp) < RESPONSE_TIMEOUT
                            });
                            
                            if let Some((original_packet_id, client_udp_addr, _)) = hash_map.remove(&data_hash) {
                                info!("Matched target response to packet_id: {}, sending to {}", 
                                      original_packet_id, client_udp_addr);
                                
                                // Fragment and encode as UDP packets (not DNS)
                                let max_chunk = 65507 - 4; // Max UDP size minus header
                                let fragments = fragment_packet(data, max_chunk);
                                let total_fragments = fragments.len() as u8;
                                
                                info!("Fragmenting response into {} fragments", total_fragments);
                                
                                // Use the ORIGINAL packet_id so client can match it
                                let response_packet_id = original_packet_id;

                                for (fragment_id, fragment_data) in fragments.iter().enumerate() {
                                    let udp_packet = codec.encode_udp_packet(
                                        fragment_data,
                                        response_packet_id,
                                        fragment_id as u8,
                                        total_fragments,
                                    );
                                    
                                    if let Err(e) = client_response_socket.send_to(&udp_packet, client_udp_addr).await {
                                        warn!("Failed to send UDP response: {}", e);
                                    } else {
                                        info!("Sent UDP response fragment {}/{} ({} bytes) to {}", 
                                               fragment_id + 1, total_fragments, udp_packet.len(), client_udp_addr);
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

    // Main loop: receive DNS queries and forward as UDP
    let mut buf = vec![0u8; 65535];
    
    loop {
        match dns_socket.recv_from(&mut buf).await {
            Ok((len, dns_source)) => {
                let query_data = &buf[..len];
                
                match Message::from_bytes(query_data) {
                    Ok(message) => {
                        info!("Received DNS query from {} ({} bytes)", dns_source, len);
                        match codec.decode_from_dns_query(&message, &config.domains) {
                            Ok(Some(mut packet)) => {
                                // Set the actual source from DNS query
                                packet.source = dns_source;
                                
                                info!("Decoded DNS query from {}: packet_id={}, fragment={}/{}", 
                                       dns_source, packet.packet_id, packet.fragment_id + 1, packet.total_fragments);

                                // Store pending request for DNS response (if needed)
                                {
                                    let mut pending = pending_requests.lock().await;
                                    pending.insert(packet.packet_id, (dns_source, message.id()));
                                }

                                // Reassemble packet
                                let mut reass = reassembler.lock().await;
                                if let Some(reassembled_data) = reass.add_fragment(packet.clone()) {
                                    info!("Reassembled packet {} ({} bytes)", packet.packet_id, reassembled_data.len());

                                    // Build client UDP address from DNS source IP and configured port
                                    let client_udp_port = config.client_udp_port.unwrap_or(5353);
                                    let client_udp_addr = SocketAddr::new(dns_source.ip(), client_udp_port);

                                    // Forward to target UDP
                                    if let Some(ref target_sock) = target_socket {
                                        if let Some(target_addr) = config.target_udp {
                                            // Compute hash of data to match response later
                                            let mut hasher = DefaultHasher::new();
                                            reassembled_data.hash(&mut hasher);
                                            let data_hash = hasher.finish();
                                            
                                            // Store mapping: data_hash -> (packet_id, client_udp_addr)
                                            {
                                                let mut hash_map = data_hash_to_packet.lock().await;
                                                hash_map.insert(data_hash, (packet.packet_id, client_udp_addr, Instant::now()));
                                            }
                                            
                                            if let Err(e) = target_sock.send_to(&reassembled_data, target_addr).await {
                                                error!("Failed to forward packet to target: {}", e);
                                                // Remove from hash map on error
                                                let mut hash_map = data_hash_to_packet.lock().await;
                                                hash_map.remove(&data_hash);
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
                                debug!("DNS query does not match tunnel format or domain");
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
