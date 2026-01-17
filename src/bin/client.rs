use anyhow::{Context, Result};
use clap::Parser;
use dns_tunnel::{
    config::{load_client_config, ClientConfig},
    dns_codec::DnsCodec,
    packet::{fragment_packet, PacketReassembler},
    utils::{get_random_port, rotate_resolver},
};
use hickory_proto::{
    serialize::binary::{BinEncodable, BinEncoder},
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
    info!("Domains: {:?}", config.domains);
    info!("Resolvers: {:?}", config.resolvers);
    info!("Max subdomain length: {}", config.max_subdomain_length);
    info!("Resolver rotation: {}", config.rotate_resolvers);

    if config.domains.is_empty() {
        anyhow::bail!("At least one domain must be specified");
    }
    if config.resolvers.is_empty() {
        anyhow::bail!("At least one resolver must be specified");
    }

    // Bind local UDP socket for receiving from applications
    let udp_socket = UdpSocket::bind(&local_udp)
        .await
        .context("Failed to bind local UDP socket")?;
    info!("Bound to local UDP: {}", local_udp);
    
    // Create a separate socket for sending DNS queries (bind to all interfaces)
    // This allows sending to both local and external resolvers
    let dns_query_socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .context("Failed to bind DNS query socket")?;
    let dns_query_socket = Arc::new(dns_query_socket);

    let codec = Arc::new(DnsCodec::new(config.max_subdomain_length));
    let reassembler = Arc::new(Mutex::new(PacketReassembler::new()));
    let pending_requests: Arc<Mutex<HashMap<u16, (SocketAddr, u16)>>> = Arc::new(Mutex::new(HashMap::new()));
    let resolver_index = Arc::new(Mutex::new(0usize));

    // Main loop: receive packets and handle both local UDP and DNS responses
    let mut buf = vec![0u8; 65535];
    let mut packet_id_counter = 0u16;
    
    loop {
        match udp_socket.recv_from(&mut buf).await {
            Ok((len, source)) => {
                let data = &buf[..len];
                debug!("Received {} bytes from {}", len, source);
                
                // Check if this is a UDP response from server or a local UDP packet
                // Server responses will be UDP packets with our tunnel format (4-byte header)
                // Local UDP packets from applications won't have this format
                // We check if it's a valid tunnel packet by trying to decode it
                // Only check if data is at least 4 bytes (header size)
                // Also check if packet_id exists in pending_requests (server responses will have this)
                let decoded_packet = if data.len() >= 4 {
                    codec.decode_udp_packet(data).ok().flatten()
                } else {
                    None
                };
                
                let is_tunnel_packet = if let Some(ref packet) = decoded_packet {
                    // Additional validation: check if this packet_id is in pending requests
                    // This helps distinguish server responses from random local UDP
                    let pending = pending_requests.lock().await;
                    let has_pending = pending.contains_key(&packet.packet_id);
                    debug!("Decoded packet: packet_id={}, fragment={}/{}, has_pending={}", 
                           packet.packet_id, packet.fragment_id + 1, packet.total_fragments, has_pending);
                    has_pending
                } else {
                    false
                };
                
                if is_tunnel_packet {
                    // This is a UDP response from the server
                    if let Some(packet) = decoded_packet {
                        info!("Received tunnel UDP packet: packet_id={}, fragment={}/{}", 
                               packet.packet_id, packet.fragment_id + 1, packet.total_fragments);
                        let mut reass = reassembler.lock().await;
                        if let Some(reassembled_data) = reass.add_fragment(packet.clone()) {
                            // Find the original source
                            let mut pending = pending_requests.lock().await;
                            if let Some((original_source, _)) = pending.remove(&packet.packet_id) {
                                // Forward reassembled packet to original source
                                if let Err(e) = udp_socket.send_to(&reassembled_data, original_source).await {
                                    error!("Failed to send reassembled packet: {}", e);
                                } else {
                                    info!("Sent reassembled packet {} ({} bytes) to {}", 
                                          packet.packet_id, reassembled_data.len(), original_source);
                                }
                            } else {
                                warn!("No pending request found for packet_id: {}", packet.packet_id);
                            }
                        }
                    }
                } else {
                    // Not a tunnel packet from server, treat as local UDP packet
                    // This is a local UDP packet from an application
                    if decoded_packet.is_some() {
                        debug!("Received UDP packet that decoded but packet_id not in pending_requests - treating as local UDP");
                    }
                    info!("Received {} bytes from local application {}", len, source);

                    // Generate packet ID
                    let packet_id = packet_id_counter;
                    packet_id_counter = packet_id_counter.wrapping_add(1);

                    // Store pending request
                    {
                        let mut pending = pending_requests.lock().await;
                        pending.insert(packet_id, (source, 0));
                    }

                    // Fragment packet if needed
                    let max_chunk = codec.max_payload_per_query();
                    let fragments = fragment_packet(data, max_chunk);
                    let total_fragments = fragments.len() as u8;

                    info!("Fragmenting packet {} into {} fragments", packet_id, total_fragments);

                    // Select domain and resolver
                    let domain = &config.domains[rand::thread_rng().gen_range(0..config.domains.len())];
                    // Note: resolver selection is computed but we send to all resolvers (spam mode)
                    let _resolver = if config.rotate_resolvers {
                        let mut idx = resolver_index.lock().await;
                        *idx = (*idx + 1) % config.resolvers.len();
                        rotate_resolver(&config.resolvers, *idx)
                    } else {
                        &config.resolvers[rand::thread_rng().gen_range(0..config.resolvers.len())]
                    };

                    // Send each fragment as DNS query
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
                                    
                                    // Send to multiple resolvers (spam)
                                    let dns_socket = dns_query_socket.clone();
                                    for resolver in &config.resolvers {
                                        if let Err(e) = dns_socket.send_to(&query_bytes, resolver).await {
                                            warn!("Failed to send DNS query to {}: {}", resolver, e);
                                        } else {
                                            info!("Sent DNS query fragment {}/{} ({} bytes) to {}", 
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
            }
            Err(e) => {
                error!("Error receiving UDP packet: {}", e);
                sleep(Duration::from_millis(100)).await;
            }
        }
    }
}
