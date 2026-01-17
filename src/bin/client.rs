use anyhow::{Context, Result};
use clap::Parser;
use dns_tunnel::{
    config::{load_client_config, ClientConfig},
    dns_codec::DnsCodec,
    packet::{fragment_packet, PacketReassembler, TunnelPacket},
    tcp_proxy::{
        create_tcp_ack_packet, create_tcp_data_packet, create_tcp_fin_packet, create_tcp_rst_packet,
        create_tcp_syn_ack_packet, create_tcp_syn_packet, extract_tcp_packet, TcpConnectionManager,
        TcpPacketFlags, ConnectionState,
    },
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
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};

#[derive(Parser)]
#[command(name = "dns-tunnel-client")]
#[command(about = "DNS Tunnel Client (Iran side)")]
struct Args {
    #[arg(short, long)]
    config: Option<String>,
    #[arg(short, long, default_value = "127.0.0.1")]
    local_addr: String,
    #[arg(short, long)]
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

async fn send_tcp_packet_via_dns(
    codec: &Arc<DnsCodec>,
    dns_socket: &Arc<UdpSocket>,
    config: &ClientConfig,
    resolver_index: &Arc<Mutex<usize>>,
    data: &[u8],
    packet_id: u16,
) {
    let max_chunk = codec.max_payload_per_query();
    let fragments = fragment_packet(data, max_chunk);
    let total_fragments = fragments.len() as u8;
    
    let domain = &config.domains[rand::thread_rng().gen_range(0..config.domains.len())];
    let resolver = if config.rotate_resolvers {
        let mut idx = resolver_index.lock().await;
        *idx = (*idx + 1) % config.resolvers.len();
        rotate_resolver(&config.resolvers, *idx)
    } else {
        &config.resolvers[rand::thread_rng().gen_range(0..config.resolvers.len())]
    };
    
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
                
                for resolver in &config.resolvers {
                    if let Err(e) = dns_socket.send_to(&query_bytes, resolver).await {
                        warn!("Failed to send DNS query to {}: {}", resolver, e);
                    } else {
                        debug!("Sent TCP packet fragment {}/{} via DNS to {}", 
                               fragment_id + 1, total_fragments, resolver);
                    }
                }
            }
            Err(e) => {
                error!("Failed to encode TCP packet to DNS: {}", e);
            }
        }
    }
}

async fn handle_tcp_connection(
    stream: Arc<Mutex<TcpStream>>,
    connection_id: u32,
    codec: Arc<DnsCodec>,
    dns_socket: Arc<UdpSocket>,
    config: ClientConfig,
    tcp_connections: Arc<Mutex<TcpConnectionManager>>,
    tcp_streams: Arc<Mutex<HashMap<u32, Arc<Mutex<TcpStream>>>>>,
    pending_tcp_requests: Arc<Mutex<HashMap<u16, u32>>>,
    resolver_index: Arc<Mutex<usize>>,
    tcp_packet_id_counter: Arc<Mutex<u16>>,
) {
    let mut buf = vec![0u8; 8192];
    let mut established = false;
    
    // Wait for SYN-ACK (connection establishment)
    // For simplicity, we'll assume connection is established after a short delay
    // In production, you'd wait for actual SYN-ACK response
    sleep(Duration::from_millis(100)).await;
    
    {
        let mut conn_mgr = tcp_connections.lock().await;
        if let Some(conn) = conn_mgr.get_connection(connection_id) {
            conn.state = ConnectionState::Established;
            conn.update_activity();
            established = true;
        }
    }
    
    if !established {
        warn!("TCP connection {} not established", connection_id);
        return;
    }
    
    info!("TCP connection {} established", connection_id);
    
    // Read from TCP stream and send via DNS tunnel
    loop {
        let read_result = {
            let mut stream_guard = stream.lock().await;
            stream_guard.read(&mut buf).await
        };
        
        match read_result {
            Ok(0) => {
                // EOF - send FIN
                info!("TCP connection {} closed by client", connection_id);
                let fin_packet = {
                    let mut conn_mgr = tcp_connections.lock().await;
                    if let Some(conn) = conn_mgr.get_connection(connection_id) {
                        let seq = conn.next_sequence;
                        conn.next_sequence = conn.next_sequence.wrapping_add(1);
                        create_tcp_fin_packet(connection_id, seq)
                    } else {
                        break;
                    }
                };
                
                let fin_data = fin_packet.serialize();
                let packet_id = {
                    let mut counter = tcp_packet_id_counter.lock().await;
                    let id = *counter;
                    *counter = counter.wrapping_add(1);
                    if *counter == 0 {
                        *counter = 1; // Skip 0 to avoid conflicts
                    }
                    id
                };
                
                {
                    let mut pending = pending_tcp_requests.lock().await;
                    pending.insert(packet_id, connection_id);
                }
                
                send_tcp_packet_via_dns(
                    &codec,
                    &dns_socket,
                    &config,
                    &resolver_index,
                    &fin_data,
                    packet_id,
                ).await;
                break;
            }
            Ok(n) => {
                let data = &buf[..n];
                debug!("Read {} bytes from TCP connection {}", n, connection_id);
                
                // Create TCP data packet
                let tcp_packet = {
                    let mut conn_mgr = tcp_connections.lock().await;
                    if let Some(conn) = conn_mgr.get_connection(connection_id) {
                        let seq = conn.next_sequence;
                        conn.next_sequence = conn.next_sequence.wrapping_add(data.len() as u32);
                        conn.update_activity();
                        create_tcp_data_packet(connection_id, seq, data)
                    } else {
                        break;
                    }
                };
                
                let packet_data = tcp_packet.serialize();
                let packet_id = {
                    let mut counter = tcp_packet_id_counter.lock().await;
                    let id = *counter;
                    *counter = counter.wrapping_add(1);
                    if *counter == 0 {
                        *counter = 1; // Skip 0 to avoid conflicts
                    }
                    id
                };
                
                {
                    let mut pending = pending_tcp_requests.lock().await;
                    pending.insert(packet_id, connection_id);
                }
                
                send_tcp_packet_via_dns(
                    &codec,
                    &dns_socket,
                    &config,
                    &resolver_index,
                    &packet_data,
                    packet_id,
                ).await;
            }
            Err(e) => {
                error!("Error reading from TCP stream {}: {}", connection_id, e);
                break;
            }
        }
    }
    
    // Cleanup
    {
        let mut conn_mgr = tcp_connections.lock().await;
        conn_mgr.remove_connection(connection_id);
    }
    {
        let mut streams = tcp_streams.lock().await;
        streams.remove(&connection_id);
    }
    info!("TCP connection {} closed", connection_id);
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
    let pending_tcp_requests: Arc<Mutex<HashMap<u16, u32>>> = Arc::new(Mutex::new(HashMap::new())); // packet_id -> connection_id
    let tcp_connections: Arc<Mutex<TcpConnectionManager>> = Arc::new(Mutex::new(TcpConnectionManager::new()));
    let tcp_streams: Arc<Mutex<HashMap<u32, Arc<Mutex<TcpStream>>>>> = Arc::new(Mutex::new(HashMap::new()));
    let resolver_index = Arc::new(Mutex::new(0usize));
    let tcp_packet_id_counter: Arc<Mutex<u16>> = Arc::new(Mutex::new(1u16)); // Start at 1 to avoid 0

    // Start TCP listener if configured
    if let Some(tcp_listen_addr) = config.tcp_listen {
        let tcp_listener = TcpListener::bind(&tcp_listen_addr)
            .await
            .context("Failed to bind TCP listener")?;
        info!("TCP listener bound to: {}", tcp_listen_addr);
        
        let codec_clone = codec.clone();
        let dns_query_socket_clone = dns_query_socket.clone();
        let config_clone = config.clone();
        let tcp_connections_clone = tcp_connections.clone();
        let tcp_streams_clone = tcp_streams.clone();
        let pending_tcp_requests_clone = pending_tcp_requests.clone();
        let resolver_index_clone = resolver_index.clone();
        let tcp_packet_id_counter_clone = tcp_packet_id_counter.clone();
        
        tokio::spawn(async move {
            loop {
                match tcp_listener.accept().await {
                    Ok((stream, addr)) => {
                        info!("New TCP connection from: {}", addr);
                        let connection_id = {
                            let mut conn_mgr = tcp_connections_clone.lock().await;
                            conn_mgr.create_connection(addr, "0.0.0.0:0".parse().unwrap())
                        };
                        
                        let stream = Arc::new(Mutex::new(stream));
                        {
                            let mut streams = tcp_streams_clone.lock().await;
                            streams.insert(connection_id, stream.clone());
                        }
                        
                        // Send SYN packet
                        let syn_packet = create_tcp_syn_packet(connection_id);
                        let syn_data = syn_packet.serialize();
                        
                        let packet_id = {
                            let mut counter = tcp_packet_id_counter_clone.lock().await;
                            let id = *counter;
                            *counter = counter.wrapping_add(1);
                            if *counter == 0 {
                                *counter = 1; // Skip 0 to avoid conflicts
                            }
                            id
                        };
                        
                        {
                            let mut pending = pending_tcp_requests_clone.lock().await;
                            pending.insert(packet_id, connection_id);
                        }
                        
                        // Send SYN via DNS tunnel
                        send_tcp_packet_via_dns(
                            &codec_clone,
                            &dns_query_socket_clone,
                            &config_clone,
                            &resolver_index_clone,
                            &syn_data,
                            packet_id,
                        ).await;
                        
                        // Handle TCP connection
                        let codec_conn = codec_clone.clone();
                        let dns_socket_conn = dns_query_socket_clone.clone();
                        let config_conn = config_clone.clone();
                        let tcp_conns = tcp_connections_clone.clone();
                        let tcp_strs = tcp_streams_clone.clone();
                        let pending_tcp = pending_tcp_requests_clone.clone();
                        let resolver_idx = resolver_index_clone.clone();
                        let tcp_packet_id_conn = tcp_packet_id_counter_clone.clone();
                        
                        tokio::spawn(async move {
                            handle_tcp_connection(
                                stream,
                                connection_id,
                                codec_conn,
                                dns_socket_conn,
                                config_conn,
                                tcp_conns,
                                tcp_strs,
                                pending_tcp,
                                resolver_idx,
                                tcp_packet_id_conn,
                            ).await;
                        });
                    }
                    Err(e) => {
                        error!("Error accepting TCP connection: {}", e);
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
                            // Check if this is a TCP packet
                            if PacketReassembler::is_tcp_packet(&reassembled_data) {
                                // Handle TCP packet
                                match extract_tcp_packet(&reassembled_data) {
                                    Ok(tcp_packet) => {
                                        debug!("Received TCP packet: connection_id={}, sequence={}, flags={}", 
                                               tcp_packet.connection_id, tcp_packet.sequence, tcp_packet.flags);
                                        
                                        let flags = TcpPacketFlags::from_byte(tcp_packet.flags);
                                        
                                        // Handle different TCP packet types
                                        let has_syn = flags.iter().any(|f| *f == TcpPacketFlags::Syn);
                                        let has_ack = flags.iter().any(|f| *f == TcpPacketFlags::Ack);
                                        let has_data = flags.iter().any(|f| *f == TcpPacketFlags::Data);
                                        let has_fin = flags.iter().any(|f| *f == TcpPacketFlags::Fin);
                                        
                                        if has_syn && has_ack {
                                            // SYN-ACK: connection established
                                            let mut conn_mgr = tcp_connections.lock().await;
                                            if let Some(conn) = conn_mgr.get_connection(tcp_packet.connection_id) {
                                                conn.state = ConnectionState::Established;
                                                conn.expected_sequence = tcp_packet.sequence.wrapping_add(1);
                                                conn.update_activity();
                                                
                                                // Send ACK
                                                let ack_packet = create_tcp_ack_packet(tcp_packet.connection_id, conn.expected_sequence);
                                                let ack_data = ack_packet.serialize();
                                                let ack_packet_id = {
                                                    let mut counter = tcp_packet_id_counter.lock().await;
                                                    let id = *counter;
                                                    *counter = counter.wrapping_add(1);
                                                    if *counter == 0 {
                                                        *counter = 1; // Skip 0 to avoid conflicts
                                                    }
                                                    id
                                                };
                                                
                                                {
                                                    let mut pending = pending_tcp_requests.lock().await;
                                                    pending.insert(ack_packet_id, tcp_packet.connection_id);
                                                }
                                                
                                                send_tcp_packet_via_dns(
                                                    &codec,
                                                    &dns_query_socket,
                                                    &config,
                                                    &resolver_index,
                                                    &ack_data,
                                                    ack_packet_id,
                                                ).await;
                                            }
                                        } else if has_data {
                                            // Data packet: write to TCP stream
                                            let streams = tcp_streams.lock().await;
                                            if let Some(stream) = streams.get(&tcp_packet.connection_id) {
                                                let mut stream_guard = stream.lock().await;
                                                if let Err(e) = stream_guard.write_all(&tcp_packet.data).await {
                                                    error!("Failed to write to TCP stream {}: {}", tcp_packet.connection_id, e);
                                                } else {
                                                    debug!("Wrote {} bytes to TCP stream {}", tcp_packet.data.len(), tcp_packet.connection_id);
                                                    
                                                    // Update connection
                                                    let mut conn_mgr = tcp_connections.lock().await;
                                                    if let Some(conn) = conn_mgr.get_connection(tcp_packet.connection_id) {
                                                        conn.expected_sequence = tcp_packet.sequence.wrapping_add(tcp_packet.data.len() as u32);
                                                        conn.update_activity();
                                                    }
                                                }
                                            }
                                        } else if has_fin {
                                            // FIN: close connection
                                            info!("Received FIN for TCP connection {}", tcp_packet.connection_id);
                                            let mut conn_mgr = tcp_connections.lock().await;
                                            conn_mgr.remove_connection(tcp_packet.connection_id);
                                            let mut streams = tcp_streams.lock().await;
                                            streams.remove(&tcp_packet.connection_id);
                                        }
                                    }
                                    Err(e) => {
                                        warn!("Failed to extract TCP packet: {}", e);
                                    }
                                }
                            } else {
                                // Regular UDP packet
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
                    let resolver = if config.rotate_resolvers {
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
