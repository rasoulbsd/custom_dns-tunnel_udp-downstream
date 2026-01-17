use anyhow::{Context, Result};
use clap::Parser;
use dns_tunnel::{
    config::{load_server_config, ServerConfig},
    dns_codec::DnsCodec,
    packet::{fragment_packet, PacketReassembler},
    tcp_proxy::{
        create_tcp_ack_packet, create_tcp_data_packet, create_tcp_fin_packet, create_tcp_rst_packet,
        create_tcp_syn_ack_packet, extract_tcp_packet, TcpConnectionManager, TcpPacketFlags,
        ConnectionState,
    },
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
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};

#[derive(Parser)]
#[command(name = "dns-tunnel-server")]
#[command(about = "DNS Tunnel Server (VPS side)")]
struct Args {
    #[arg(short, long)]
    config: Option<String>,
    #[arg(short, long, default_value = "0.0.0.0")]
    dns_bind_addr: String,
    #[arg(short, long)]
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

async fn send_tcp_response_via_udp(
    codec: &Arc<DnsCodec>,
    client_socket: &Arc<UdpSocket>,
    tcp_packet: &dns_tunnel::tcp_proxy::TcpPacket,
    client_addr: SocketAddr,
    packet_id: u16,
) {
    let tcp_data = tcp_packet.serialize();
    let max_chunk = 65507 - 4; // Max UDP size minus header
    let fragments = fragment_packet(&tcp_data, max_chunk);
    let total_fragments = fragments.len() as u8;
    
    for (fragment_id, fragment_data) in fragments.iter().enumerate() {
        let udp_packet = codec.encode_udp_packet(
            fragment_data,
            packet_id,
            fragment_id as u8,
            total_fragments,
        );
        
        if let Err(e) = client_socket.send_to(&udp_packet, client_addr).await {
            warn!("Failed to send TCP response via UDP: {}", e);
        } else {
            debug!("Sent TCP response fragment {}/{} via UDP", fragment_id + 1, total_fragments);
        }
    }
}

async fn handle_tcp_response(
    stream: Arc<Mutex<TcpStream>>,
    connection_id: u32,
    codec: Arc<DnsCodec>,
    client_socket: Arc<UdpSocket>,
    conn_to_client: Arc<Mutex<HashMap<u32, SocketAddr>>>,
    tcp_streams: Arc<Mutex<HashMap<u32, Arc<Mutex<TcpStream>>>>>,
    tcp_connections: Arc<Mutex<TcpConnectionManager>>,
) {
    let mut buf = vec![0u8; 8192];
    let mut packet_id_counter = 0u16;
    let mut sequence = 1u32;
    
    loop {
        let read_result = {
            let mut stream_guard = stream.lock().await;
            stream_guard.read(&mut buf).await
        };
        
        match read_result {
            Ok(0) => {
                // EOF - send FIN
                info!("TCP connection {} closed by target", connection_id);
                let fin_packet = create_tcp_fin_packet(connection_id, sequence);
                
                let client_addr = {
                    let conn_map = conn_to_client.lock().await;
                    conn_map.get(&connection_id).copied()
                };
                
                if let Some(addr) = client_addr {
                    let packet_id = {
                        let mut counter = packet_id_counter;
                        packet_id_counter = packet_id_counter.wrapping_add(1);
                        counter
                    };
                    
                    send_tcp_response_via_udp(
                        &codec,
                        &client_socket,
                        &fin_packet,
                        addr,
                        packet_id,
                    ).await;
                }
                break;
            }
            Ok(n) => {
                let data = &buf[..n];
                debug!("Read {} bytes from TCP stream {}", n, connection_id);
                
                // Create TCP data packet
                let tcp_packet = create_tcp_data_packet(connection_id, sequence, data);
                sequence = sequence.wrapping_add(n as u32);
                
                let client_addr = {
                    let conn_map = conn_to_client.lock().await;
                    conn_map.get(&connection_id).copied()
                };
                
                if let Some(addr) = client_addr {
                    let packet_id = {
                        let mut counter = packet_id_counter;
                        packet_id_counter = packet_id_counter.wrapping_add(1);
                        counter
                    };
                    
                    send_tcp_response_via_udp(
                        &codec,
                        &client_socket,
                        &tcp_packet,
                        addr,
                        packet_id,
                    ).await;
                    
                    // Update connection
                    let mut conn_mgr = tcp_connections.lock().await;
                    if let Some(conn) = conn_mgr.get_connection(connection_id) {
                        conn.update_activity();
                    }
                } else {
                    warn!("No client address found for connection {}", connection_id);
                }
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
    {
        let mut conn_to_client = conn_to_client.lock().await;
        conn_to_client.remove(&connection_id);
    }
    info!("TCP connection {} handler closed", connection_id);
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
    info!("Target TCP: {:?}", config.tcp_target);
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
    // Map: packet_id -> client_udp_addr (for responses from target)
    // We'll use the DNS query source IP and a UDP port (we'll need to get this from config or embed in query)
    let packet_to_client_udp: Arc<Mutex<HashMap<u16, SocketAddr>>> = Arc::new(Mutex::new(HashMap::new()));
    // TCP connection management
    let tcp_connections: Arc<Mutex<TcpConnectionManager>> = Arc::new(Mutex::new(TcpConnectionManager::new()));
    // Map: connection_id -> TcpStream to target
    let tcp_streams: Arc<Mutex<HashMap<u32, Arc<Mutex<TcpStream>>>>> = Arc::new(Mutex::new(HashMap::new()));
    // Map: connection_id -> client_udp_addr for responses
    let tcp_connection_to_client: Arc<Mutex<HashMap<u32, SocketAddr>>> = Arc::new(Mutex::new(HashMap::new()));
    
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
            let packet_to_client_udp = packet_to_client_udp.clone();
            
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65507];
                
                loop {
                    match target_sock.recv_from(&mut buf).await {
                        Ok((len, _src)) => {
                            let data = &buf[..len];
                            debug!("Received {} bytes from target", len);

                            // Find the original client UDP address using packet_id
                            // We use FIFO approach: take the first (oldest) entry
                            // This works because responses come back in order for single-threaded echo server
                            let mut packet_map = packet_to_client_udp.lock().await;
                            
                            if let Some((&original_packet_id, &client_udp_addr)) = packet_map.iter().next() {
                                packet_map.remove(&original_packet_id);
                                
                                info!("Matching target response to original packet_id: {}, sending to {}", 
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
                                warn!("No matching client UDP address found for target response");
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

                                // Store pending request and client UDP address for response routing
                                {
                                    let mut pending = pending_requests.lock().await;
                                    pending.insert(packet.packet_id, (dns_source, message.id()));
                                    
                                    // Build client UDP address from DNS source IP and configured port
                                    let client_udp_port = config.client_udp_port.unwrap_or(5353);
                                    let client_udp_addr = SocketAddr::new(dns_source.ip(), client_udp_port);
                                    
                                    let mut packet_map = packet_to_client_udp.lock().await;
                                    packet_map.insert(packet.packet_id, client_udp_addr);
                                }

                                // Reassemble packet
                                let mut reass = reassembler.lock().await;
                                if let Some(reassembled_data) = reass.add_fragment(packet.clone()) {
                                    info!("Reassembled packet {} ({} bytes)", packet.packet_id, reassembled_data.len());

                                    // Check if this is a TCP packet
                                    if PacketReassembler::is_tcp_packet(&reassembled_data) {
                                        info!("Detected TCP packet ({} bytes), extracting...", reassembled_data.len());
                                        // Handle TCP packet
                                        match extract_tcp_packet(&reassembled_data) {
                                            Ok(tcp_packet) => {
                                                info!("Received TCP packet: connection_id={}, sequence={}, flags={}, data_length={}, actual_data_len={}", 
                                                       tcp_packet.connection_id, tcp_packet.sequence, tcp_packet.flags, tcp_packet.data_length, tcp_packet.data.len());
                                                
                                                let client_udp_addr = {
                                                    let client_udp_port = config.client_udp_port.unwrap_or(5353);
                                                    SocketAddr::new(dns_source.ip(), client_udp_port)
                                                };
                                                
                                                // Store client address for this connection
                                                {
                                                    let mut conn_to_client = tcp_connection_to_client.lock().await;
                                                    conn_to_client.insert(tcp_packet.connection_id, client_udp_addr);
                                                }
                                                
                                                let flags = TcpPacketFlags::from_byte(tcp_packet.flags);
                                                let has_syn = flags.iter().any(|f| *f == TcpPacketFlags::Syn);
                                                let has_ack = flags.iter().any(|f| *f == TcpPacketFlags::Ack);
                                                let has_data = flags.iter().any(|f| *f == TcpPacketFlags::Data);
                                                let has_fin = flags.iter().any(|f| *f == TcpPacketFlags::Fin);
                                                
                                                if has_syn && !has_ack {
                                                    // SYN: establish connection to target
                                                    if let Some(tcp_target) = config.tcp_target {
                                                        info!("Establishing TCP connection {} to {}", tcp_packet.connection_id, tcp_target);
                                                        
                                                        // Create connection entry with client's connection ID
                                                        {
                                                            let mut conn_mgr = tcp_connections.lock().await;
                                                            conn_mgr.create_connection_with_id(tcp_packet.connection_id, dns_source, tcp_target);
                                                        }
                                                        
                                                        match TcpStream::connect(tcp_target).await {
                                                            Ok(stream) => {
                                                                let stream = Arc::new(Mutex::new(stream));
                                                                {
                                                                    let mut streams = tcp_streams.lock().await;
                                                                    streams.insert(tcp_packet.connection_id, stream.clone());
                                                                }
                                                                
                                                                {
                                                                    let mut conn_mgr = tcp_connections.lock().await;
                                                                    if let Some(conn) = conn_mgr.get_connection(tcp_packet.connection_id) {
                                                                        conn.state = ConnectionState::Established;
                                                                        conn.update_activity();
                                                                    }
                                                                }
                                                                
                                                                // Send SYN-ACK
                                                                let syn_ack = create_tcp_syn_ack_packet(tcp_packet.connection_id, 1);
                                                                send_tcp_response_via_udp(
                                                                    &codec,
                                                                    &client_response_socket,
                                                                    &syn_ack,
                                                                    client_udp_addr,
                                                                    packet.packet_id,
                                                                ).await;
                                                                
                                                                // Spawn task to read from TCP stream and send back
                                                                let codec_read = codec.clone();
                                                                let client_socket_read = client_response_socket.clone();
                                                                let conn_to_client_read = tcp_connection_to_client.clone();
                                                                let tcp_strs_read = tcp_streams.clone();
                                                                let tcp_conns_read = tcp_connections.clone();
                                                                let conn_id = tcp_packet.connection_id;
                                                                
                                                                tokio::spawn(async move {
                                                                    handle_tcp_response(
                                                                        stream,
                                                                        conn_id,
                                                                        codec_read,
                                                                        client_socket_read,
                                                                        conn_to_client_read,
                                                                        tcp_strs_read,
                                                                        tcp_conns_read,
                                                                    ).await;
                                                                });
                                                            }
                                                            Err(e) => {
                                                                error!("Failed to connect to TCP target {}: {}", tcp_target, e);
                                                                // Send RST
                                                                let rst = create_tcp_rst_packet(tcp_packet.connection_id);
                                                                send_tcp_response_via_udp(
                                                                    &codec,
                                                                    &client_response_socket,
                                                                    &rst,
                                                                    client_udp_addr,
                                                                    packet.packet_id,
                                                                ).await;
                                                            }
                                                        }
                                                    }
                                                } else if has_data {
                                                    // Data packet: write to TCP stream
                                                    info!("Received TCP data packet: connection_id={}, data_len={}", 
                                                          tcp_packet.connection_id, tcp_packet.data.len());
                                                    let streams = tcp_streams.lock().await;
                                                    if let Some(stream) = streams.get(&tcp_packet.connection_id) {
                                                        let mut stream_guard = stream.lock().await;
                                                        if let Err(e) = stream_guard.write_all(&tcp_packet.data).await {
                                                            error!("Failed to write to TCP stream {}: {}", tcp_packet.connection_id, e);
                                                        } else {
                                                            info!("Wrote {} bytes to TCP stream {}", tcp_packet.data.len(), tcp_packet.connection_id);
                                                            
                                                            // Update connection
                                                            let mut conn_mgr = tcp_connections.lock().await;
                                                            if let Some(conn) = conn_mgr.get_connection(tcp_packet.connection_id) {
                                                                conn.update_activity();
                                                            }
                                                            
                                                            // Send ACK back to client (optional, but helps with flow control)
                                                            // Note: In a full TCP implementation, we'd track sequence numbers
                                                            // For now, we'll just acknowledge receipt
                                                        }
                                                    } else {
                                                        warn!("No TCP stream found for connection {}", tcp_packet.connection_id);
                                                    }
                                                } else if has_fin {
                                                    // FIN: close connection
                                                    info!("Received FIN for TCP connection {}", tcp_packet.connection_id);
                                                    let streams = tcp_streams.lock().await;
                                                    if let Some(stream) = streams.get(&tcp_packet.connection_id) {
                                                        let mut stream_guard = stream.lock().await;
                                                        let _ = stream_guard.shutdown().await;
                                                    }
                                                    
                                                    // Send FIN-ACK
                                                    let fin_ack = create_tcp_fin_packet(tcp_packet.connection_id, tcp_packet.sequence.wrapping_add(1));
                                                    send_tcp_response_via_udp(
                                                        &codec,
                                                        &client_response_socket,
                                                        &fin_ack,
                                                        client_udp_addr,
                                                        packet.packet_id,
                                                    ).await;
                                                    
                                                    // Cleanup
                                                    {
                                                        let mut conn_mgr = tcp_connections.lock().await;
                                                        conn_mgr.remove_connection(tcp_packet.connection_id);
                                                    }
                                                    {
                                                        let mut streams = tcp_streams.lock().await;
                                                        streams.remove(&tcp_packet.connection_id);
                                                    }
                                                    {
                                                        let mut conn_to_client = tcp_connection_to_client.lock().await;
                                                        conn_to_client.remove(&tcp_packet.connection_id);
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                error!("Failed to extract TCP packet: {} (reassembled_data len: {}, first 20 bytes: {:?})", 
                                                       e, reassembled_data.len(), 
                                                       if reassembled_data.len() >= 20 { 
                                                           &reassembled_data[..20] 
                                                       } else { 
                                                           &reassembled_data[..] 
                                                       });
                                            }
                                        }
                                    } else {
                                        // Regular UDP packet
                                        // Forward to target UDP
                                        if let Some(ref target_sock) = target_socket {
                                            if let Some(target_addr) = config.target_udp {
                                                if let Err(e) = target_sock.send_to(&reassembled_data, target_addr).await {
                                                    error!("Failed to forward packet to target: {}", e);
                                                } else {
                                                    info!("Forwarded packet to {}", target_addr);
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
