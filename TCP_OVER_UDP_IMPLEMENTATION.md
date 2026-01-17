# TCP-over-UDP Implementation for DNS Tunnel

## Overview

This implementation extends the DNS tunnel to support TCP connections over the existing UDP-based DNS tunnel infrastructure. This enables VPN functionality where shadowsocks (TCP) clients can connect through the tunnel.

## Architecture

### Flow Diagram

```
User Device
    │
    │ TCP (shadowsocks)
    ▼
Client (Iran Server)
    │
    │ TCP → UDP conversion
    │ TCP packets wrapped with connection metadata
    │ Fragmented and sent via DNS queries
    ▼
DNS Tunnel (UDP-based)
    │
    │ DNS queries (uplink)
    │ UDP responses (downlink)
    ▼
Server (VPS)
    │
    │ UDP → TCP conversion
    │ Reassemble TCP packets
    │ Forward to xray core (shadowsocks server)
    ▼
xray core (127.0.0.1:8388)
    │
    │ Internet
    ▼
```

### Reverse Flow (Response)

```
xray core
    │
    │ TCP response
    ▼
Server
    │
    │ TCP → UDP conversion
    │ Send via UDP (downlink)
    ▼
Client
    │
    │ UDP → TCP conversion
    │ Forward to shadowsocks client
    ▼
User Device
```

## Implementation Details

### TCP Packet Format

TCP packets are serialized with the following format:
```
[4 bytes: connection_id]
[4 bytes: sequence]
[2 bytes: data_length]
[1 byte: flags]
[N bytes: data]
```

**Flags:**
- `SYN = 1` - Connection establishment
- `ACK = 2` - Acknowledgment
- `FIN = 4` - Connection termination
- `DATA = 8` - Data packet
- `RST = 16` - Reset connection

### Connection Lifecycle

1. **Client Side:**
   - TCP connection accepted from shadowsocks client
   - Connection ID assigned (unique per connection)
   - SYN packet sent via DNS tunnel
   - Wait for SYN-ACK
   - Send ACK, connection established
   - Data packets sent/received
   - FIN sent on close

2. **Server Side:**
   - Receive SYN via DNS tunnel
   - Connect to xray core (TCP target)
   - Send SYN-ACK back
   - Connection established
   - Forward data packets
   - Handle FIN and cleanup

### Key Components

1. **tcp_proxy.rs**: TCP connection management and packet serialization
2. **Client modifications**: TCP listener, connection handling, TCP→UDP conversion
3. **Server modifications**: TCP packet detection, UDP→TCP conversion, forwarding to xray core

## Configuration

### Client Configuration (client-config.json)

```json
{
  "local_udp": "127.0.0.1:5353",
  "tcp_listen": "127.0.0.1:1080",
  "domains": ["example.com", "tunnel.example.com"],
  "resolvers": ["8.8.8.8:53"],
  "max_subdomain_length": 63,
  "rotate_resolvers": true,
  "tcp_connection_timeout": 60
}
```

**Key fields:**
- `tcp_listen`: Address where shadowsocks clients connect (default: 127.0.0.1:1080)
- `tcp_connection_timeout`: Timeout in seconds for idle connections (default: 60)
- `domains`: List of domains to use (supports multiple domains like `tunnel.example.com`)

### Server Configuration (server-config.json)

```json
{
  "dns_bind": "0.0.0.0:5353",
  "tcp_target": "49.13.223.25:32675",
  "client_udp_port": 5355,
  "domains": ["example.com", "tunnel.example.com"],
  "max_subdomain_length": 63,
  "tcp_connection_timeout": 60
}
```

**Key fields:**
- `tcp_target`: Address of xray core shadowsocks server (e.g., "49.13.223.25:32675")
- `client_udp_port`: UDP port to send responses to client (default: 5355)
- `domains`: Must match client domains (supports multiple domains)

## Critical Implementation Details

### Packet ID Management

**IMPORTANT:** TCP packets must use unique packet IDs across all connections. The implementation uses a shared `Arc<Mutex<u16>>` counter that:
- Starts at 1 (skips 0 to avoid conflicts)
- Is shared across all TCP connections
- Wraps around but skips 0 when wrapping

**Why this matters:**
- Packet ID collisions cause reassembly failures
- All fragments of a packet must have the same packet_id
- Different TCP packets must have different packet_ids

### Client-Side Packet Handling

The client distinguishes between:
1. **Tunnel packets (from server)**: Checked against `pending_requests` (UDP) and `pending_tcp_requests` (TCP)
2. **Local UDP packets**: From applications, sent via DNS tunnel

**Key logic:**
```rust
// Check if packet_id exists in either pending list
let is_tunnel_packet = has_pending_udp || has_pending_tcp;

if is_tunnel_packet {
    // Process as server response - DON'T resend via DNS tunnel
    // Remove from appropriate pending list
    // Forward to TCP stream or original UDP source
} else {
    // Treat as local UDP packet - send via DNS tunnel
}
```

### Server-Side TCP Connection Handling

TCP connections are spawned in separate tasks to avoid blocking the main DNS query processing loop:

```rust
// Spawn TCP connection attempt in separate task
tokio::spawn(async move {
    match TcpStream::connect(tcp_target).await {
        Ok(stream) => {
            // Handle connection
            // Spawn another task for reading responses
        }
        Err(e) => {
            // Send RST to client
        }
    }
});
```

**Why this matters:**
- Prevents server from blocking on TCP connection attempts
- Allows server to continue processing DNS queries
- Handles connection failures gracefully

### Domain Extraction Fix

When using multiple domains (e.g., `tunnel.example.com` and `example.com`), the codec must match the **longest domain first** to avoid partial matches:

```rust
// Match longest domain first
let domain = expected_domains.iter()
    .filter(|d| query_name.ends_with(&format!(".{}", d)) || query_name == d.as_str())
    .max_by_key(|d| d.len())
    .ok_or_else(|| anyhow!("Domain not found"))?;
```

**Why this matters:**
- Prevents matching `example.com` when query is for `tunnel.example.com`
- Ensures correct subdomain extraction
- Avoids hex decode errors

### Pending Request Cleanup

**Client:**
- Remove from `pending_tcp_requests` or `pending_requests` after reassembly
- Based on packet type (TCP vs UDP)
- Prevents memory leaks and false positives

**Server:**
- Remove from `pending_requests` after reassembly
- Prevents memory buildup
- Allows proper cleanup

## Usage

### Setup

1. **On Server (VPS):**
   ```bash
   # Configure xray core to listen on the target address
   # Update server-config.json with correct tcp_target
   # Run DNS tunnel server
   ./target/release/server --config server-config.json
   ```

2. **On Client (Iran Server):**
   ```bash
   # Update client-config.json with correct domains and resolvers
   # Run DNS tunnel client
   ./target/release/client --config client-config.json
   ```

3. **On User Device:**
   ```bash
   # Configure shadowsocks client to connect to Iran server:1080
   # The connection will be tunneled through DNS
   ```

### Testing

1. **Test TCP connection:**
   ```bash
   # On user device
   nc -v iran-server-ip 1080
   ```

2. **Test with shadowsocks:**
   ```bash
   # Configure shadowsocks client
   # Server: iran-server-ip
   # Port: 1080
   # Method: (your shadowsocks method)
   ```

## Protocol Details

### Connection ID Management

- Client generates unique connection IDs (u32) per TCP connection
- Server uses client-provided connection IDs
- Connection IDs are embedded in all TCP packets
- Each connection ID maps to one TCP stream

### Sequence Numbers

- Used for ordering (not full TCP state machine)
- Client maintains `next_sequence` for outgoing packets
- Server maintains `expected_sequence` for incoming packets
- Sequence numbers increment by data length

### Fragmentation

- TCP packets are fragmented using the same mechanism as UDP packets
- Fragments are sent via DNS queries (uplink)
- Reassembled on server side
- Responses are fragmented and sent via UDP (downlink)
- Each fragment has: `[packet_id (2)][fragment_id (1)][total_fragments (1)][data]`

## Known Issues and Solutions

### Issue 1: Packet ID Collisions

**Problem:** All TCP packets using `packet_id=0` caused reassembly conflicts.

**Solution:** Use shared packet ID counter starting at 1, skip 0:
```rust
let tcp_packet_id_counter: Arc<Mutex<u16>> = Arc::new(Mutex::new(1u16));
```

### Issue 2: Client Treating Server Responses as Local UDP

**Problem:** Server responses on UDP port were being treated as local UDP packets and re-sent via DNS tunnel.

**Solution:** Check both `pending_requests` and `pending_tcp_requests` to identify tunnel packets:
```rust
let is_tunnel_packet = has_pending_udp || has_pending_tcp;
```

### Issue 3: Server Stopping After Few Packets

**Problem:** Server main loop blocking on TCP connection attempts.

**Solution:** Spawn TCP connections in separate tasks:
```rust
tokio::spawn(async move {
    // TCP connection handling
});
```

### Issue 4: Domain Extraction Errors

**Problem:** Queries for `tunnel.example.com` were matching `example.com` first, causing hex decode errors.

**Solution:** Match longest domain first:
```rust
.max_by_key(|d| d.len())
```

### Issue 5: Incomplete Reassembly

**Problem:** Large TCP packets (738 bytes instead of 846 bytes) due to packet ID collisions.

**Solution:** Fixed packet ID management + proper pending request cleanup.

## Limitations

1. **Simplified TCP State Machine:**
   - Not a full TCP implementation
   - Relies on shadowsocks layer for reliability
   - No retransmission (packet loss handled by shadowsocks)

2. **Connection Timeout:**
   - Idle connections timeout after 60 seconds (configurable)
   - No keepalive mechanism

3. **Single Connection per ID:**
   - Each connection ID represents one TCP connection
   - Connection IDs wrap around (u32)

4. **No Flow Control:**
   - No windowing
   - No backpressure mechanism
   - Relies on TCP layer for flow control

## Troubleshooting

### Connection Not Established

- Check that xray core is running on server
- Verify `tcp_target` configuration
- Check DNS tunnel is working (test UDP first)
- Review logs for SYN/SYN-ACK exchange
- Look for "Successfully connected to TCP target" logs

### Data Not Flowing

- Verify connection is established (check logs)
- Check sequence numbers in logs
- Ensure fragments are being reassembled
- Verify TCP stream is connected to xray core
- Check for "Received TCP data packet" and "Wrote X bytes to TCP stream" logs

### Connection Drops

- Check connection timeout settings
- Verify network stability
- Review connection cleanup in logs
- Check for FIN packets in logs

### Server Stops Processing

- Check for panics in logs
- Verify TCP connection attempts are spawned (not blocking)
- Check for errors in DNS query processing
- Ensure main loop continues after errors

### Client Re-sending Server Responses

- Verify `pending_tcp_requests` is being checked
- Check that packets are removed from pending after processing
- Ensure tunnel packet detection logic is correct

### Incomplete Reassembly

- Check for packet ID collisions (all packets should have unique IDs)
- Verify all fragments are received (check fragment counts in logs)
- Check domain extraction is working correctly
- Verify no fragments are being lost

## Debugging Tips

### Enable Debug Logging

```bash
RUST_LOG=debug ./target/release/client --config client-config.json
RUST_LOG=debug ./target/release/server --config server-config.json
```

### Key Log Messages to Watch

**Client:**
- "New TCP connection from: ..." - Connection accepted
- "TCP connection X established" - Connection ready
- "Received tunnel UDP packet: ..." - Server response received
- "Received TCP packet: connection_id=..." - TCP packet from server
- "Wrote X bytes to TCP stream" - Data forwarded to user

**Server:**
- "Received DNS query from ..." - Query received
- "Reassembled packet X (Y bytes)" - Packet reassembled
- "Detected TCP packet" - TCP packet identified
- "Establishing TCP connection X to ..." - Connection attempt
- "Successfully connected to TCP target" - Connection established
- "Received TCP data packet: ..." - Data received
- "Wrote X bytes to TCP stream" - Data forwarded to xray

### Common Error Messages

- "Packet data incomplete" - Reassembly failed, check packet IDs
- "Failed to extract TCP packet" - Deserialization error, check packet format
- "No TCP stream found for connection" - Connection not established or closed
- "TCP packet_id X not found in pending_tcp_requests" - Packet ID mismatch

## Future Improvements

1. **Full TCP State Machine:**
   - Implement proper TCP handshake
   - Add retransmission
   - Handle windowing
   - Implement congestion control

2. **Connection Pooling:**
   - Reuse connections when possible
   - Better connection lifecycle management
   - Connection health checks

3. **Keepalive:**
   - Add TCP keepalive mechanism
   - Prevent idle connection timeouts
   - Heartbeat packets

4. **Error Recovery:**
   - Better error handling
   - Automatic reconnection
   - Connection state recovery
   - Packet retransmission

5. **Performance:**
   - Batch processing
   - Connection multiplexing
   - Better fragmentation strategy
   - Compression

6. **Monitoring:**
   - Connection statistics
   - Packet loss tracking
   - Latency metrics
   - Throughput monitoring

## Code Structure

### Client (`src/bin/client.rs`)

- TCP listener on `tcp_listen` port
- TCP connection handler per connection
- Shared packet ID counter for TCP packets
- Tunnel packet detection (UDP + TCP)
- TCP response handling

### Server (`src/bin/server.rs`)

- DNS query receiver
- TCP packet detection after reassembly
- TCP connection spawning (non-blocking)
- TCP response handler (reads from xray, sends via UDP)

### TCP Proxy (`src/tcp_proxy.rs`)

- TCP packet serialization/deserialization
- Connection state management
- Connection lifecycle handling
- Packet type creation (SYN, ACK, FIN, DATA, RST)

### DNS Codec (`src/dns_codec.rs`)

- Domain matching (longest first)
- Subdomain extraction
- Hex encoding/decoding
- Packet fragmentation

## Notes

- This implementation maintains backward compatibility with UDP-only mode
- TCP and UDP packets can coexist in the same tunnel
- The implementation prioritizes simplicity over full TCP compliance
- For production use, consider adding encryption and authentication layers
- Packet IDs are critical - ensure uniqueness across all connections
- Domain matching must use longest-first to avoid partial matches
- Server must spawn TCP connections to avoid blocking main loop
- Client must distinguish tunnel packets from local UDP packets

## Testing Checklist

- [ ] TCP connection establishment (SYN/SYN-ACK/ACK)
- [ ] Data transfer (uplink and downlink)
- [ ] Connection teardown (FIN)
- [ ] Multiple concurrent connections
- [ ] Large data transfers
- [ ] Packet fragmentation
- [ ] Domain matching with multiple domains
- [ ] Server response handling
- [ ] Error recovery
- [ ] Connection timeout
- [ ] Packet ID uniqueness
- [ ] No packet re-sending
