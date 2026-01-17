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
   - Connection ID assigned
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
  "domains": ["example.com"],
  "resolvers": ["8.8.8.8:53"],
  "max_subdomain_length": 63,
  "rotate_resolvers": true,
  "tcp_connection_timeout": 60
}
```

**Key fields:**
- `tcp_listen`: Address where shadowsocks clients connect (default: 127.0.0.1:1080)
- `tcp_connection_timeout`: Timeout in seconds for idle connections (default: 60)

### Server Configuration (server-config.json)

```json
{
  "dns_bind": "0.0.0.0:53",
  "tcp_target": "127.0.0.1:8388",
  "client_udp_port": 5353,
  "domains": ["example.com"],
  "max_subdomain_length": 63,
  "tcp_connection_timeout": 60
}
```

**Key fields:**
- `tcp_target`: Address of xray core shadowsocks server (default: 127.0.0.1:8388)
- `client_udp_port`: UDP port to send responses to client (default: 5353)

## Usage

### Setup

1. **On Server (VPS):**
   ```bash
   # Configure xray core to listen on 127.0.0.1:8388
   # Run DNS tunnel server
   ./target/release/server --config server-config.json
   ```

2. **On Client (Iran Server):**
   ```bash
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

- Client generates unique connection IDs (u32)
- Server uses client-provided connection IDs
- Connection IDs are embedded in all TCP packets

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

## Troubleshooting

### Connection Not Established

- Check that xray core is running on server
- Verify `tcp_target` configuration
- Check DNS tunnel is working (test UDP first)
- Review logs for SYN/SYN-ACK exchange

### Data Not Flowing

- Verify connection is established (check logs)
- Check sequence numbers in logs
- Ensure fragments are being reassembled
- Verify TCP stream is connected to xray core

### Connection Drops

- Check connection timeout settings
- Verify network stability
- Review connection cleanup in logs
- Check for FIN packets in logs

## Future Improvements

1. **Full TCP State Machine:**
   - Implement proper TCP handshake
   - Add retransmission
   - Handle windowing

2. **Connection Pooling:**
   - Reuse connections when possible
   - Better connection lifecycle management

3. **Keepalive:**
   - Add TCP keepalive mechanism
   - Prevent idle connection timeouts

4. **Error Recovery:**
   - Better error handling
   - Automatic reconnection
   - Connection state recovery

## Notes

- This implementation maintains backward compatibility with UDP-only mode
- TCP and UDP packets can coexist in the same tunnel
- The implementation prioritizes simplicity over full TCP compliance
- For production use, consider adding encryption and authentication layers
