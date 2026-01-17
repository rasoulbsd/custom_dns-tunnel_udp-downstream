# Bi-directional Tunnel Fix

## Issues Fixed

### Problem
The server was using FIFO (First-In-First-Out) matching to correlate responses from `target_udp` back to the original `packet_id`. This approach:
- Assumed responses come back in order (not guaranteed with UDP)
- Failed with concurrent requests
- Could not match responses correctly when multiple requests were in flight

### Solution
Implemented **hash-based matching**:
1. When forwarding a packet to `target_udp`, compute a hash of the data and store: `data_hash -> (packet_id, client_udp_addr, timestamp)`
2. When receiving a response from `target_udp`, compute the hash of the received data and look up the corresponding `packet_id`
3. Use the stored `packet_id` and `client_udp_addr` to send the response back to the client

### Changes Made

**File: `src/bin/server.rs`**

1. **Added imports**:
   - `std::hash::{Hash, Hasher}`
   - `std::collections::hash_map::DefaultHasher`
   - `tokio::time::Instant`

2. **Replaced FIFO matching with hash-based matching**:
   - Removed: `packet_to_client_udp` HashMap (packet_id -> client_udp_addr)
   - Added: `data_hash_to_packet` HashMap (data_hash -> (packet_id, client_udp_addr, timestamp))
   - Added timeout-based cleanup for old entries (30 seconds)

3. **Updated response matching logic**:
   - When forwarding to `target_udp`: Compute hash and store mapping
   - When receiving from `target_udp`: Compute hash and look up `packet_id`

## How It Works

### Request Flow
1. Client sends UDP packet → Client encodes as DNS queries → Server
2. Server decodes DNS queries → Reassembles packet
3. Server computes hash of packet data
4. Server stores: `hash -> (packet_id, client_udp_addr, timestamp)`
5. Server forwards packet to `target_udp`

### Response Flow
1. Echo server receives packet → Echoes it back
2. Server receives response from `target_udp`
3. Server computes hash of response data
4. Server looks up hash in `data_hash_to_packet` map
5. Server finds `packet_id` and `client_udp_addr`
6. Server fragments response and encodes with original `packet_id`
7. Server sends UDP packets to `client_udp_addr`
8. Client receives UDP packets → Reassembles → Forwards to original source

## Testing

Use the provided test scripts:

```bash
# Start echo server
python3 test_echo_server.py 127.0.0.1 8080

# In separate terminals, start server and client
# Terminal 1: Server
cargo run --bin dns-tunnel-server -- --config server-config.json

# Terminal 2: Client  
cargo run --bin dns-tunnel-client -- --config client-config.json

# Terminal 3: Run test
./test_bidirectional.sh
# or
python3 test_bidirectional_python.py
```

## Benefits

- ✅ Works with concurrent requests
- ✅ Doesn't assume response order
- ✅ Handles multiple in-flight requests correctly
- ✅ Automatic cleanup of stale entries (30s timeout)
- ✅ Robust matching using data hash

## Limitations

- Hash collisions are theoretically possible but extremely unlikely (u64 hash space)
- Requires echo server to return exact same data (standard echo behavior)
- 30-second timeout for response matching (configurable)
