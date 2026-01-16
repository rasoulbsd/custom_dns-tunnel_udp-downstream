# Testing Guide - No Manual Rebuild Needed

## Quick Testing Options

### Option 1: Quick Test Script (Recommended)
```bash
./test_quick.sh
```
- Uses `cargo run` directly - rebuilds automatically if needed
- Fastest way to test changes
- No need to manually run `cargo build --release`

### Option 2: Development Test Script
```bash
./test_dev.sh
```
- More detailed logging
- Saves logs to `/tmp/` for inspection
- Uses `cargo run` - auto-rebuilds

### Option 3: Watch for Changes (Auto-Rebuild)
```bash
# Terminal 1: Watch and rebuild
cargo install cargo-watch  # One-time install
cargo watch -x "build --release --bin server --bin client"

# Terminal 2: Run test
./test_dns_tunnel.sh
```

### Option 4: Direct Cargo Run
```bash
# Terminal 1: Server
RUST_LOG=info cargo run --release --bin server -- server-config.json

# Terminal 2: Client  
RUST_LOG=info cargo run --release --bin client -- client-config.json

# Terminal 3: Send test data
echo -n "Hello!" | nc -u 127.0.0.1 5355
```

## Why Server Isn't Decoding Queries

Looking at your logs, the server receives DNS queries but doesn't decode them. This could be because:

1. **Domain mismatch**: The query subdomain doesn't match `example.com`
2. **Hex decode error**: The subdomain isn't valid hex
3. **Query format issue**: The DNS query structure doesn't match expected format

Check the server logs for:
- `Failed to decode DNS query` warnings
- `DNS query does not match tunnel format` debug messages

## Debugging Tips

1. **Enable debug logging**:
   ```bash
   RUST_LOG=debug cargo run --release --bin server -- server-config.json
   ```

2. **Check what the client is sending**:
   ```bash
   RUST_LOG=debug cargo run --release --bin client -- client-config.json
   ```

3. **Inspect DNS queries**:
   Use `tcpdump` or `wireshark` to see actual DNS packets:
   ```bash
   sudo tcpdump -i lo -n port 5353
   ```

## Current Issue

From your logs:
- ✅ Server receives DNS queries (62 bytes)
- ❌ Server doesn't decode them (no "Decoded DNS query" messages)
- ❌ Client receives 12-byte responses from server but misidentifies them

The 12-byte responses are likely DNS responses (not tunnel UDP packets), which is why the client validation rejects them.
