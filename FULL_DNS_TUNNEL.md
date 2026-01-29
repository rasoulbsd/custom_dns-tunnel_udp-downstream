# Full DNS Tunnel Implementation

## Overview

The DNS tunnel now supports **full bi-directional DNS tunneling** with an adjustable response mode. You can choose between:
- **DNS mode**: Both uplink and downlink use DNS (full DNS tunnel)
- **UDP mode**: Uplink uses DNS, downlink uses direct UDP (hybrid mode, default)

## New Features

### 1. Response Mode Configuration

Both client and server now support a `response_mode` configuration option:

- `"dns"`: Full DNS tunnel - responses are sent as DNS responses
- `"udp"`: Hybrid mode - responses are sent as direct UDP packets (default)

### 2. Minimum Subdomain Length

Added `min_subdomain_length` configuration option for padding/obfuscation:
- Default: `0` (no padding)
- When set, subdomains are padded with zeros to meet the minimum length
- Useful for obfuscation and consistent packet sizes

## Configuration

### Server Config (`server-config.json`)

```json
{
  "dns_bind": "0.0.0.0:53533",
  "target_udp": "127.0.0.1:8080",
  "client_udp_port": 5355,
  "response_mode": "dns",  // or "udp"
  "domains": ["example.com"],
  "max_subdomain_length": 63,
  "min_subdomain_length": 0,
  "randomize_dns_port": false
}
```

### Client Config (`client-config.json`)

```json
{
  "local_udp": "127.0.0.1:5355",
  "response_mode": "dns",  // or "udp"
  "domains": ["example.com"],
  "resolvers": ["127.0.0.1:53533"],
  "max_subdomain_length": 63,
  "min_subdomain_length": 0,
  "rotate_resolvers": true,
  "randomize_local_port": false
}
```

## How It Works

### DNS Mode (Full DNS Tunnel)

1. **Uplink (Client → Server)**:
   - Client receives UDP packet from application
   - Fragments packet and encodes each fragment as DNS query
   - Sends DNS queries to resolvers
   - Server receives DNS queries, decodes, and forwards to target

2. **Downlink (Server → Client)**:
   - Server receives response from target
   - Fragments response and encodes each fragment as DNS response
   - Sends DNS responses back to client's DNS query source
   - Client receives DNS responses, decodes, and forwards to application

### UDP Mode (Hybrid - Default)

1. **Uplink (Client → Server)**:
   - Same as DNS mode (uses DNS queries)

2. **Downlink (Server → Client)**:
   - Server receives response from target
   - Fragments response and encodes as UDP packets
   - Sends UDP packets directly to client's IP address
   - Client receives UDP packets, decodes, and forwards to application

## Code Changes

### `src/config.rs`
- Added `ResponseMode` enum (`Dns` / `Udp`)
- Added `response_mode` field to `ClientConfig` and `ServerConfig`
- Added `min_subdomain_length` field to both configs

### `src/dns_codec.rs`
- Added `new_with_min()` constructor to support minimum subdomain length
- Added `encode_to_dns_response()` method for encoding DNS responses
- Added `decode_from_dns_response()` method for decoding DNS responses
- Updated `encode_to_dns_query()` to support minimum subdomain length padding

### `src/bin/server.rs`
- Updated to check `response_mode` when sending responses
- Sends DNS responses when `response_mode = "dns"`
- Sends UDP packets when `response_mode = "udp"`
- Stores query_id and domain in pending_requests for DNS responses

### `src/bin/client.rs`
- Added task to listen for DNS responses when `response_mode = "dns"`
- Decodes DNS responses and handles them similar to UDP responses
- Uses `new_with_min()` for codec initialization

## Usage Examples

### Full DNS Tunnel (Both Directions)

**Server:**
```json
{
  "response_mode": "dns"
}
```

**Client:**
```json
{
  "response_mode": "dns"
}
```

### Hybrid Mode (DNS Uplink, UDP Downlink)

**Server:**
```json
{
  "response_mode": "udp"
}
```

**Client:**
```json
{
  "response_mode": "udp"
}
```

### With Minimum Subdomain Length

For obfuscation or consistent packet sizes:

```json
{
  "max_subdomain_length": 63,
  "min_subdomain_length": 40
}
```

This ensures all subdomains are at least 40 characters (padded with zeros if needed).

## Benefits

1. **Full DNS Tunnel**: Complete DNS-based communication when needed
2. **Flexibility**: Choose the best mode for your use case
3. **Backward Compatible**: Default is UDP mode (existing behavior)
4. **Obfuscation**: Minimum subdomain length for padding/obfuscation
5. **Configurable**: All options can be set via config files

## Notes

- Both client and server must use the same `response_mode` for proper communication
- DNS mode has higher latency but better obfuscation
- UDP mode has lower latency but requires direct UDP connectivity
- Minimum subdomain length padding uses hex '0' characters (even length guaranteed)
