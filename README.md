# DNS Tunnel

A hybrid DNS/UDP tunneling implementation in Rust that allows UDP traffic to be sent via DNS queries (uplink) and received via direct UDP (downlink), enabling communication through DNS servers.

## Features

- **DNS Encapsulation (Uplink)**: Encapsulates UDP packets as DNS queries (any record type: TXT, NS, etc.)
- **Direct UDP (Downlink)**: Server sends responses directly via UDP (not DNS)
- **Case Insensitive Encoding**: Uses hex encoding which is case insensitive
- **Packet Fragmentation**: Automatically fragments large packets to fit within DNS subdomain length limits
- **Packet Reassembly**: Reassembles fragmented packets on both client and server
- **Multiple Domains**: Supports listening for multiple domains
- **Resolver Rotation**: Option to rotate between multiple DNS resolvers
- **Randomized Ports**: Optional random port assignment for both client and server
- **Configurable Subdomain Length**: Adjustable maximum subdomain length (default: 64, max: 100)

## Architecture

### Client (Iran side)
1. Receives UDP packets from local applications
2. Fragments packets if necessary
3. Encapsulates each fragment as a DNS query (hex encoded in subdomain)
4. Sends DNS queries to multiple DNS resolvers (spam)
5. Receives UDP responses directly from server (not DNS)
6. Decodes and reassembles packets
7. Forwards reassembled packets to original source

### Server (VPS side - DE/NL)
1. Listens for DNS queries on specified domains
2. Decodes DNS queries to extract UDP packet fragments (hex decoded from subdomain)
3. Reassembles fragments into complete packets
4. Forwards packets to target UDP address (internet)
5. Receives responses from target
6. Encapsulates responses as UDP packets (not DNS)
7. Sends UDP packets directly back to client

## Installation

### Option 1: Docker (Recommended for Production)

See [DOCKER_GUIDE.md](./DOCKER_GUIDE.md) for Docker deployment instructions.

**VPS Dependencies:**
- Docker Engine
- Docker Compose
- Git
- UFW (firewall)

See [VPS_SETUP.md](./VPS_SETUP.md) for complete VPS setup instructions.

### Option 2: Native Build

```bash
# Clone the repository
git clone <repository-url>
cd dns-tunnel

# Install Rust (if not already installed)
curl https://sh.rustup.rs -sSf | sh

# Build the project
cargo build --release

# The binaries will be in target/release/
# - client: DNS tunnel client
# - server: DNS tunnel server
```

## Configuration

### Client Configuration

Create a `client-config.json` file:

```json
{
  "local_udp": "127.0.0.1:5353",
  "domains": [
    "example.com",
    "tunnel.example.com"
  ],
  "resolvers": [
    "8.8.8.8:53",
    "1.1.1.1:53",
    "9.9.9.9:53"
  ],
  "max_subdomain_length": 64,
  "rotate_resolvers": true,
  "randomize_local_port": false
}
```

### Server Configuration

Create a `server-config.json` file:

```json
{
  "dns_bind": "0.0.0.0:53",
  "target_udp": "127.0.0.1:8080",
  "domains": [
    "example.com",
    "tunnel.example.com"
  ],
  "max_subdomain_length": 64,
  "randomize_dns_port": false
}
```

## Usage

### Running the Client

```bash
# Using configuration file
./target/release/client --config client-config.json

# Using command-line arguments
./target/release/client \
  --local-addr 127.0.0.1 \
  --local-port 5353 \
  --domains example.com tunnel.example.com \
  --resolvers 8.8.8.8:53 1.1.1.1:53 \
  --max-subdomain-length 64

# With randomized local port
./target/release/client --config client-config.json --randomize-local-port
```

### Running the Server

```bash
# Using configuration file
./target/release/server --config server-config.json

# Using command-line arguments
./target/release/server \
  --dns-bind-addr 0.0.0.0 \
  --dns-port 53 \
  --target-udp 127.0.0.1:8080 \
  --domains example.com tunnel.example.com \
  --max-subdomain-length 64

# With randomized DNS port
./target/release/server --config server-config.json --randomize-dns-port
```

## Command-Line Options

### Client Options

- `--config, -c`: Path to configuration file (JSON)
- `--local-addr, -a`: Local UDP bind address (default: 127.0.0.1)
- `--local-port, -p`: Local UDP port
- `--domains, -d`: List of domains to use (can be specified multiple times)
- `--resolvers, -r`: List of DNS resolver addresses (can be specified multiple times)
- `--max-subdomain-length`: Maximum subdomain length (default: 64, max: 100)
- `--no-rotate-resolvers`: Disable resolver rotation
- `--randomize-local-port`: Randomize local UDP port

### Server Options

- `--config, -c`: Path to configuration file (JSON)
- `--dns-bind-addr, -a`: DNS server bind address (default: 0.0.0.0)
- `--dns-port, -p`: DNS server port
- `--target-udp, -t`: Target UDP address to forward packets to
- `--domains, -d`: List of domains to listen for (can be specified multiple times)
- `--max-subdomain-length`: Maximum subdomain length (default: 64, max: 100)
- `--randomize-dns-port`: Randomize DNS server port

## How It Works

1. **Packet Encoding (Uplink)**: UDP packets are encoded with metadata (packet ID, fragment ID, total fragments) and then hex encoded (case insensitive)
2. **DNS Query Creation**: The hex-encoded data is used as a subdomain in DNS queries (e.g., `<hex-encoded-data>.example.com`)
3. **Subdomain Length Limit**: The subdomain is truncated to the maximum length (64 or 100 characters) to ensure DNS compatibility
4. **Fragmentation**: Large packets are automatically fragmented to fit within the subdomain length limit
5. **Multiple Resolvers**: The client sends queries to multiple DNS resolvers simultaneously for redundancy
6. **Response Handling (Downlink)**: Server sends responses directly as UDP packets (not DNS), which are decoded and reassembled

## Security Considerations

- This tool is for educational and legitimate use cases only
- DNS tunneling can be detected by network monitoring
- Use appropriate domains that you own or have permission to use
- Consider rate limiting to avoid overwhelming DNS servers
- The implementation does not include encryption - add encryption if needed for sensitive data

## Limitations

- Maximum packet size is limited by DNS subdomain length constraints
- Packet fragmentation adds overhead
- DNS responses may be cached by intermediate DNS servers
- Some DNS servers may rate-limit or block excessive queries

## License

[Specify your license here]

## Contributing

[Contributing guidelines]
