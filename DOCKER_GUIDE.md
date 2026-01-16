# Docker Deployment Guide

## Quick Start

### Local Testing (Single Machine)

1. **Build and run all services:**
```bash
docker-compose -f docker-compose.test.yml up --build
```

2. **Test the tunnel:**
```bash
# In another terminal
echo -n "Hello, DNS Tunnel!" | nc -u 127.0.0.1 5355
```

3. **View logs:**
```bash
docker-compose -f docker-compose.test.yml logs -f
```

4. **Stop services:**
```bash
docker-compose -f docker-compose.test.yml down
```

### Production Deployment (Two Servers)

#### On VPS (Server)

1. **Copy files to server:**
```bash
scp -r dns-tunnel user@vps-ip:/opt/
```

2. **On server, create production config:**
```bash
cd /opt/dns-tunnel
# Edit server-config-prod.json with your settings
```

3. **Build and run server:**
```bash
docker-compose -f docker-compose.prod.yml up -d server --build
```

4. **Check logs:**
```bash
docker-compose -f docker-compose.prod.yml logs -f server
```

#### On Client (Iran)

1. **Copy files to client:**
```bash
scp -r dns-tunnel user@client-ip:/opt/
```

2. **On client, create production config:**
```bash
cd /opt/dns-tunnel
# Edit client-config-prod.json with your settings
```

3. **Build and run client:**
```bash
docker-compose -f docker-compose.prod.yml up -d client --build
```

4. **Check logs:**
```bash
docker-compose -f docker-compose.prod.yml logs -f client
```

## Docker Compose Files

### `docker-compose.yml`
- Basic setup for both client and server
- Uses host networking
- Good for local development

### `docker-compose.test.yml`
- Includes echo server for testing
- All services on one machine
- Perfect for local testing

### `docker-compose.prod.yml`
- Production setup
- Can be used on separate servers
- No echo server (use your own target)

## Configuration

### Server Config (`server-config-prod.json`)
```json
{
  "dns_bind": "0.0.0.0:53",
  "target_udp": null,
  "client_udp_port": 5355,
  "domains": ["yourdomain.com"],
  "max_subdomain_length": 64,
  "randomize_dns_port": false
}
```

### Client Config (`client-config-prod.json`)
```json
{
  "local_udp": "127.0.0.1:5355",
  "domains": ["yourdomain.com"],
  "resolvers": ["8.8.8.8:53", "1.1.1.1:53"],
  "max_subdomain_length": 64,
  "rotate_resolvers": true,
  "randomize_local_port": false
}
```

## Networking

### Host Network Mode
Both compose files use `network_mode: host` because:
- Server needs to bind to port 53 (DNS)
- Client needs to send DNS queries and receive UDP
- Direct UDP communication between client and server

### Alternative: Bridge Network
If you need bridge networking, modify the compose files:
```yaml
networks:
  - tunnel-network
ports:
  - "53:53/udp"
  - "5355:5355/udp"
cap_add:
  - NET_ADMIN
  - NET_RAW
```

## Privileges

### Server (Port 53)
The server needs elevated privileges for port 53:
- Option 1: `privileged: true` (simpler, less secure)
- Option 2: Specific capabilities (more secure):
  ```yaml
  cap_add:
    - NET_ADMIN
    - NET_RAW
    - NET_BIND_SERVICE
  user: "0:0"  # root
  ```

### Client
Client doesn't need special privileges (uses port 5355).

## Building Images

### Build individually:
```bash
docker build -f Dockerfile.server -t dns-tunnel:server .
docker build -f Dockerfile.client -t dns-tunnel:client .
```

### Build with compose:
```bash
docker-compose build
# or
docker-compose -f docker-compose.test.yml build
```

## Logs

### View all logs:
```bash
docker-compose logs -f
```

### View specific service:
```bash
docker-compose logs -f server
docker-compose logs -f client
```

### Logs are also saved to:
- `./logs/server/` (if volume mounted)
- `./logs/client/` (if volume mounted)

## Troubleshooting

### Port 53 Permission Denied
```bash
# Check if port is in use
sudo netstat -tulpn | grep :53

# Server needs root or capabilities
# Use privileged: true or cap_add in compose file
```

### DNS Queries Not Received
```bash
# Check server logs
docker-compose logs server | grep "Received DNS query"

# Test DNS from outside
dig @<server-ip> test.yourdomain.com TXT
```

### Client Can't Send DNS Queries
```bash
# Check client logs
docker-compose logs client | grep "Failed to send"

# Test DNS resolver connectivity
docker exec dns-tunnel-client dig @8.8.8.8 google.com
```

### Container Won't Start
```bash
# Check container status
docker ps -a

# Check logs
docker logs dns-tunnel-server
docker logs dns-tunnel-client

# Verify config files exist
ls -la *-config*.json
```

## Performance Testing in Docker

### Run performance test:
```bash
# On client machine
docker exec dns-tunnel-client sh -c "echo -n 'test' | nc -u 127.0.0.1 5355"
```

### Monitor resource usage:
```bash
docker stats dns-tunnel-server dns-tunnel-client
```

## Updating

### Rebuild and restart:
```bash
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

### Update config without rebuild:
```bash
# Edit config file
vim server-config-prod.json

# Restart service
docker-compose restart server
```

## Security Notes

1. **Don't use `privileged: true` in production** - use specific capabilities instead
2. **Mount configs as read-only** (`:ro` flag)
3. **Use non-root user** when possible (client can, server needs root for port 53)
4. **Limit network exposure** - only expose necessary ports
5. **Use secrets management** for sensitive configs (not implemented here)

## Systemd Integration

You can also run docker-compose via systemd:

```ini
[Unit]
Description=DNS Tunnel Server
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/dns-tunnel
ExecStart=/usr/bin/docker-compose -f docker-compose.prod.yml up -d server
ExecStop=/usr/bin/docker-compose -f docker-compose.prod.yml stop server

[Install]
WantedBy=multi-user.target
```
