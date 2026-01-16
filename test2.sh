#!/bin/bash
# test_dns_tunnel.sh - Comprehensive test script

set -e

echo "=== DNS Tunnel Test Script ==="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}Cleaning up...${NC}"
    pkill -f "target/release/server" 2>/dev/null || true
    pkill -f "target/release/client" 2>/dev/null || true
    pkill -f "udp_echo.py" 2>/dev/null || true
    sleep 1
}

trap cleanup EXIT

# Check if binaries exist
if [ ! -f "target/release/server" ] || [ ! -f "target/release/client" ]; then
    echo -e "${RED}Error: Binaries not found. Run 'cargo build --release' first.${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Binaries found${NC}"
echo ""

# Create UDP echo server
cat > /tmp/udp_echo.py << 'EOF'
#!/usr/bin/env python3
import socket
import sys

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", 8080))
sock.settimeout(5)
print("UDP Echo Server listening on 127.0.0.1:8080", flush=True)

try:
    while True:
        try:
            data, addr = sock.recvfrom(1024)
            msg = data.decode('utf-8', errors='ignore')
            print(f"[ECHO] Received from {addr}: {msg}", flush=True)
            response = f"Echo: {msg}".encode()
            sock.sendto(response, addr)
            print(f"[ECHO] Sent response to {addr}", flush=True)
        except socket.timeout:
            continue
        except KeyboardInterrupt:
            break
except Exception as e:
    print(f"[ECHO] Error: {e}", flush=True)
finally:
    sock.close()
EOF

chmod +x /tmp/udp_echo.py

# Start echo server
echo -e "${YELLOW}Starting UDP echo server...${NC}"
python3 /tmp/udp_echo.py > /tmp/echo_server.log 2>&1 &
ECHO_PID=$!
sleep 1

# Start server
echo -e "${YELLOW}Starting DNS tunnel server...${NC}"
RUST_LOG=info ./target/release/server \
    --dns-port 5353 \
    --target-udp 127.0.0.1:8080 \
    --client-udp-port 5355 \
    --domains example.com \
    > /tmp/server.log 2>&1 &
SERVER_PID=$!
sleep 2

# Start client
echo -e "${YELLOW}Starting DNS tunnel client...${NC}"
RUST_LOG=info ./target/release/client \
    --local-port 5355 \
    --domains example.com \
    --resolvers 127.0.0.1:5353 \
    > /tmp/client.log 2>&1 &
CLIENT_PID=$!
sleep 2

# Test
echo -e "${GREEN}Testing...${NC}"
echo "Sending test packet: 'Hello, DNS Tunnel!'"
echo "Hello, DNS Tunnel!" | nc -u -w 1 127.0.0.1 5355 || true

sleep 3

# Check results
echo ""
echo -e "${YELLOW}=== Server Log ===${NC}"
tail -20 /tmp/server.log || true

echo ""
echo -e "${YELLOW}=== Client Log ===${NC}"
tail -20 /tmp/client.log || true

echo ""
echo -e "${YELLOW}=== Echo Server Log ===${NC}"
tail -10 /tmp/echo_server.log || true

# Check if echo server received anything
if grep -q "Received" /tmp/echo_server.log; then
    echo -e "${GREEN}✓ Echo server received packet!${NC}"
else
    echo -e "${RED}✗ Echo server did not receive packet${NC}"
fi

echo ""
echo "Test complete. Check logs above for details."
