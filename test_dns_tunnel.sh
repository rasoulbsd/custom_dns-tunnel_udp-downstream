#!/bin/bash
# Comprehensive DNS Tunnel Test Script

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
    echo -e "\n${YELLOW}Cleaning up processes...${NC}"
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
sock.settimeout(10)
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

# Clean up old log files
rm -f /tmp/echo_server.log /tmp/server.log /tmp/client.log

# Start echo server
echo -e "${YELLOW}Starting UDP echo server on 127.0.0.1:8080...${NC}"
python3 /tmp/udp_echo.py > /tmp/echo_server.log 2>&1 &
ECHO_PID=$!
sleep 1

# Start server
echo -e "${YELLOW}Starting DNS tunnel server on port 5353...${NC}"
RUST_LOG=debug ./target/release/server \
    --dns-port 5353 \
    --target-udp 127.0.0.1:8080 \
    --client-udp-port 5355 \
    --domains example.com \
    > /tmp/server.log 2>&1 &
SERVER_PID=$!
sleep 2

# Verify server started
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo -e "${RED}Server failed to start!${NC}"
    cat /tmp/server.log
    exit 1
fi

# Start client
echo -e "${YELLOW}Starting DNS tunnel client on port 5355...${NC}"
RUST_LOG=debug ./target/release/client \
    --local-port 5355 \
    --domains example.com \
    --resolvers 127.0.0.1:5353 \
    > /tmp/client.log 2>&1 &
CLIENT_PID=$!
sleep 2

# Verify client started
if ! kill -0 $CLIENT_PID 2>/dev/null; then
    echo -e "${RED}Client failed to start!${NC}"
    cat /tmp/client.log
    exit 1
fi

echo -e "${GREEN}All services started${NC}"
echo ""

# Test
echo -e "${YELLOW}Testing: Sending 'Hello, DNS Tunnel!' to client...${NC}"
echo "Hello, DNS Tunnel!" | timeout 2 nc -u -w 1 127.0.0.1 5355 2>/dev/null || true

sleep 3

# Send another test
echo -e "${YELLOW}Testing: Sending 'Test packet 2'...${NC}"
echo "Test packet 2" | timeout 2 nc -u -w 1 127.0.0.1 5355 2>/dev/null || true

sleep 3

# Check results
echo ""
echo -e "${YELLOW}=== Server Log (last 30 lines) ===${NC}"
tail -30 /tmp/server.log || true

echo ""
echo -e "${YELLOW}=== Client Log (last 30 lines) ===${NC}"
tail -30 /tmp/client.log || true

echo ""
echo -e "${YELLOW}=== Echo Server Log ===${NC}"
tail -10 /tmp/echo_server.log || true

# Check if echo server received anything
if grep -q "Received" /tmp/echo_server.log; then
    echo ""
    echo -e "${GREEN}✓ SUCCESS: Echo server received packet(s)!${NC}"
    RECEIVED_COUNT=$(grep -c "Received" /tmp/echo_server.log || echo "0")
    echo -e "${GREEN}  Total packets received: $RECEIVED_COUNT${NC}"
else
    echo ""
    echo -e "${RED}✗ FAILED: Echo server did not receive any packets${NC}"
    echo -e "${YELLOW}Debugging info:${NC}"
    echo "  Server PID: $SERVER_PID"
    echo "  Client PID: $CLIENT_PID"
    echo "  Echo PID: $ECHO_PID"
    echo ""
    echo "Check logs above for errors"
fi

echo ""
echo "Test complete."
