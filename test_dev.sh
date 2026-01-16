#!/bin/bash
# Development test script - uses cargo run directly (no need to rebuild manually)

set -e

echo "=== DNS Tunnel Development Test ==="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}Cleaning up processes...${NC}"
    pkill -f "cargo run.*server" 2>/dev/null || true
    pkill -f "cargo run.*client" 2>/dev/null || true
    pkill -f "target/release/server" 2>/dev/null || true
    pkill -f "target/release/client" 2>/dev/null || true
    pkill -f "udp_echo.py" 2>/dev/null || true
    pkill -f "python3.*echo" 2>/dev/null || true
    fuser -k 8080/udp 2>/dev/null || true
    fuser -k 5353/udp 2>/dev/null || true
    fuser -k 5355/udp 2>/dev/null || true
    sleep 1
}

trap cleanup EXIT

# Kill any existing processes
echo -e "${YELLOW}Cleaning up any existing processes...${NC}"
pkill -f "cargo run.*server" 2>/dev/null || true
pkill -f "cargo run.*client" 2>/dev/null || true
pkill -f "target/release/server" 2>/dev/null || true
pkill -f "target/release/client" 2>/dev/null || true
fuser -k 8080/udp 2>/dev/null || true
fuser -k 5353/udp 2>/dev/null || true
fuser -k 5355/udp 2>/dev/null || true
sleep 1

# Check if cargo is available
if ! command -v cargo &> /dev/null; then
    echo -e "${RED}Error: cargo not found. Please install Rust toolchain.${NC}"
    exit 1
fi

# Start UDP echo server
echo -e "${YELLOW}Starting UDP echo server on 127.0.0.1:8080...${NC}"
python3 -c "
import socket
import sys
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('127.0.0.1', 8080))
print('UDP Echo Server listening on 127.0.0.1:8080', flush=True)
while True:
    data, addr = sock.recvfrom(1024)
    print(f'Received: {data.decode()} from {addr}', flush=True)
    sock.sendto(data, addr)
" > /tmp/echo_server.log 2>&1 &
ECHO_PID=$!

sleep 1

# Build binaries first to avoid lock conflicts
echo -e "${YELLOW}Building binaries...${NC}"
cargo build --release --bin server --bin client > /tmp/build.log 2>&1 || {
    echo -e "${RED}Build failed. Check /tmp/build.log${NC}"
    exit 1
}

# Start DNS tunnel server
echo -e "${YELLOW}Starting DNS tunnel server...${NC}"
RUST_LOG=info ./target/release/server --config server-config.json > /tmp/server.log 2>&1 &
SERVER_PID=$!

sleep 2

# Check if server started
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo -e "${RED}Server failed to start. Check /tmp/server.log${NC}"
    tail -20 /tmp/server.log
    exit 1
fi

# Start DNS tunnel client
echo -e "${YELLOW}Starting DNS tunnel client...${NC}"
RUST_LOG=info ./target/release/client --config client-config.json > /tmp/client.log 2>&1 &
CLIENT_PID=$!

sleep 2

# Check if client started
if ! kill -0 $CLIENT_PID 2>/dev/null; then
    echo -e "${RED}Client failed to start. Check /tmp/client.log${NC}"
    tail -20 /tmp/client.log
    exit 1
fi

echo -e "${GREEN}All services started${NC}"
echo ""

# Test: Send data to client
echo -e "${YELLOW}Testing: Sending 'Hello, DNS Tunnel!' to client...${NC}"
echo -n "Hello, DNS Tunnel!" | nc -u -w1 127.0.0.1 5355 || true

sleep 2

echo -e "${YELLOW}Testing: Sending 'Test packet 2'...${NC}"
echo -n "Test packet 2" | nc -u -w1 127.0.0.1 5355 || true

sleep 3

# Show logs
echo ""
echo -e "${YELLOW}=== Server Log (last 30 lines) ===${NC}"
tail -30 /tmp/server.log || echo "No server log"

echo ""
echo -e "${YELLOW}=== Client Log (last 30 lines) ===${NC}"
tail -30 /tmp/client.log || echo "No client log"

echo ""
echo -e "${YELLOW}=== Echo Server Log ===${NC}"
tail -20 /tmp/echo_server.log || echo "No echo server log"

echo ""

# Check if echo server received packets
if grep -q "Received:" /tmp/echo_server.log 2>/dev/null; then
    echo -e "${GREEN}✓ SUCCESS: Echo server received packets!${NC}"
else
    echo -e "${RED}✗ FAILED: Echo server did not receive any packets${NC}"
fi

echo ""
echo "Test complete."
echo ""
echo "To watch logs in real-time, run:"
echo "  tail -f /tmp/server.log"
echo "  tail -f /tmp/client.log"
echo "  tail -f /tmp/echo_server.log"
