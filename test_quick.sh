#!/bin/bash
# Quick test using cargo run (no pre-built binaries needed)

set -e

echo "=== Quick DNS Tunnel Test (using cargo run) ==="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Cleanup
cleanup() {
    echo -e "\n${YELLOW}Cleaning up...${NC}"
    pkill -f "cargo run.*server" 2>/dev/null || true
    pkill -f "cargo run.*client" 2>/dev/null || true
    pkill -f "udp_echo.py" 2>/dev/null || true
    pkill -f "python3.*echo" 2>/dev/null || true
    fuser -k 8080/udp 2>/dev/null || true
    fuser -k 5353/udp 2>/dev/null || true
    fuser -k 5355/udp 2>/dev/null || true
    sleep 1
}

trap cleanup EXIT

# Kill any existing processes on our ports
echo -e "${YELLOW}Cleaning up any existing processes...${NC}"
pkill -f "cargo run.*server" 2>/dev/null || true
pkill -f "cargo run.*client" 2>/dev/null || true
fuser -k 8080/udp 2>/dev/null || true
fuser -k 5353/udp 2>/dev/null || true
fuser -k 5355/udp 2>/dev/null || true
sleep 1

# Start echo server
echo -e "${YELLOW}Starting echo server...${NC}"
python3 -c "
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('127.0.0.1', 8080))
print('Echo server ready', flush=True)
while True:
    data, addr = sock.recvfrom(1024)
    print(f'Echo: {data.decode()}', flush=True)
    sock.sendto(data, addr)
" > /tmp/echo_quick.log 2>&1 &
ECHO_PID=$!

# Wait for echo server
sleep 1
if ! kill -0 $ECHO_PID 2>/dev/null; then
    echo -e "${RED}Failed to start echo server${NC}"
    exit 1
fi

# Start server (build first to avoid lock conflicts)
echo -e "${YELLOW}Building server...${NC}"
cargo build --release --bin server > /tmp/server_build.log 2>&1 || {
    echo -e "${RED}Server build failed. Check /tmp/server_build.log${NC}"
    exit 1
}

echo -e "${YELLOW}Starting server...${NC}"
RUST_LOG=info ./target/release/server --config server-config.json > /tmp/server_quick.log 2>&1 &
SERVER_PID=$!

sleep 2

# Start client (build first)
echo -e "${YELLOW}Building client...${NC}"
cargo build --release --bin client > /tmp/client_build.log 2>&1 || {
    echo -e "${RED}Client build failed. Check /tmp/client_build.log${NC}"
    exit 1
}

echo -e "${YELLOW}Starting client...${NC}"
RUST_LOG=info ./target/release/client --config client-config.json > /tmp/client_quick.log 2>&1 &
CLIENT_PID=$!

sleep 3

# Check if services are running
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo -e "${RED}Server died. Check /tmp/server_quick.log${NC}"
    tail -20 /tmp/server_quick.log
    exit 1
fi

if ! kill -0 $CLIENT_PID 2>/dev/null; then
    echo -e "${RED}Client died. Check /tmp/client_quick.log${NC}"
    tail -20 /tmp/client_quick.log
    exit 1
fi

echo -e "${GREEN}All services ready${NC}"
echo ""

# Send test data
echo -e "${YELLOW}Sending test data...${NC}"
echo -n "Hello!" | nc -u -w1 127.0.0.1 5355 2>/dev/null || echo "nc not available"

sleep 2

echo -n "Test 2" | nc -u -w1 127.0.0.1 5355 2>/dev/null || true

sleep 3

echo ""
echo -e "${YELLOW}=== Server Log (last 15 lines) ===${NC}"
tail -15 /tmp/server_quick.log 2>/dev/null || echo "No server log"

echo ""
echo -e "${YELLOW}=== Client Log (last 15 lines) ===${NC}"
tail -15 /tmp/client_quick.log 2>/dev/null || echo "No client log"

echo ""
echo -e "${YELLOW}=== Echo Server Log ===${NC}"
tail -10 /tmp/echo_quick.log 2>/dev/null || echo "No echo log"

echo ""
if grep -q "Echo:" /tmp/echo_quick.log 2>/dev/null; then
    echo -e "${GREEN}✓ SUCCESS: Echo server received packets!${NC}"
else
    echo -e "${RED}✗ FAILED: Echo server did not receive packets${NC}"
fi

echo ""
echo -e "${GREEN}Test complete.${NC}"
echo ""
echo "To watch logs in real-time:"
echo "  tail -f /tmp/server_quick.log"
echo "  tail -f /tmp/client_quick.log"
echo "  tail -f /tmp/echo_quick.log"
