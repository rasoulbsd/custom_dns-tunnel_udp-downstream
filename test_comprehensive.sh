#!/bin/bash
# Comprehensive test script - tests everything systematically

set -e

echo "=== Comprehensive DNS Tunnel Test ==="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}Cleaning up...${NC}"
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

# Check if binaries exist
if [ ! -f "target/release/server" ] || [ ! -f "target/release/client" ]; then
    echo -e "${RED}Error: Binaries not found.${NC}"
    echo -e "${YELLOW}Please build on Windows with: cargo build --release${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Binaries found${NC}"
echo ""

# Kill any existing processes
echo -e "${YELLOW}Cleaning up any existing processes...${NC}"
pkill -f "target/release/server" 2>/dev/null || true
pkill -f "target/release/client" 2>/dev/null || true
fuser -k 8080/udp 2>/dev/null || true
fuser -k 5353/udp 2>/dev/null || true
fuser -k 5355/udp 2>/dev/null || true
sleep 1

# Create UDP echo server
cat > /tmp/udp_echo_test.py << 'EOF'
#!/usr/bin/env python3
import socket
import sys

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(1.0)
try:
    sock.bind(('127.0.0.1', 8080))
    print('[ECHO] Listening on 127.0.0.1:8080', flush=True)
    while True:
        try:
            data, addr = sock.recvfrom(1024)
            msg = data.decode('utf-8', errors='ignore')
            print(f'[ECHO] Received from {addr}: {msg}', flush=True)
            sock.sendto(data, addr)
            print(f'[ECHO] Echoed back to {addr}', flush=True)
        except socket.timeout:
            continue
        except KeyboardInterrupt:
            break
except Exception as e:
    print(f'[ECHO] Error: {e}', flush=True)
finally:
    sock.close()
EOF

chmod +x /tmp/udp_echo_test.py

# Start echo server
echo -e "${YELLOW}Starting UDP echo server...${NC}"
python3 /tmp/udp_echo_test.py > /tmp/echo_test.log 2>&1 &
ECHO_PID=$!
sleep 1

if ! kill -0 $ECHO_PID 2>/dev/null; then
    echo -e "${RED}Failed to start echo server${NC}"
    cat /tmp/echo_test.log
    exit 1
fi

echo -e "${GREEN}✓ Echo server started (PID: $ECHO_PID)${NC}"

# Start DNS tunnel server
echo -e "${YELLOW}Starting DNS tunnel server...${NC}"
RUST_LOG=info ./target/release/server --config server-config.json > /tmp/server_test.log 2>&1 &
SERVER_PID=$!
sleep 2

if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo -e "${RED}Server failed to start${NC}"
    cat /tmp/server_test.log
    exit 1
fi

echo -e "${GREEN}✓ Server started (PID: $SERVER_PID)${NC}"

# Start DNS tunnel client
echo -e "${YELLOW}Starting DNS tunnel client...${NC}"
RUST_LOG=info ./target/release/client --config client-config.json > /tmp/client_test.log 2>&1 &
CLIENT_PID=$!
sleep 2

if ! kill -0 $CLIENT_PID 2>/dev/null; then
    echo -e "${RED}Client failed to start${NC}"
    cat /tmp/client_test.log
    exit 1
fi

echo -e "${GREEN}✓ Client started (PID: $CLIENT_PID)${NC}"
echo ""

# Wait a bit for everything to stabilize
sleep 1

# Test 1: Send simple message
echo -e "${BLUE}=== Test 1: Simple message ===${NC}"
echo -n "Hello" | nc -u -w1 127.0.0.1 5355 2>/dev/null || echo "nc failed"
sleep 2

# Test 2: Send longer message
echo -e "${BLUE}=== Test 2: Longer message ===${NC}"
echo -n "Hello, DNS Tunnel!" | nc -u -w1 127.0.0.1 5355 2>/dev/null || echo "nc failed"
sleep 2

# Test 3: Send multiple messages
echo -e "${BLUE}=== Test 3: Multiple messages ===${NC}"
for i in {1..3}; do
    echo -n "Test $i" | nc -u -w1 127.0.0.1 5355 2>/dev/null || true
    sleep 1
done

sleep 3

# Show results
echo ""
echo -e "${YELLOW}=== Server Log (last 40 lines) ===${NC}"
tail -40 /tmp/server_test.log 2>/dev/null || echo "No server log"

echo ""
echo -e "${YELLOW}=== Client Log (last 40 lines) ===${NC}"
tail -40 /tmp/client_test.log 2>/dev/null || echo "No client log"

echo ""
echo -e "${YELLOW}=== Echo Server Log ===${NC}"
tail -20 /tmp/echo_test.log 2>/dev/null || echo "No echo log"

echo ""

# Check results
SUCCESS=false
if grep -q "Received from" /tmp/echo_test.log 2>/dev/null; then
    echo -e "${GREEN}✓ SUCCESS: Echo server received packets!${NC}"
    SUCCESS=true
else
    echo -e "${RED}✗ FAILED: Echo server did not receive any packets${NC}"
fi

# Check if server decoded queries
if grep -q "Decoded DNS query" /tmp/server_test.log 2>/dev/null; then
    echo -e "${GREEN}✓ Server is decoding DNS queries${NC}"
else
    echo -e "${RED}✗ Server is NOT decoding DNS queries${NC}"
    echo -e "${YELLOW}Check server log for 'Failed to decode' or domain mismatch${NC}"
fi

# Check if client sent queries
if grep -q "Sent DNS query" /tmp/client_test.log 2>/dev/null; then
    echo -e "${GREEN}✓ Client is sending DNS queries${NC}"
else
    echo -e "${RED}✗ Client is NOT sending DNS queries${NC}"
fi

# Check if client received responses
if grep -q "Received tunnel UDP packet" /tmp/client_test.log 2>/dev/null; then
    echo -e "${GREEN}✓ Client received tunnel UDP responses${NC}"
else
    echo -e "${YELLOW}⚠ Client did not receive tunnel UDP responses (may be normal if echo server didn't respond)${NC}"
fi

echo ""
if [ "$SUCCESS" = true ]; then
    echo -e "${GREEN}=== TEST PASSED ===${NC}"
    exit 0
else
    echo -e "${RED}=== TEST FAILED ===${NC}"
    echo ""
    echo "Debugging tips:"
    echo "1. Check server log: tail -f /tmp/server_test.log"
    echo "2. Check client log: tail -f /tmp/client_test.log"
    echo "3. Check echo log: tail -f /tmp/echo_test.log"
    echo "4. Verify config files match expected domains"
    exit 1
fi
