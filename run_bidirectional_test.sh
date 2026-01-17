#!/bin/bash
# Complete test runner for bi-directional tunnel
# This script sets up and runs the full test

set -e

echo "=== DNS Tunnel Bi-directional Test Runner ==="
echo ""

# Configuration
CLIENT_PORT=5355
SERVER_DNS_PORT=5353
TARGET_UDP="127.0.0.1:8080"
TARGET_HOST="127.0.0.1"
TARGET_PORT="8080"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if echo server is running
echo "Checking echo server on $TARGET_UDP..."
if ! nc -z -u $TARGET_HOST $TARGET_PORT 2>/dev/null; then
    echo -e "${YELLOW}Echo server not detected. Starting echo server in background...${NC}"
    python3 test_echo_server.py $TARGET_HOST $TARGET_PORT > /tmp/echo_server.log 2>&1 &
    ECHO_PID=$!
    sleep 1
    echo -e "${GREEN}Echo server started (PID: $ECHO_PID)${NC}"
    CLEANUP_ECHO=true
else
    echo -e "${GREEN}Echo server is running${NC}"
    CLEANUP_ECHO=false
fi

echo ""
echo "=== Test Configuration ==="
echo "Client port: $CLIENT_PORT"
echo "Server DNS port: $SERVER_DNS_PORT"
echo "Target UDP: $TARGET_UDP"
echo ""
echo -e "${YELLOW}Please ensure:${NC}"
echo "  1. Server is running: cargo run --bin dns-tunnel-server -- --config server-config.json"
echo "  2. Client is running: cargo run --bin dns-tunnel-client -- --config client-config.json"
echo ""
read -p "Press Enter when server and client are running..."

echo ""
echo "=== Running Bi-directional Test ==="
echo ""

# Run the test
if command -v python3 &> /dev/null; then
    python3 test_bidirectional_python.py 127.0.0.1 $CLIENT_PORT 10 64
    TEST_RESULT=$?
else
    ./test_bidirectional.sh $CLIENT_PORT $SERVER_DNS_PORT $TARGET_UDP 10 64
    TEST_RESULT=$?
fi

echo ""

# Cleanup
if [ "$CLEANUP_ECHO" = true ]; then
    echo "Stopping echo server (PID: $ECHO_PID)..."
    kill $ECHO_PID 2>/dev/null || true
    wait $ECHO_PID 2>/dev/null || true
fi

if [ $TEST_RESULT -eq 0 ]; then
    echo -e "${GREEN}✓ Test completed successfully!${NC}"
    exit 0
else
    echo -e "${RED}✗ Test failed${NC}"
    exit 1
fi
