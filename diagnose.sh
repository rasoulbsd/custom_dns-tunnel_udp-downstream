#!/bin/bash
# Diagnostic script to identify all issues

set -e

echo "=== DNS Tunnel Diagnostic ==="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Check 1: Binaries exist
echo -e "${BLUE}Check 1: Binaries${NC}"
if [ -f "target/release/server" ] && [ -f "target/release/client" ]; then
    echo -e "${GREEN}✓ Binaries found${NC}"
    ls -lh target/release/server target/release/client
else
    echo -e "${RED}✗ Binaries not found${NC}"
    echo "  Build with: cargo build --release"
    exit 1
fi

# Check 2: Config files
echo ""
echo -e "${BLUE}Check 2: Config Files${NC}"
if [ -f "client-config.json" ] && [ -f "server-config.json" ]; then
    echo -e "${GREEN}✓ Config files found${NC}"
    echo "Client config:"
    cat client-config.json | python3 -m json.tool 2>/dev/null || cat client-config.json
    echo ""
    echo "Server config:"
    cat server-config.json | python3 -m json.tool 2>/dev/null || cat server-config.json
else
    echo -e "${RED}✗ Config files missing${NC}"
    exit 1
fi

# Check 3: Port availability
echo ""
echo -e "${BLUE}Check 3: Port Availability${NC}"
for port in 8080 5353 5355; do
    if lsof -i:$port >/dev/null 2>&1 || fuser $port/udp >/dev/null 2>&1; then
        echo -e "${YELLOW}⚠ Port $port is in use${NC}"
        lsof -i:$port 2>/dev/null || echo "  (check with: sudo lsof -i:$port)"
    else
        echo -e "${GREEN}✓ Port $port is available${NC}"
    fi
done

# Check 4: Test DNS encoding manually
echo ""
echo -e "${BLUE}Check 4: DNS Encoding Test${NC}"
python3 << 'PYEOF'
import binascii

# Simulate encoding
test_data = b"Hello"
packet_id = 12345
fragment_id = 0
total_fragments = 1

# Create packet header
packet = packet_id.to_bytes(2, 'big') + bytes([fragment_id, total_fragments]) + test_data
hex_encoded = binascii.hexlify(packet).decode('ascii')

print(f"Original data: {test_data}")
print(f"Packet ID: {packet_id}, Fragment: {fragment_id}/{total_fragments}")
print(f"Hex encoded: {hex_encoded}")
print(f"Length: {len(hex_encoded)} chars")

# Simulate subdomain
domain = "example.com"
subdomain = hex_encoded[:64]  # max 64 chars
query_name = f"{subdomain}.{domain}"
print(f"DNS query name: {query_name}")
print(f"Total length: {len(query_name)} chars")

# Check if it would fit
if len(query_name) > 253:
    print("⚠ WARNING: DNS name too long (max 253 chars)")
else:
    print("✓ DNS name length OK")
PYEOF

# Check 5: Test server startup
echo ""
echo -e "${BLUE}Check 5: Server Startup Test${NC}"
timeout 3 ./target/release/server --config server-config.json > /tmp/server_diag.log 2>&1 &
SERVER_PID=$!
sleep 1
if kill -0 $SERVER_PID 2>/dev/null; then
    echo -e "${GREEN}✓ Server starts successfully${NC}"
    kill $SERVER_PID 2>/dev/null || true
    sleep 1
else
    echo -e "${RED}✗ Server failed to start${NC}"
    cat /tmp/server_diag.log
fi

# Check 6: Test client startup
echo ""
echo -e "${BLUE}Check 6: Client Startup Test${NC}"
timeout 3 ./target/release/client --config client-config.json > /tmp/client_diag.log 2>&1 &
CLIENT_PID=$!
sleep 1
if kill -0 $CLIENT_PID 2>/dev/null; then
    echo -e "${GREEN}✓ Client starts successfully${NC}"
    kill $CLIENT_PID 2>/dev/null || true
    sleep 1
else
    echo -e "${RED}✗ Client failed to start${NC}"
    cat /tmp/client_diag.log
fi

echo ""
echo -e "${GREEN}=== Diagnostic Complete ===${NC}"
echo ""
echo "Next steps:"
echo "1. Fix any issues above"
echo "2. Run: ./test_comprehensive.sh"
