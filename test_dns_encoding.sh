#!/bin/bash
# Test DNS encoding/decoding directly

set -e

echo "=== Testing DNS Encoding/Decoding ==="
echo ""

# Build test binary if needed
if [ ! -f "target/release/client" ]; then
    echo "Binaries not found. Please build first."
    exit 1
fi

# Test data
TEST_DATA="Hello, DNS Tunnel!"
echo "Test data: $TEST_DATA"
echo ""

# Check what the client would encode
echo "Checking client encoding..."
RUST_LOG=debug ./target/release/client --config client-config.json > /tmp/client_encode_test.log 2>&1 &
CLIENT_PID=$!

sleep 1

# Send test data
echo -n "$TEST_DATA" | nc -u -w1 127.0.0.1 5355 2>/dev/null || true

sleep 2

kill $CLIENT_PID 2>/dev/null || true

# Check logs
echo "=== Client Encoding Log ==="
grep -E "encode|DNS query|fragment|hex" /tmp/client_encode_test.log | head -20 || echo "No encoding logs found"

echo ""
echo "Test complete. Check logs above."
