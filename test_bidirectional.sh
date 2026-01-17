#!/bin/bash
# Comprehensive Bi-directional Test for DNS Tunnel
# Tests the full round-trip: client -> DNS tunnel -> server -> target_udp -> echo -> server -> UDP -> client

set -e

CLIENT_PORT=${1:-5355}
SERVER_DNS_PORT=${2:-53533}
TARGET_UDP=${3:-127.0.0.1:8080}
ITERATIONS=${4:-10}
PAYLOAD_SIZE=${5:-64}

echo "=== DNS Tunnel Bi-directional Test ==="
echo "Client port: $CLIENT_PORT"
echo "Server DNS port: $SERVER_DNS_PORT"
echo "Target UDP: $TARGET_UDP"
echo "Iterations: $ITERATIONS"
echo "Payload size: $PAYLOAD_SIZE bytes"
echo ""
echo "This test verifies:"
echo "  1. Client sends UDP packet -> DNS tunnel -> Server"
echo "  2. Server forwards to target_udp (echo server)"
echo "  3. Echo server responds -> Server"
echo "  4. Server sends UDP response -> Client"
echo "  5. Client forwards response to original source"
echo ""

# Check if echo server is running
TARGET_HOST=$(echo $TARGET_UDP | cut -d: -f1)
TARGET_PORT=$(echo $TARGET_UDP | cut -d: -f2)

if ! nc -z -u $TARGET_HOST $TARGET_PORT 2>/dev/null; then
    echo "⚠ Warning: Cannot connect to echo server at $TARGET_UDP"
    echo "  Please start the echo server: python3 test_echo_server.py $TARGET_HOST $TARGET_PORT"
    echo "  Or use: nc -u -l $TARGET_HOST $TARGET_PORT"
    echo ""
fi

success=0
failed=0
total_latency=0
latencies=()

for i in $(seq 1 $ITERATIONS); do
    # Generate unique test payload with sequence number
    payload=$(echo -n "TEST-$i-$(date +%s%N)" | head -c $PAYLOAD_SIZE)
    if [ ${#payload} -lt $PAYLOAD_SIZE ]; then
        # Pad if needed
        padding=$(head -c $((PAYLOAD_SIZE - ${#payload})) < /dev/zero | tr '\0' 'X')
        payload="${payload}${padding}"
    fi
    
    echo -n "Test $i: Sending ${#payload} bytes... "
    
    # Send and receive with timeout
    start=$(date +%s%N)
    
    # Use timeout to avoid hanging
    response=$(timeout 10 bash -c "echo -n '$payload' | nc -u -w2 127.0.0.1 $CLIENT_PORT 2>/dev/null" || echo "")
    end=$(date +%s%N)
    
    if [ -n "$response" ] && [ ${#response} -gt 0 ]; then
        duration=$((($end - $start) / 1000000))
        total_latency=$(($total_latency + $duration))
        latencies+=($duration)
        
        # Verify echo - response should match payload
        if [ "$payload" = "$response" ]; then
            echo "✓ OK (${duration}ms) - Response matches!"
            success=$(($success + 1))
        else
            echo "✗ FAILED (response mismatch)"
            echo "  Sent:     ${payload:0:40}..."
            echo "  Received: ${response:0:40}..."
            failed=$(($failed + 1))
        fi
    else
        echo "✗ FAILED (no response or timeout)"
        failed=$(($failed + 1))
    fi
    
    sleep 0.3
done

echo ""
echo "=== Results ==="
echo "Success: $success/$ITERATIONS"
echo "Failed: $failed/$ITERATIONS"

if [ $success -gt 0 ]; then
    # Calculate average latency
    avg_latency=$(($total_latency / $success))
    echo "Average latency: ${avg_latency}ms"
    
    # Calculate min/max if we have latencies
    if [ ${#latencies[@]} -gt 0 ]; then
        min_latency=${latencies[0]}
        max_latency=${latencies[0]}
        for lat in "${latencies[@]}"; do
            if [ $lat -lt $min_latency ]; then
                min_latency=$lat
            fi
            if [ $lat -gt $max_latency ]; then
                max_latency=$lat
            fi
        done
        echo "Latency range: ${min_latency}ms - ${max_latency}ms"
    fi
fi

echo ""
if [ $failed -eq 0 ]; then
    echo "✓ All tests passed! Bi-directional tunnel is working correctly."
    exit 0
else
    echo "✗ Some tests failed. Check:"
    echo "  - Server is running and listening on DNS port $SERVER_DNS_PORT"
    echo "  - Client is running and listening on UDP port $CLIENT_PORT"
    echo "  - Echo server is running on $TARGET_UDP"
    echo "  - Server config has correct target_udp and client_udp_port"
    exit 1
fi
