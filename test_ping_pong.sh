#!/bin/bash
# Ping-Pong Test for DNS Tunnel
# Sends data and verifies echo response

set -e

CLIENT_PORT=${1:-5355}
ITERATIONS=${2:-10}
PAYLOAD_SIZE=${3:-64}

echo "=== DNS Tunnel Ping-Pong Test ==="
echo "Client port: $CLIENT_PORT"
echo "Iterations: $ITERATIONS"
echo "Payload size: $PAYLOAD_SIZE bytes"
echo ""

success=0
failed=0
total_latency=0

for i in $(seq 1 $ITERATIONS); do
    # Generate test payload
    payload=$(head -c $PAYLOAD_SIZE < /dev/urandom | base64 | head -c $PAYLOAD_SIZE)
    
    echo -n "Test $i: Sending ${#payload} bytes... "
    
    # Send and receive with timeout
    start=$(date +%s%N)
    response=$(echo -n "$payload" | nc -u -w2 127.0.0.1 $CLIENT_PORT 2>/dev/null | head -c $PAYLOAD_SIZE)
    end=$(date +%s%N)
    
    if [ $? -eq 0 ] && [ -n "$response" ]; then
        duration=$((($end - $start) / 1000000))
        total_latency=$(($total_latency + $duration))
        
        # Verify echo
        if [ "$payload" = "$response" ]; then
            echo "✓ OK (${duration}ms)"
            success=$(($success + 1))
        else
            echo "✗ FAILED (response mismatch)"
            failed=$(($failed + 1))
        fi
    else
        echo "✗ FAILED (no response)"
        failed=$(($failed + 1))
    fi
    
    sleep 0.5
done

echo ""
echo "=== Results ==="
echo "Success: $success/$ITERATIONS"
echo "Failed: $failed/$ITERATIONS"

if [ $success -gt 0 ]; then
    avg_latency=$(($total_latency / $success))
    echo "Average latency: ${avg_latency}ms"
fi

if [ $failed -eq 0 ]; then
    echo "✓ All tests passed!"
    exit 0
else
    echo "✗ Some tests failed"
    exit 1
fi
