#!/bin/bash
# Large Data Transfer Test for DNS Tunnel
# Transfers a base64-encoded image through the tunnel

set -e

CLIENT_PORT=${1:-5355}
TEST_IMAGE_SIZE=${2:-50000}  # Size in bytes

echo "=== DNS Tunnel Large Data Transfer Test ==="
echo "Client port: $CLIENT_PORT"
echo "Test data size: $TEST_IMAGE_SIZE bytes"
echo ""

# Create a test image (simple pattern)
echo "Generating test image..."
test_image="/tmp/test_image_${TEST_IMAGE_SIZE}.bin"
dd if=/dev/urandom of="$test_image" bs=1 count=$TEST_IMAGE_SIZE 2>/dev/null

# Encode to base64
echo "Encoding to base64..."
base64_image="/tmp/test_image_base64.txt"
base64 "$test_image" > "$base64_image"
base64_size=$(stat -f%z "$base64_image" 2>/dev/null || stat -c%s "$base64_image" 2>/dev/null)

echo "Original size: $TEST_IMAGE_SIZE bytes"
echo "Base64 size: $base64_size bytes"
echo ""

# Split into chunks (UDP max ~65KB, but we'll use smaller chunks)
CHUNK_SIZE=1000
total_chunks=$((($base64_size + $CHUNK_SIZE - 1) / $CHUNK_SIZE))

echo "Sending $total_chunks chunks of ~$CHUNK_SIZE bytes..."
echo ""

# Send chunks
start_time=$(date +%s%N)
sent_chunks=0

while IFS= read -r -n $CHUNK_SIZE chunk || [ -n "$chunk" ]; do
    if [ -n "$chunk" ]; then
        echo -n "$chunk" | nc -u -w1 127.0.0.1 $CLIENT_PORT 2>/dev/null
        if [ $? -eq 0 ]; then
            sent_chunks=$(($sent_chunks + 1))
            echo -n "."
        else
            echo -n "X"
        fi
    fi
done < "$base64_image"

echo ""
end_time=$(date +%s%N)
duration=$((($end_time - $start_time) / 1000000))

echo ""
echo "=== Transfer Complete ==="
echo "Chunks sent: $sent_chunks/$total_chunks"
echo "Total time: ${duration}ms"
if [ $sent_chunks -gt 0 ]; then
    throughput=$(($base64_size * 1000 / $duration))
    echo "Throughput: ~$throughput bytes/sec"
fi

# Cleanup
rm -f "$test_image" "$base64_image"

if [ $sent_chunks -eq $total_chunks ]; then
    echo "✓ All chunks sent successfully!"
    exit 0
else
    echo "✗ Some chunks failed to send"
    exit 1
fi
