#!/bin/bash
# Create a test image file for transfer testing
# Creates a simple pattern image as base64

SIZE_KB=${1:-50}
OUTPUT_FILE=${2:-test_image_base64.txt}

echo "Creating ${SIZE_KB}KB test image..."

# Create a pattern: alternating bytes
# This creates a visible pattern when decoded
pattern=""
for i in {0..255}; do
    pattern+=$(printf "\\x%02x" $i)
done

# Repeat pattern to reach desired size
target_size=$(($SIZE_KB * 1024))
image_data=""

while [ ${#image_data} -lt $target_size ]; do
    image_data+="$pattern"
done

# Trim to exact size
image_data=$(echo -n "$image_data" | head -c $target_size)

# Encode to base64
echo -n "$image_data" | base64 > "$OUTPUT_FILE"

actual_size=$(stat -f%z "$OUTPUT_FILE" 2>/dev/null || stat -c%s "$OUTPUT_FILE" 2>/dev/null)
echo "Created: $OUTPUT_FILE"
echo "Size: $actual_size bytes (base64 encoded)"
echo ""
echo "To send through tunnel:"
echo "  cat $OUTPUT_FILE | while IFS= read -r line; do echo -n \"\$line\" | nc -u 127.0.0.1 5355; done"
