#!/bin/bash
# Manual test script for DNS tunnel
# This script helps test the implementation

echo "=== DNS Tunnel Test Script ==="
echo ""
echo "This script will help you test the DNS tunnel implementation."
echo "Make sure you have Rust installed and cargo is in your PATH."
echo ""

# Check if cargo is available
if ! command -v cargo &> /dev/null; then
    echo "ERROR: cargo is not installed or not in PATH"
    echo "Please install Rust from https://rustup.rs/"
    exit 1
fi

echo "✓ Cargo found: $(cargo --version)"
echo ""

# Build the project
echo "Building project..."
cargo build --release

if [ $? -ne 0 ]; then
    echo "ERROR: Build failed!"
    exit 1
fi

echo "✓ Build successful!"
echo ""

# Run unit tests
echo "Running tests..."
cargo test

if [ $? -ne 0 ]; then
    echo "WARNING: Some tests failed"
else
    echo "✓ All tests passed!"
fi

echo ""
echo "=== Test Complete ==="
echo ""
echo "Binaries are available at:"
echo "  - target/release/client"
echo "  - target/release/server"
echo ""
echo "To test manually:"
echo "1. Start the server: ./target/release/server --config server-config.json"
echo "2. Start the client: ./target/release/client --config client-config.json"
echo "3. Send UDP packets to the client's local UDP address"
