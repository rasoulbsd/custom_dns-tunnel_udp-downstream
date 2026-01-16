#!/bin/bash
# Watch for file changes and auto-test
# Requires: cargo-watch (install with: cargo install cargo-watch)

set -e

echo "=== DNS Tunnel Auto-Test with File Watching ==="
echo ""

# Check if cargo-watch is available
if ! command -v cargo-watch &> /dev/null; then
    echo "Installing cargo-watch..."
    cargo install cargo-watch --locked
fi

# This script will watch for changes and rebuild
# Run the test script in another terminal
echo "Starting file watcher..."
echo "This will rebuild on file changes."
echo "Run './test_dev.sh' in another terminal to test."
echo ""

# Watch for changes in src/ and rebuild
cargo watch -x "build --release --bin server --bin client"
