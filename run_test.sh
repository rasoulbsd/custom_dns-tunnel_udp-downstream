#!/bin/bash
# Simple test runner for DNS tunnel

cd /mnt/c/Users/rasoo/Desktop/Github/dns-tunnel || exit 1

echo "Building..."
cargo build --release || exit 1

echo ""
echo "Running test script..."
bash test_dns_tunnel.sh
