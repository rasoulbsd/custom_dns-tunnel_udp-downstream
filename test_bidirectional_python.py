#!/usr/bin/env python3
"""
Comprehensive Bi-directional Test for DNS Tunnel
Tests the full round-trip: client -> DNS tunnel -> server -> target_udp -> echo -> server -> UDP -> client
"""

import socket
import time
import sys
import random
import string
import hashlib

def generate_payload(size, seq_num=None):
    """Generate unique payload of specified size"""
    if seq_num is None:
        seq_num = random.randint(1, 1000000)
    # Create unique payload with sequence number
    base = f"TEST-{seq_num}-{int(time.time() * 1000000)}"
    if len(base) >= size:
        return base[:size].encode()
    # Pad to desired size
    padding = ''.join(random.choices(string.ascii_letters + string.digits, k=size - len(base))).encode()
    return (base + padding.decode()).encode()

def bidirectional_test(host='127.0.0.1', client_port=5355, iterations=10, payload_size=64):
    """Run comprehensive bi-directional test"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(10.0)  # Increased timeout for DNS tunnel
    
    print(f"=== DNS Tunnel Bi-directional Test ===")
    print(f"Client: {host}:{client_port}")
    print(f"Iterations: {iterations}")
    print(f"Payload size: {payload_size} bytes")
    print()
    print("This test verifies:")
    print("  1. Client sends UDP packet -> DNS tunnel -> Server")
    print("  2. Server forwards to target_udp (echo server)")
    print("  3. Echo server responds -> Server")
    print("  4. Server sends UDP response -> Client")
    print("  5. Client forwards response to original source")
    print()
    
    success = 0
    failed = 0
    total_latency = 0
    latencies = []
    
    for i in range(1, iterations + 1):
        # Generate unique payload
        payload = generate_payload(payload_size, i)
        payload_hash = hashlib.md5(payload).hexdigest()[:8]
        
        print(f"Test {i}: Sending {len(payload)} bytes (hash: {payload_hash})... ", end='', flush=True)
        
        try:
            start = time.time()
            sock.sendto(payload, (host, client_port))
            
            # Try to receive response
            response, addr = sock.recvfrom(65535)
            end = time.time()
            
            latency_ms = (end - start) * 1000
            latencies.append(latency_ms)
            total_latency += latency_ms
            
            # Verify echo - response should match payload exactly
            if payload == response:
                print(f"✓ OK ({latency_ms:.2f}ms) - Response matches!")
                success += 1
            else:
                response_hash = hashlib.md5(response).hexdigest()[:8]
                print(f"✗ FAILED (response mismatch)")
                print(f"    Sent hash:     {payload_hash}")
                print(f"    Received hash: {response_hash}")
                print(f"    Sent size:     {len(payload)} bytes")
                print(f"    Received size: {len(response)} bytes")
                failed += 1
                
        except socket.timeout:
            print("✗ FAILED (timeout - no response received)")
            failed += 1
        except Exception as e:
            print(f"✗ FAILED ({e})")
            failed += 1
        
        time.sleep(0.2)  # Small delay between tests
    
    sock.close()
    
    print()
    print("=== Results ===")
    print(f"Success: {success}/{iterations}")
    print(f"Failed: {failed}/{iterations}")
    
    if success > 0:
        avg_latency = total_latency / success
        min_latency = min(latencies) if latencies else 0
        max_latency = max(latencies) if latencies else 0
        print(f"Latency: min={min_latency:.2f}ms, avg={avg_latency:.2f}ms, max={max_latency:.2f}ms")
    
    print()
    if failed == 0:
        print("✓ All tests passed! Bi-directional tunnel is working correctly.")
        return 0
    else:
        print("✗ Some tests failed. Check:")
        print("  - Server is running and listening on DNS port")
        print("  - Client is running and listening on UDP port", client_port)
        print("  - Echo server is running on target_udp")
        print("  - Server config has correct target_udp and client_udp_port")
        return 1

def main():
    host = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
    client_port = int(sys.argv[2]) if len(sys.argv) > 2 else 5355
    iterations = int(sys.argv[3]) if len(sys.argv) > 3 else 10
    payload_size = int(sys.argv[4]) if len(sys.argv) > 4 else 64
    
    sys.exit(bidirectional_test(host, client_port, iterations, payload_size))

if __name__ == '__main__':
    main()
