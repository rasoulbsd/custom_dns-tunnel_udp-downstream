#!/usr/bin/env python3
"""
Ping-Pong Test for DNS Tunnel
Sends data and verifies echo response
"""

import socket
import time
import sys
import random
import string

def generate_payload(size):
    """Generate random payload of specified size"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=size)).encode()

def ping_pong_test(host='127.0.0.1', port=5355, iterations=10, payload_size=64):
    """Run ping-pong test"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5.0)
    
    print(f"=== DNS Tunnel Ping-Pong Test ===")
    print(f"Target: {host}:{port}")
    print(f"Iterations: {iterations}")
    print(f"Payload size: {payload_size} bytes")
    print()
    
    success = 0
    failed = 0
    total_latency = 0
    latencies = []
    
    for i in range(1, iterations + 1):
        # Generate payload
        payload = generate_payload(payload_size)
        
        print(f"Test {i}: Sending {len(payload)} bytes... ", end='', flush=True)
        
        try:
            start = time.time()
            sock.sendto(payload, (host, port))
            
            # Try to receive response
            response, addr = sock.recvfrom(65535)
            end = time.time()
            
            latency_ms = (end - start) * 1000
            latencies.append(latency_ms)
            total_latency += latency_ms
            
            # Verify echo
            if payload == response:
                print(f"✓ OK ({latency_ms:.2f}ms)")
                success += 1
            else:
                print(f"✗ FAILED (response mismatch: sent {len(payload)}, got {len(response)})")
                failed += 1
                
        except socket.timeout:
            print("✗ FAILED (timeout)")
            failed += 1
        except Exception as e:
            print(f"✗ FAILED ({e})")
            failed += 1
        
        time.sleep(0.1)
    
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
    
    if failed == 0:
        print("✓ All tests passed!")
        return 0
    else:
        print("✗ Some tests failed")
        return 1

def main():
    host = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5355
    iterations = int(sys.argv[3]) if len(sys.argv) > 3 else 10
    payload_size = int(sys.argv[4]) if len(sys.argv) > 4 else 64
    
    sys.exit(ping_pong_test(host, port, iterations, payload_size))

if __name__ == '__main__':
    main()
