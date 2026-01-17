#!/usr/bin/env python3
"""
Simple UDP Echo Server for Testing
Echoes back any UDP packets it receives
"""

import socket
import sys

def main():
    host = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    sock.settimeout(1.0)
    
    print(f"UDP Echo Server listening on {host}:{port}")
    print("Press Ctrl+C to stop")
    
    packet_count = 0
    
    try:
        while True:
            try:
                data, addr = sock.recvfrom(65535)
                packet_count += 1
                print(f"[{packet_count}] Received {len(data)} bytes from {addr}")
                
                # Echo back
                sock.sendto(data, addr)
                print(f"      Echoed {len(data)} bytes back to {addr}")
            except socket.timeout:
                continue
            except KeyboardInterrupt:
                break
    except Exception as e:
        print(f"Error: {e}")
    finally:
        sock.close()
        print(f"\nEcho server stopped. Total packets: {packet_count}")

if __name__ == '__main__':
    main()
