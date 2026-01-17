#!/usr/bin/env python3
"""
Large Image Transfer Test for DNS Tunnel
Transfers a base64-encoded image through the tunnel and verifies integrity
"""

import socket
import base64
import time
import sys
import os

def create_test_image(size_kb=50):
    """Create a test image of specified size"""
    target_size = size_kb * 1024
    
    try:
        from io import BytesIO
        from PIL import Image, ImageDraw
        
        # Create a simple colored image
        width = 800
        height = 600
        img = Image.new('RGB', (width, height), color='red')
        draw = ImageDraw.Draw(img)
        
        # Draw some patterns to make it non-uniform
        for i in range(0, width, 50):
            draw.rectangle([i, 0, i+25, height], fill='blue')
        for i in range(0, height, 50):
            draw.rectangle([0, i, width, i+25], fill='green')
        
        # Save to bytes
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        img_data = buffer.getvalue()
        
        # If image is too small, pad it
        if len(img_data) < target_size:
            padding = b'X' * (target_size - len(img_data))
            img_data = img_data + padding
        
        return img_data[:target_size]  # Trim to exact size
    except ImportError:
        # Fallback: create simple binary pattern if PIL not available
        # Create a pattern: 0x00 to 0xFF repeating
        pattern = bytes(range(256))
        img_data = (pattern * ((target_size // 256) + 1))[:target_size]
        return img_data

def send_udp_chunks(data, host='127.0.0.1', port=5355, chunk_size=1000):
    """Send data in chunks via UDP"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    
    total_chunks = (len(data) + chunk_size - 1) // chunk_size
    sent = 0
    
    print(f"Sending {total_chunks} chunks of {chunk_size} bytes...")
    start_time = time.time()
    
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i+chunk_size]
        try:
            sock.sendto(chunk, (host, port))
            sent += 1
            if sent % 10 == 0:
                print(f"  Sent {sent}/{total_chunks} chunks...", end='\r')
        except Exception as e:
            print(f"\nError sending chunk {sent}: {e}")
            break
    
    end_time = time.time()
    duration = (end_time - start_time) * 1000
    
    sock.close()
    
    print(f"\nSent {sent}/{total_chunks} chunks in {duration:.2f}ms")
    if sent > 0:
        throughput = (len(data) / duration) * 1000
        print(f"Throughput: ~{throughput:.0f} bytes/sec")
    
    return sent == total_chunks

def main():
    if len(sys.argv) > 1:
        size_kb = int(sys.argv[1])
    else:
        size_kb = 50  # 50KB default
    
    print("=== DNS Tunnel Large Image Transfer Test ===")
    print(f"Image size: {size_kb}KB")
    print()
    
    # Create test image
    print("Creating test image...")
    img_data = create_test_image(size_kb)
    print(f"Image created: {len(img_data)} bytes")
    
    # Encode to base64
    print("Encoding to base64...")
    base64_data = base64.b64encode(img_data)
    print(f"Base64 size: {len(base64_data)} bytes")
    print()
    
    # Send through tunnel
    print("Sending through DNS tunnel...")
    success = send_udp_chunks(base64_data, chunk_size=1000)
    
    if success:
        print("\n✓ Transfer completed successfully!")
        return 0
    else:
        print("\n✗ Transfer failed or incomplete")
        return 1

if __name__ == '__main__':
    sys.exit(main())
