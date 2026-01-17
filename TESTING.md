# Testing Guide

## Test Files

### 1. Ping-Pong Tests

**`test_ping_pong.sh`** - Bash-based ping-pong test
```bash
./test_ping_pong.sh [port] [iterations] [payload_size]
# Example:
./test_ping_pong.sh 5355 10 64
```

**`test_ping_pong_python.py`** - Python-based ping-pong test (more detailed)
```bash
python3 test_ping_pong_python.py [host] [port] [iterations] [payload_size]
# Example:
python3 test_ping_pong_python.py 127.0.0.1 5355 10 128
```

### 2. Large Data Transfer Tests

**`test_large_data.sh`** - Bash-based large data transfer
```bash
./test_large_data.sh [port] [size_bytes]
# Example:
./test_large_data.sh 5355 50000  # 50KB
```

**`test_image_transfer.py`** - Python-based image transfer (requires Pillow)
```bash
# Install Pillow first:
pip3 install Pillow

# Run test:
python3 test_image_transfer.py [size_kb]
# Example:
python3 test_image_transfer.py 50  # 50KB image
```

### 3. Comprehensive Test Suite

**`test_comprehensive.sh`** - Runs all tests
```bash
./test_comprehensive.sh [port] [host]
# Example:
./test_comprehensive.sh 5355 127.0.0.1
```

### 4. Echo Server (for testing)

**`test_echo_server.py`** - Simple UDP echo server
```bash
python3 test_echo_server.py [host] [port]
# Example:
python3 test_echo_server.py 127.0.0.1 8080
```

## Quick Start

### 1. Start Echo Server (on VPS or locally)

```bash
python3 test_echo_server.py 127.0.0.1 8080
```

### 2. Configure Server

Make sure `server-config.json` has:
```json
{
  "target_udp": "127.0.0.1:8080"
}
```

### 3. Run Tests

```bash
# Make scripts executable
chmod +x test_*.sh

# Run comprehensive test
./test_comprehensive.sh

# Or run individual tests
./test_ping_pong.sh
python3 test_image_transfer.py 50
```

## Test Scenarios

### Scenario 1: Basic Connectivity
```bash
echo -n "hello" | nc -u 127.0.0.1 5355
```

### Scenario 2: Ping-Pong (Small)
```bash
./test_ping_pong.sh 5355 10 64
```

### Scenario 3: Ping-Pong (Medium)
```bash
python3 test_ping_pong_python.py 127.0.0.1 5355 20 512
```

### Scenario 4: Large Data Transfer
```bash
# 100KB transfer
./test_large_data.sh 5355 100000
```

### Scenario 5: Image Transfer
```bash
# 100KB image
python3 test_image_transfer.py 100
```

## Expected Results

### Ping-Pong Test
- **Success Rate**: Should be 100%
- **Latency**: 200-2000ms (depends on DNS resolver and network)
- **Payload Match**: Sent and received should be identical

### Large Data Transfer
- **Chunks Sent**: Should match total chunks
- **Throughput**: 5-50 Kbps (DNS tunnel overhead)
- **No Errors**: No "label exceed 63" or "odd hex" errors

## Troubleshooting

### Tests Fail with "Connection refused"
- Check if client is running: `ps aux | grep client`
- Check if port is correct: `netstat -tulpn | grep 5355`

### Tests Fail with "Timeout"
- Check server logs for DNS query reception
- Verify DNS records point to server
- Check firewall rules

### "Odd number of digits" Errors
- Should be fixed in latest code (capped at 63, even-length hex)
- Rebuild if using old binary

### Large Transfers Fail
- DNS tunnel has inherent size limits
- Try smaller chunks or reduce total size
- Check server logs for decode errors

## Performance Benchmarks

Expected performance (varies by network):

| Test Type | Expected Result |
|-----------|----------------|
| Small payload (64B) | 90-100% success, 200-500ms latency |
| Medium payload (1KB) | 80-95% success, 500-1500ms latency |
| Large payload (10KB+) | 70-90% success, 2-10s total time |
| Throughput | 5-50 Kbps |

## Notes

- DNS tunnel has high latency due to DNS query overhead
- Large transfers will be fragmented automatically
- Success rate depends on DNS resolver reliability
- Use multiple resolvers for better reliability
