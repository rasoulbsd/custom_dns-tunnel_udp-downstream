#!/bin/bash
# Comprehensive Test Suite for DNS Tunnel

set -e

CLIENT_PORT=${1:-5355}
CLIENT_HOST=${2:-127.0.0.1}

echo "╔════════════════════════════════════════════════════════════╗"
echo "║     DNS Tunnel Comprehensive Test Suite                   ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test results
TESTS_PASSED=0
TESTS_FAILED=0

run_test() {
    local test_name=$1
    local test_command=$2
    
    echo -e "${BLUE}Running: $test_name${NC}"
    if eval "$test_command"; then
        echo -e "${GREEN}✓ PASSED: $test_name${NC}"
        TESTS_PASSED=$(($TESTS_PASSED + 1))
    else
        echo -e "${RED}✗ FAILED: $test_name${NC}"
        TESTS_FAILED=$(($TESTS_FAILED + 1))
    fi
echo ""
}

# Test 1: Basic connectivity
echo -e "${YELLOW}=== Test 1: Basic Connectivity ===${NC}"
run_test "Basic UDP Send" "echo -n 'test' | nc -u -w1 $CLIENT_HOST $CLIENT_PORT 2>/dev/null && sleep 1"

# Test 2: Ping-Pong (small payloads)
echo -e "${YELLOW}=== Test 2: Ping-Pong (Small Payloads) ===${NC}"
if [ -f "test_ping_pong.sh" ]; then
    run_test "Ping-Pong Test" "bash test_ping_pong.sh $CLIENT_PORT 5 64"
else
    echo -e "${YELLOW}⚠ Skipping: test_ping_pong.sh not found${NC}"
fi

# Test 3: Ping-Pong Python (if available)
echo -e "${YELLOW}=== Test 3: Ping-Pong Python ===${NC}"
if command -v python3 &> /dev/null && [ -f "test_ping_pong_python.py" ]; then
    run_test "Ping-Pong Python" "python3 test_ping_pong_python.py $CLIENT_HOST $CLIENT_PORT 5 128"
else
    echo -e "${YELLOW}⚠ Skipping: Python or test_ping_pong_python.py not found${NC}"
fi

# Test 4: Medium payload
echo -e "${YELLOW}=== Test 4: Medium Payload (1KB) ===${NC}"
run_test "Medium Payload" "dd if=/dev/urandom bs=1024 count=1 2>/dev/null | base64 | head -c 1024 | nc -u -w2 $CLIENT_HOST $CLIENT_PORT 2>/dev/null && sleep 2"

# Test 5: Large payload
echo -e "${YELLOW}=== Test 5: Large Payload (10KB) ===${NC}"
if [ -f "test_large_data.sh" ]; then
    run_test "Large Data Transfer" "bash test_large_data.sh $CLIENT_PORT 10000"
else
    echo -e "${YELLOW}⚠ Skipping: test_large_data.sh not found${NC}"
fi

# Test 6: Image transfer (if Python available)
echo -e "${YELLOW}=== Test 6: Image Transfer ===${NC}"
if command -v python3 &> /dev/null && [ -f "test_image_transfer.py" ]; then
    # Check if PIL is available
    if python3 -c "from PIL import Image" 2>/dev/null; then
        run_test "Image Transfer (50KB)" "python3 test_image_transfer.py 50"
else
        echo -e "${YELLOW}⚠ Skipping: PIL/Pillow not installed${NC}"
        echo "  Install with: pip3 install Pillow"
    fi
else
    echo -e "${YELLOW}⚠ Skipping: Python or test_image_transfer.py not found${NC}"
fi

# Test 7: Multiple rapid sends
echo -e "${YELLOW}=== Test 7: Rapid Fire Test ===${NC}"
rapid_success=0
for i in {1..20}; do
    if echo -n "rapid$i" | nc -u -w1 $CLIENT_HOST $CLIENT_PORT 2>/dev/null; then
        rapid_success=$(($rapid_success + 1))
    fi
done
if [ $rapid_success -ge 15 ]; then
    echo -e "${GREEN}✓ PASSED: Rapid Fire ($rapid_success/20)${NC}"
    TESTS_PASSED=$(($TESTS_PASSED + 1))
else
    echo -e "${RED}✗ FAILED: Rapid Fire ($rapid_success/20)${NC}"
    TESTS_FAILED=$(($TESTS_FAILED + 1))
fi
echo ""

# Summary
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                    Test Summary                            ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
echo -e "${RED}Failed: $TESTS_FAILED${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ Some tests failed${NC}"
    exit 1
fi
