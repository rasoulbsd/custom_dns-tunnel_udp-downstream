# Critical Fixes Needed for DNS Tunnel

## Issue: Client Misidentifies Local UDP Packets as Tunnel Packets

### Problem
The client is treating local UDP packets (from netcat) as tunnel UDP packets from the server. This causes:
1. Local packets are not being sent as DNS queries
2. Invalid fragment numbers (109/108, 116/116) are being processed
3. Echo server never receives packets

### Root Cause
The validation in `decode_udp_packet` should reject invalid packets (fragment_id >= total_fragments), but it's not working correctly. The bytes "Hello, DNS Tunnel!" decode to:
- packet_id = 18533
- fragment_id = 108
- total_fragments = 108

Since 108 >= 108, the validation should return `Ok(None)`, but it's not.

### Fixes Applied
1. ✅ Added strict validation in `decode_udp_packet`:
   - Check `total_fragments > 0 && total_fragments <= 200`
   - Check `fragment_id < total_fragments` (strict, not <=)
   - Check `packet_id != 0`
   - Added debug logging

2. ✅ Added `pending_requests` check in client:
   - Only treat as tunnel packet if `packet_id` exists in `pending_requests`
   - This ensures only server responses are processed as tunnel packets

3. ✅ Fixed incomplete `info!` macro call in client

### Next Steps
1. **Rebuild the binaries** - The current binaries are from Jan 15 and don't include the fixes
2. **Test again** - Run `test_dns_tunnel.sh` after rebuilding
3. **Verify** - Check that:
   - Client logs "Received X bytes from local application" for netcat packets
   - Client logs "Fragmenting packet X into Y fragments" 
   - Client logs "Sent DNS query fragment X/Y"
   - Server logs "Received DNS query" and "Decoded DNS query"
   - Echo server receives packets

### To Rebuild
Since cargo is not available in WSL, rebuild on Windows or in a different environment:
```bash
cargo build --release
```

Then run the test script again.
