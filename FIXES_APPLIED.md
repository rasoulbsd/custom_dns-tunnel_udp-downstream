# Fixes Applied to DNS Tunnel

## Critical Fixes

### 1. Config File Port Mismatches ✅
- **Issue**: Client config had `local_udp: 5353` but tests expect 5355
- **Fix**: Changed to `5355` to match test expectations
- **Issue**: Server config had `dns_bind: 0.0.0.0:53` but should be `5353` for testing
- **Fix**: Changed to `5353`
- **Issue**: Server `client_udp_port` was `5353` but client listens on `5355`
- **Fix**: Changed to `5355`

### 2. DNS Domain Matching ✅
- **Issue**: DNS names with trailing dots weren't handled
- **Fix**: Added trailing dot removal in `decode_from_dns_query`
- **Issue**: Domain matching didn't handle exact domain matches
- **Fix**: Improved domain matching logic to handle both `.domain` and exact `domain` cases

### 3. Test Scripts ✅
- **Issue**: Scripts used positional args instead of `--config` flag
- **Fix**: Updated all scripts to use `--config` flag
- **Issue**: Build lock conflicts when multiple cargo processes run
- **Fix**: Scripts now build once, then run binaries directly
- **Issue**: Port conflicts from previous test runs
- **Fix**: Added cleanup of ports and processes before starting

## Testing Scripts Created

1. **test_comprehensive.sh** - Full end-to-end test
2. **diagnose.sh** - Diagnostic script to identify issues
3. **test_dns_encoding.sh** - Test DNS encoding/decoding
4. **build_and_test.bat** - Windows build script

## Remaining Issues to Test

1. **Server DNS Query Decoding**: Server receives queries but may not decode them
   - Check server logs for "Decoded DNS query" messages
   - Check for "Failed to decode" warnings
   - Verify domain matching works

2. **Client-Server Packet Flow**: 
   - Client sends DNS queries → Server receives and decodes
   - Server forwards to target → Target responds
   - Server sends UDP response → Client receives and forwards

3. **Packet Reassembly**:
   - Multiple fragments are reassembled correctly
   - Packet IDs match between client and server

## Next Steps

1. Build on Windows: `cargo build --release` or run `build_and_test.bat`
2. Run diagnostic: `./diagnose.sh` in WSL
3. Run comprehensive test: `./test_comprehensive.sh` in WSL
4. Check logs for any remaining issues
