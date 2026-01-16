# DNS Tunnel Infrastructure Diagram

```text
╔══════════════════════════════════════════════════════════════════════════════╗
║                    DNS TUNNEL INFRASTRUCTURE DIAGRAM                        ║
╚══════════════════════════════════════════════════════════════════════════════╝

┌─────────────────────────────────────────────────────────────────────────────┐
│                          IRAN (Client Side)                                 │
│                                                                             │
│  ┌──────────────┐                                                         │
│  │ Local App    │  (Browser, VPN Client, etc.)                            │
│  │ (UDP Client) │                                                         │
│  └──────┬───────┘                                                         │
│         │ UDP                                                              │
│         │ (127.0.0.1:5353)                                                │
│         ▼                                                                  │
│  ┌──────────────────────────────────────────────────────────────┐         │
│  │           DNS Tunnel CLIENT                                   │         │
│  │  ┌────────────────────────────────────────────────────────┐ │         │
│  │  │ 1. Receive UDP Packet                                   │ │         │
│  │  │ 2. Fragment if needed                                    │ │         │
│  │  │ 3. Add Header: [packet_id][frag_id][total_frags][data] │ │         │
│  │  │ 4. Hex Encode (case insensitive)                        │ │         │
│  │  │ 5. Create DNS Query: <hex>.example.com                 │ │         │
│  │  └────────────────────────────────────────────────────────┘ │         │
│  └──────┬───────────────────────────────────────────────────────┘         │
│         │ DNS Queries (UDP port 53)                                        │
│         │ Multiple queries (spam to all resolvers)                        │
│         │                                                                 │
└─────────┼─────────────────────────────────────────────────────────────────┘
          │
          │ DNS Queries
          │ (example.com, tunnel.example.com)
          │
          ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    PUBLIC DNS RESOLVERS                                     │
│                                                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐                   │
│  │ 8.8.8.8  │  │ 1.1.1.1  │  │ 9.9.9.9  │  │ ...      │                   │
│  │ (Google) │  │(Cloudflare)│ │(Quad9)  │  │          │                   │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘                   │
│       │            │            │            │                              │
│       └────────────┴────────────┴────────────┘                              │
│                    │                                                        │
│                    │ Forward DNS Queries                                    │
│                    │ (to authoritative DNS server)                          │
│                    ▼                                                        │
└────────────────────┼────────────────────────────────────────────────────────┘
                     │
                     │ DNS Queries
                     │ (UDP port 53)
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    VPS SERVER (DE/NL)                                      │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────┐         │
│  │           DNS Tunnel SERVER                                   │         │
│  │                                                               │         │
│  │  ┌────────────────────────────────────────────────────────┐ │         │
│  │  │ DNS Listener (Port 53)                                  │ │         │
│  │  │ 1. Receive DNS Query                                     │ │         │
│  │  │ 2. Extract subdomain: <hex>.example.com                │ │         │
│  │  │ 3. Hex Decode (case insensitive)                       │ │         │
│  │  │ 4. Parse: [packet_id][frag_id][total_frags][data]       │ │         │
│  │  │ 5. Reassemble fragments                                 │ │         │
│  │  └────────────────────────────────────────────────────────┘ │         │
│  │                    │                                          │         │
│  │                    │ Reassembled UDP Packet                  │         │
│  │                    ▼                                          │         │
│  │  ┌────────────────────────────────────────────────────────┐ │         │
│  │  │ UDP Forwarder                                           │ │         │
│  │  │ Forward to: target_udp (127.0.0.1:8080)                │ │         │
│  │  └────────────────────────────────────────────────────────┘ │         │
│  │                    │                                          │         │
│  │                    │ UDP                                      │         │
│  │                    ▼                                          │         │
│  └────────────────────┼──────────────────────────────────────────┘         │
│                       │                                                    │
│                       │ UDP (to Internet)                                   │
│                       ▼                                                    │
│  ┌──────────────────────────────────────────────────────────────┐         │
│  │           TARGET SERVICE                                     │         │
│  │  (Internet Service, Proxy, VPN Server, etc.)                 │         │
│  │  Listening on: 127.0.0.1:8080 (or external IP)             │         │
│  └──────────────────────────────────────────────────────────────┘         │
│                       │                                                    │
│                       │ UDP Response                                       │
│                       │                                                    │
│                       ▼                                                    │
│  ┌──────────────────────────────────────────────────────────────┐         │
│  │           UDP Response Handler                               │         │
│  │  1. Receive UDP Response                                    │         │
│  │  2. Fragment if needed                                       │         │
│  │  3. Add Header: [packet_id][frag_id][total_frags][data]     │         │
│  │  4. Encode as UDP Packet (NOT DNS)                          │         │
│  │  5. Send directly to Client UDP                              │         │
│  │     (client_ip:client_udp_port)                              │         │
│  └──────────────────────────────────────────────────────────────┘         │
│                       │                                                    │
│                       │ Direct UDP (NOT DNS)                                │
│                       │ (client_ip:5353)                                    │
│                       ▼                                                    │
└───────────────────────┼────────────────────────────────────────────────────┘
                        │
                        │ UDP Response
                        │ (Direct connection, bypassing DNS)
                        │
                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          IRAN (Client Side)                                 │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────┐      │
│  │           DNS Tunnel CLIENT                                     │      │
│  │  ┌────────────────────────────────────────────────────────┐    │      │
│  │  │ UDP Response Receiver                                    │    │      │
│  │  │ 1. Receive UDP Packet (from server)                     │    │      │
│  │  │ 2. Parse Header: [packet_id][frag_id][total_frags][data]│    │      │
│  │  │ 3. Reassemble fragments                                  │    │      │
│  │  │ 4. Forward to original source                           │    │      │
│  │  └────────────────────────────────────────────────────────┘    │      │
│  └──────┬───────────────────────────────────────────────────────────┘      │
│         │ UDP                                                               │
│         │ (127.0.0.1:5353)                                                  │
│         ▼                                                                    │
│  ┌──────────────┐                                                            │
│  │ Local App    │  (Receives response)                                      │
│  │ (UDP Client) │                                                            │
│  └──────────────┘                                                            │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

╔══════════════════════════════════════════════════════════════════════════════╗
║                          DATA FLOW SUMMARY                                   ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  UPLINK (Client → Server):                                                  ║
║  ┌────────────────────────────────────────────────────────────────────┐    ║
║  │ Local App → Client → Fragment → Hex Encode → DNS Query → Resolvers │    ║
║  │ → Server → Decode → Reassemble → Target Service                   │    ║
║  └────────────────────────────────────────────────────────────────────┘    ║
║                                                                              ║
║  DOWNLINK (Server → Client):                                                 ║
║  ┌────────────────────────────────────────────────────────────────────┐    ║
║  │ Target Service → Server → Fragment → UDP Packet → Client          │    ║
║  │ → Reassemble → Local App                                           │    ║
║  └────────────────────────────────────────────────────────────────────┘    ║
║                                                                              ║
║  KEY POINTS:                                                                 ║
║  • Uplink: DNS queries (port 53) - goes through DNS infrastructure         ║
║  • Downlink: Direct UDP (bypasses DNS) - faster, more reliable              ║
║  • Encoding: Hex (case insensitive)                                         ║
║  • Fragmentation: Automatic for large packets                              ║
║  • Multiple resolvers: Client "spams" all configured resolvers             ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝

┌─────────────────────────────────────────────────────────────────────────────┐
│                          PORT CONFIGURATION                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  CLIENT (Iran):                                                             │
│  • Local UDP:        127.0.0.1:5353  (receives from local apps)           │
│  • Response UDP:     127.0.0.1:5353  (receives from server)                │
│  • DNS Queries:      → 8.8.8.8:53, 1.1.1.1:53, etc.                       │
│                                                                             │
│  SERVER (VPS):                                                              │
│  • DNS Listener:     0.0.0.0:53      (receives DNS queries)                │
│  • Target UDP:       127.0.0.1:8080  (forwards to internet)                │
│  • Client Response:  → client_ip:5353  (sends UDP directly)                │
│                                                                             │
│  DNS RESOLVERS:                                                             │
│  • Google DNS:       8.8.8.8:53                                             │
│  • Cloudflare:       1.1.1.1:53                                             │
│  • Quad9:            9.9.9.9:53                                             │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                          PACKET FORMAT                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  DNS QUERY (Uplink):                                                        │
│  ┌────────────────────────────────────────────────────────────┐          │
│  │ <hex_encoded_data>.example.com                              │          │
│  │                                                              │          │
│  │ Hex Data Contains:                                           │          │
│  │ [packet_id: 2 bytes][frag_id: 1 byte][total: 1 byte][data] │          │
│  └────────────────────────────────────────────────────────────┘          │
│                                                                             │
│  UDP PACKET (Downlink):                                                     │
│  ┌────────────────────────────────────────────────────────────┐          │
│  │ [packet_id: 2 bytes][frag_id: 1 byte][total: 1 byte][data] │          │
│  │                                                              │          │
│  │ Direct UDP, no DNS encapsulation                             │          │
│  └────────────────────────────────────────────────────────────┘          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Simplified Flow Diagram

```
┌─────────┐
│ Local   │
│ App     │
└───┬─────┘
    │ UDP
    ▼
┌──────────────┐      DNS Query       ┌──────────┐      DNS Query       ┌──────────────┐
│   CLIENT     │ ──────────────────→ │  DNS     │ ──────────────────→ │   SERVER     │
│  (Iran)      │  (Hex encoded in     │ Resolvers│  (Port 53)          │  (VPS DE/NL)  │
│              │   subdomain)         │          │                     │              │
│  • Fragment  │                      │          │                     │  • Decode    │
│  • Hex Encode│                      │          │                     │  • Reassemble│
│  • DNS Query │                      │          │                     │  • Forward   │
└──────────────┘                      └──────────┘                     └──────┬───────┘
                                                                              │ UDP
                                                                              ▼
                                                                      ┌──────────────┐
                                                                      │   Internet   │
                                                                      │   Service    │
                                                                      └──────┬───────┘
                                                                             │ UDP Response
                                                                             ▼
                                                                      ┌──────────────┐
                                                                      │   SERVER     │
                                                                      │  (VPS DE/NL) │
                                                                      │              │
                                                                      │  • Fragment │
                                                                      │  • UDP Encode│
                                                                      │  • Send UDP │
                                                                      └──────┬───────┘
                                                                             │ Direct UDP
                                                                             │ (NOT DNS)
                                                                             ▼
                                                                      ┌──────────────┐
                                                                      │   CLIENT     │
                                                                      │  (Iran)      │
                                                                      │              │
                                                                      │  • Receive   │
                                                                      │  • Reassemble│
                                                                      │  • Forward   │
                                                                      └──────┬───────┘
                                                                             │ UDP
                                                                             ▼
                                                                      ┌─────────┐
                                                                      │ Local   │
                                                                      │ App     │
                                                                      └─────────┘
```

## Key Infrastructure Points

### 1. **Uplink (Client → Server)**
   - Uses DNS queries (port 53)
   - Data is hex-encoded in the subdomain
   - Sent to multiple DNS resolvers simultaneously
   - Routed through normal DNS infrastructure
   - Appears as legitimate DNS traffic

### 2. **Downlink (Server → Client)**
   - Uses direct UDP (NOT DNS)
   - Faster and more reliable
   - Bypasses DNS infrastructure entirely
   - Server sends directly to client IP:port
   - No DNS query/response overhead

### 3. **Benefits of This Architecture**
   - **Stealth**: DNS queries look like normal DNS traffic
   - **Performance**: Downlink is direct UDP (faster)
   - **Reliability**: Multiple resolver redundancy
   - **Scalability**: Automatic fragmentation for large packets
   - **Bi-directional**: Full duplex communication

### 4. **Network Flow**
   - **Outbound**: Local App → Client → DNS Resolvers → Server → Internet
   - **Inbound**: Internet → Server → Client → Local App
   - **Protocol**: DNS (uplink) + UDP (downlink)

### 5. **Security Considerations**
   - No encryption by default (add if needed)
   - DNS queries are visible to network monitoring
   - UDP responses are direct (may be blocked by firewalls)
   - Consider adding authentication/encryption for production use
