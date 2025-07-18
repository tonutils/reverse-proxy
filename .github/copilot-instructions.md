# GitHub Copilot Instructions for TON Reverse Proxy

## Project Overview

TON Reverse Proxy bridges traditional HTTP websites to The Open Network (TON) blockchain, enabling websites to be accessible via ADNL addresses and .ton domains. This Go application converts HTTP requests to RLDP protocol over ADNL transport.

## Architecture Components

### Core Packages

- `cmd/proxy/main.go` - Single binary entry point with domain setup, tunnel support, and HTTP proxy
- `rldphttp/` - RLDP-HTTP bridge: `server.go` (ADNL/RLDP server), `client.go` (RLDP client), `http.go` (TL schemas), `address.go` (ADNL encoding), `stream.go` (chunked streaming)
- `config/fallback.go` - Embedded TON network configuration as JSON fallback

### Key Data Flow

1. HTTP request → RLDP server → HTTP handler → upstream backend
2. RLDP chunked streaming for large payloads (>128KB chunks)
3. DHT address publishing every minute for discovery
4. Domain linking via TON DNS blockchain transactions

## Critical Patterns

### RLDP Protocol Implementation

```go
// TL schema registration in http.go init()
tl.Register(Request{}, "http.request id:int256 method:string url:string http_version:string headers:(vector http.header) = http.Response")

// Chunked payload streaming (server.go)
func (s *Server) fetchPayload(ctx context.Context, requestID []byte, client RLDP, w io.Writer) error {
    var seqno int32 = 0
    for !last {
        var part PayloadPart
        err := client.DoQuery(ctx, _RLDPMaxAnswerSize, GetNextPayloadPart{
            ID: requestID, Seqno: seqno, MaxChunkSize: _ChunkSize,
        }, &part)
        // Write part.Data to stream
        seqno++
    }
}
```

### ADNL Address Handling

```go
// Always use base32 encoding with CRC16 validation (address.go)
func SerializeADNLAddress(addr []byte) (string, error) {
    a := append([]byte{0x2d}, addr...)
    crcBytes := make([]byte, 2)
    binary.BigEndian.PutUint16(crcBytes, crc16.Checksum(a, crc16table))
    return strings.ToLower(base32.StdEncoding.EncodeToString(append(a, crcBytes...))[1:]), nil
}
```

### Domain Setup Workflow

```go
// Auto-generated QR transaction for domain linking (main.go)
setupDomain(client, *FlagDomain, s.Address())

// Poll for domain record updates every 2 seconds
for {
    updated, err := resolve(ctx, resolver, domain, adnlAddr)
    if updated { break }
    time.Sleep(2 * time.Second)
}
```

### Configuration Patterns

```go
// Auto-config generation with consistent port calculation
cfg.Port = 9000 + (crc16.Checksum([]byte(cfg.ExternalIP), crc16table) % 5000)

// Environment-based overrides
ProxyPass: envOrVal("PROXY_PASS", "http://127.0.0.1:80/").(string)
```

## Development Commands

### Build & Test

```bash
# Local development build
make build                    # → build/tonutils-reverse-proxy

# Cross-platform release builds
make all                      # → builds for Linux, Windows, macOS (amd64/arm64)

# Docker with cache optimization
docker build --progress=plain .  # Uses BuildKit cache mounts
```

### Debugging

```bash
# Enable debug mode (shows ADNL/RLDP traffic)
./tonutils-reverse-proxy --debug

# Domain setup mode
./tonutils-reverse-proxy --domain example.ton

# Tunnel mode (no public IP required)
./tonutils-reverse-proxy --enable-tunnel
```

### Testing Patterns

```go
// Mock RLDP interfaces for testing
type mockRLDP struct{}
func (m *mockRLDP) DoQuery(ctx context.Context, maxAnswerSize uint64, query, result tl.Serializable) error

// Test ADNL address serialization
addr, _ := rldphttp.SerializeADNLAddress([]byte{...})
parsed, _ := rldphttp.ParseADNLAddress(addr)
```

## Critical Integration Points

### Tunnel System

- Uses `github.com/ton-blockchain/adnl-tunnel` for NAT bypass
- Event-driven configuration with `NodesPool` file requirement
- Automatic external IP detection and port mapping

### DHT Operations

- Address publishing every 60 seconds with 15-minute TTL
- Automatic retry with 5-second backoff on failures
- Connection validation via `FindAddresses` verification

### TL Serialization

- All RLDP messages use custom TL schemas (see `http.go` init())
- `tl:"int256"` for request IDs, `tl:"vector struct"` for headers
- Manual registration required: `tl.Register(Type{}, "schema definition")`

This codebase requires understanding of TON's ADNL/RLDP protocols and TL serialization. Focus on the `rldphttp` package for core proxy logic and `cmd/proxy/main.go` for configuration and domain setup flows.
