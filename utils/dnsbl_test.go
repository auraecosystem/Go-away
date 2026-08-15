package utils

import (
	"context"
	"net"
	"testing"
	"time"
)

// startFakeNXDOMAINServer runs a minimal DNS server on loopback UDP that
// answers every query with RCODE 3 (NXDOMAIN), and returns a *net.Resolver
// configured to dial it regardless of the requested address.
func startFakeNXDOMAINServer(t *testing.T) *net.Resolver {
	t.Helper()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("failed to start fake dns server: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n < 12 {
				continue
			}
			resp := make([]byte, 0, n+4)
			resp = append(resp, buf[0], buf[1]) // ID, echoed
			resp = append(resp, 0x81, 0x83)     // QR=1, RD=1, RA=1, RCODE=3 (NXDOMAIN)
			resp = append(resp, 0x00, 0x01)     // QDCOUNT=1
			resp = append(resp, 0x00, 0x00)     // ANCOUNT=0
			resp = append(resp, 0x00, 0x00)     // NSCOUNT=0
			resp = append(resp, 0x00, 0x00)     // ARCOUNT=0
			resp = append(resp, buf[12:n]...)   // echo question section
			_, _ = conn.WriteToUDP(resp, addr)
		}
	}()

	serverAddr := conn.LocalAddr().String()
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", serverAddr)
		},
	}
}

func TestDNSBLLookupNXDOMAIN(t *testing.T) {
	resolver := startFakeNXDOMAINServer(t)
	bl := NewDNSBL("dnsbl.example.invalid", resolver)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result, err := bl.Lookup(ctx, net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatalf("unexpected error for NXDOMAIN: %v", err)
	}
	if result != ResponseGood {
		t.Fatalf("expected ResponseGood for NXDOMAIN, got %v", result)
	}
	if result.Bad() {
		t.Fatal("NXDOMAIN result should not be considered bad")
	}
}
