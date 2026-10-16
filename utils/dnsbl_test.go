package utils

import (
	"context"
	"net"
	"testing"
	"time"

	"git.gammaspectra.live/git/go-away/internal/dnstest"
)

func TestDNSBLLookupNXDOMAIN(t *testing.T) {
	// no answers, so every name is NXDOMAIN
	resolver := dnstest.Resolver(dnstest.NewServer(t, nil))
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

func TestDNSBLLookupListed(t *testing.T) {
	resolver := dnstest.Resolver(dnstest.NewServer(t, map[string]net.IP{
		"1.0.0.127.dnsbl.example.invalid": net.IPv4(127, 0, 0, 3),
	}))
	bl := NewDNSBL("dnsbl.example.invalid", resolver)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result, err := bl.Lookup(ctx, net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != 3 {
		t.Fatalf("expected response 3, got %v", result)
	}
	if !result.Bad() {
		t.Fatal("listed result should be considered bad")
	}
}
