package utils

import (
	"bytes"
	"net"
	"os"
	"testing"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

// createTestMMDB writes a minimal GeoLite2-ASN database to a temp file and
// returns its path. The caller's test cleanup removes the file.
//
// Records inserted:
//
//	1.0.0.0/24 → ASN 13335
//	2.0.0.0/24 → ASN 13335
//	3.0.0.0/24 → ASN 15169
func createTestMMDB(t *testing.T) string {
	t.Helper()

	writer, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType:        "GeoLite2-ASN",
		DisableIPv4Aliasing: true,
	})
	if err != nil {
		t.Fatalf("failed to create mmdb writer: %v", err)
	}

	entries := []struct {
		cidr string
		asn  uint32
	}{
		{"1.0.0.0/24", 13335},
		{"2.0.0.0/24", 13335},
		{"3.0.0.0/24", 15169},
	}
	for _, e := range entries {
		_, network, err := net.ParseCIDR(e.cidr)
		if err != nil {
			t.Fatalf("failed to parse CIDR %s: %v", e.cidr, err)
		}
		if err := writer.Insert(network, mmdbtype.Map{
			mmdbtype.String("autonomous_system_number"): mmdbtype.Uint32(e.asn),
		}); err != nil {
			t.Fatalf("failed to insert %s: %v", e.cidr, err)
		}
	}

	f, err := os.CreateTemp("", "go-away-test-*.mmdb")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	t.Cleanup(func() { os.Remove(f.Name()) })

	var buf bytes.Buffer
	if _, err := writer.WriteTo(&buf); err != nil {
		t.Fatalf("failed to write mmdb: %v", err)
	}
	if _, err := f.Write(buf.Bytes()); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	f.Close()

	return f.Name()
}

func TestNewMaxMindDB(t *testing.T) {
	t.Run("invalid path", func(t *testing.T) {
		_, err := NewMaxMindDB("/nonexistent/path.mmdb")
		if err == nil {
			t.Fatal("expected error for nonexistent path, got nil")
		}
	})

	t.Run("valid path", func(t *testing.T) {
		path := createTestMMDB(t)
		db, err := NewMaxMindDB(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if db == nil {
			t.Fatal("expected non-nil db")
		}
		db.Close()
	})
}

func TestGetASN(t *testing.T) {
	path := createTestMMDB(t)
	db, err := NewMaxMindDB(path)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	t.Cleanup(db.Close)

	t.Run("known IP returns correct ASN", func(t *testing.T) {
		asn, err := db.GetASN(net.ParseIP("1.0.0.1"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if asn != 13335 {
			t.Fatalf("expected ASN 13335, got %d", asn)
		}
	})

	t.Run("second network same ASN", func(t *testing.T) {
		asn, err := db.GetASN(net.ParseIP("2.0.0.50"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if asn != 13335 {
			t.Fatalf("expected ASN 13335, got %d", asn)
		}
	})

	t.Run("different ASN", func(t *testing.T) {
		asn, err := db.GetASN(net.ParseIP("3.0.0.1"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if asn != 15169 {
			t.Fatalf("expected ASN 15169, got %d", asn)
		}
	})

	t.Run("unknown IP returns error", func(t *testing.T) {
		_, err := db.GetASN(net.ParseIP("4.0.0.1"))
		if err == nil {
			t.Fatal("expected error for unregistered IP, got nil")
		}
	})
}
