package utils

import (
	"bytes"
	"net"
	"os"
	"testing"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

// createTestASNMMDB writes a minimal GeoLite2-ASN database to a temp file and
// returns its path. The caller's test cleanup removes the file.
//
// Records inserted:
//
//	1.0.0.0/24 → ASN 13335, organization CLOUDFLARENET
//	2.0.0.0/24 → ASN 13335, no organization
//	3.0.0.0/24 → ASN 15169, organization GOOGLE
func createTestASNMMDB(t *testing.T) string {
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
		org  string
	}{
		{"1.0.0.0/24", 13335, "CLOUDFLARENET"},
		{"2.0.0.0/24", 13335, ""},
		{"3.0.0.0/24", 15169, "GOOGLE"},
	}
	for _, e := range entries {
		_, network, err := net.ParseCIDR(e.cidr)
		if err != nil {
			t.Fatalf("failed to parse CIDR %s: %v", e.cidr, err)
		}
		record := mmdbtype.Map{
			mmdbtype.String("autonomous_system_number"): mmdbtype.Uint32(e.asn),
		}
		if e.org != "" {
			record[mmdbtype.String("autonomous_system_organization")] = mmdbtype.String(e.org)
		}
		if err := writer.Insert(network, record); err != nil {
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
		path := createTestASNMMDB(t)
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
	path := createTestASNMMDB(t)
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

func TestGetASNOrg(t *testing.T) {
	path := createTestASNMMDB(t)
	db, err := NewMaxMindDB(path)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	t.Cleanup(db.Close)

	tests := []struct {
		ip  string
		asn uint
		org string
	}{
		{"1.0.0.1", 13335, "CLOUDFLARENET"},
		{"2.0.0.1", 13335, ""},
		{"3.0.0.1", 15169, "GOOGLE"},
	}
	for _, tt := range tests {
		asn, org, err := db.GetASNOrg(net.ParseIP(tt.ip))
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", tt.ip, err)
		}
		if asn != tt.asn || org != tt.org {
			t.Fatalf("%s: got AS%d %q, want AS%d %q", tt.ip, asn, org, tt.asn, tt.org)
		}
	}

	if _, _, err := db.GetASNOrg(net.ParseIP("4.0.0.1")); err == nil {
		t.Fatal("expected error for unregistered IP, got nil")
	}
}

// createTestCountryMMDB writes a minimal GeoLite2-Country database to a temp
// directory and returns its path.
//
// Records inserted:
//
//	1.0.0.0/24 → country HU, registered country DE
//	2.0.0.0/24 → registered country US only
//	3.0.0.0/24 → no country data
func createTestCountryMMDB(t *testing.T) string {
	t.Helper()

	writer, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType:        "GeoLite2-Country",
		DisableIPv4Aliasing: true,
	})
	if err != nil {
		t.Fatalf("failed to create mmdb writer: %v", err)
	}

	isoCode := func(code string) mmdbtype.Map {
		return mmdbtype.Map{mmdbtype.String("iso_code"): mmdbtype.String(code)}
	}
	entries := []struct {
		cidr   string
		record mmdbtype.Map
	}{
		{"1.0.0.0/24", mmdbtype.Map{
			mmdbtype.String("country"):            isoCode("HU"),
			mmdbtype.String("registered_country"): isoCode("DE"),
		}},
		{"2.0.0.0/24", mmdbtype.Map{
			mmdbtype.String("registered_country"): isoCode("US"),
		}},
		{"3.0.0.0/24", mmdbtype.Map{}},
	}
	for _, e := range entries {
		_, network, err := net.ParseCIDR(e.cidr)
		if err != nil {
			t.Fatalf("failed to parse CIDR %s: %v", e.cidr, err)
		}
		if err := writer.Insert(network, e.record); err != nil {
			t.Fatalf("failed to insert %s: %v", e.cidr, err)
		}
	}

	path := t.TempDir() + "/country.mmdb"
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("failed to create mmdb file: %v", err)
	}
	if _, err := writer.WriteTo(f); err != nil {
		t.Fatalf("failed to write mmdb: %v", err)
	}
	f.Close()

	return path
}

func TestGetCountry(t *testing.T) {
	db, err := NewMaxMindDB(createTestCountryMMDB(t))
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	t.Cleanup(db.Close)

	tests := []struct {
		name string
		ip   string
		want string
	}{
		{"location country preferred over registered country", "1.0.0.1", "HU"},
		{"registered country used when location is unknown", "2.0.0.1", "US"},
		{"IP without country data", "3.0.0.1", ""},
		{"IP not in database", "4.0.0.1", ""},
		{"IPv6 not in database", "2001:db8::1", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			country, err := db.GetCountry(net.ParseIP(tt.ip))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if country != tt.want {
				t.Fatalf("expected country %q, got %q", tt.want, country)
			}
		})
	}
}
