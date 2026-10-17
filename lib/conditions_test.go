package lib

import (
	"bytes"
	"log/slog"
	"net"
	"os"
	"strings"
	"testing"

	http_cel "codeberg.org/gone/http-cel"
	"git.gammaspectra.live/git/go-away/utils"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

// captureDebugLogs redirects the default slog logger to a buffer for the
// duration of the test, so debug-level log lines can be asserted on.
func captureDebugLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// writeTestASNMMDB writes a minimal GeoLite2-ASN database to a temp file and returns its path.
//
//	1.0.0.0/24 → ASN 13335, organization CLOUDFLARENET
//	2.0.0.0/24 → ASN 13335, no organization
//	3.0.0.0/24 → ASN 15169, organization GOOGLE
func writeTestASNMMDB(t *testing.T) string {
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

func createTestASNMMDB(t *testing.T) *utils.MaxMindDB {
	t.Helper()
	db, err := utils.NewMaxMindDB(writeTestASNMMDB(t))
	if err != nil {
		t.Fatalf("failed to open test mmdb: %v", err)
	}
	return db
}

func newTestState(t *testing.T, mmdb *utils.MaxMindDB) *State {
	t.Helper()
	state := &State{
		maxMindASNDB: mmdb,
		networks:     make(map[string]func() networkMatcher),
	}
	if err := state.initConditions(); err != nil {
		t.Fatalf("initConditions: %v", err)
	}
	return state
}

func TestAsnCELFunction(t *testing.T) {
	mmdb := createTestASNMMDB(t)
	state := newTestState(t, mmdb)

	t.Run("compiles successfully", func(t *testing.T) {
		_, err := state.RegisterCondition(http_cel.OperatorOr, "remoteAddress.asn() == 13335")
		if err != nil {
			t.Fatalf("failed to register condition: %v", err)
		}
	})

	t.Run("evaluates true for matching ASN", func(t *testing.T) {
		prog, err := state.RegisterCondition(http_cel.OperatorOr, "remoteAddress.asn() == 13335")
		if err != nil {
			t.Fatalf("failed to register condition: %v", err)
		}
		out, _, err := prog.Eval(map[string]any{
			"remoteAddress": net.IP{1, 0, 0, 1},
			"fp":            map[string]string{},
		})
		if err != nil {
			t.Fatalf("eval error: %v", err)
		}
		if out.Equal(types.True) != types.True {
			t.Fatalf("expected true, got %v", out)
		}
	})

	t.Run("evaluates false for non-matching ASN", func(t *testing.T) {
		prog, err := state.RegisterCondition(http_cel.OperatorOr, "remoteAddress.asn() == 13335")
		if err != nil {
			t.Fatalf("failed to register condition: %v", err)
		}
		out, _, err := prog.Eval(map[string]any{
			"remoteAddress": net.IP{3, 0, 0, 1},
			"fp":            map[string]string{},
		})
		if err != nil {
			t.Fatalf("eval error: %v", err)
		}
		if out.Equal(types.False) != types.True {
			t.Fatalf("expected false, got %v", out)
		}
	})

	t.Run("fails to register condition when ASN database not configured", func(t *testing.T) {
		stateNoMM := newTestState(t, nil)
		_, err := stateNoMM.RegisterCondition(http_cel.OperatorOr, "remoteAddress.asn() == 13335")
		if err == nil {
			t.Fatal("expected error registering condition when ASN database not configured, got nil")
		}
	})
}

func TestAsnCELFunctionLogging(t *testing.T) {
	mmdb := createTestASNMMDB(t)
	state := newTestState(t, mmdb)

	prog, err := state.RegisterCondition(http_cel.OperatorOr, "remoteAddress.asn() == 13335")
	if err != nil {
		t.Fatalf("failed to register condition: %v", err)
	}

	t.Run("logs successful lookup", func(t *testing.T) {
		buf := captureDebugLogs(t)
		_, _, err := prog.Eval(map[string]any{
			"remoteAddress": net.IP{1, 0, 0, 1},
			"fp":            map[string]string{},
		})
		if err != nil {
			t.Fatalf("eval error: %v", err)
		}
		out := buf.String()
		if !strings.Contains(out, "maxmind ASN lookup") {
			t.Fatalf("expected asn lookup debug log, got: %s", out)
		}
		if !strings.Contains(out, "asn=13335") {
			t.Fatalf("expected asn=13335 in log, got: %s", out)
		}
	})

	t.Run("logs failed lookup", func(t *testing.T) {
		buf := captureDebugLogs(t)
		_, _, err := prog.Eval(map[string]any{
			"remoteAddress": net.IP{4, 0, 0, 1},
			"fp":            map[string]string{},
		})
		if err == nil {
			t.Fatal("expected eval error for unregistered IP")
		}
		out := buf.String()
		if !strings.Contains(out, "maxmind ASN lookup failed") {
			t.Fatalf("expected asn lookup failure debug log, got: %s", out)
		}
	})
}

func createTestCountryMMDB(t *testing.T) *utils.MaxMindDB {
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

	db, err := utils.NewMaxMindDB(path)
	if err != nil {
		t.Fatalf("failed to open test mmdb: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

func TestCountryCELFunction(t *testing.T) {
	state := newTestState(t, nil)
	state.maxMindCountryDB = createTestCountryMMDB(t)

	prog, err := state.RegisterCondition(http_cel.OperatorOr, `remoteAddress.country() == "HU"`)
	if err != nil {
		t.Fatalf("failed to register condition: %v", err)
	}

	tests := []struct {
		name string
		ip   net.IP
		want ref.Val
	}{
		{"location country matches", net.IP{1, 0, 0, 1}, types.True},
		{"registered country fallback does not match", net.IP{2, 0, 0, 1}, types.False},
		{"ip without country", net.IP{3, 0, 0, 1}, types.False},
		{"ip not in database", net.IP{4, 0, 0, 1}, types.False},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, _, err := prog.Eval(map[string]any{
				"remoteAddress": tt.ip,
				"fp":            map[string]string{},
			})
			if err != nil {
				t.Fatalf("eval error: %v", err)
			}
			if out.Equal(tt.want) != types.True {
				t.Fatalf("expected %v, got %v", tt.want, out)
			}
		})
	}

	t.Run("returns registered country when location is unknown", func(t *testing.T) {
		prog, err := state.RegisterCondition(http_cel.OperatorOr, `remoteAddress.country() == "US"`)
		if err != nil {
			t.Fatalf("failed to register condition: %v", err)
		}
		out, _, err := prog.Eval(map[string]any{
			"remoteAddress": net.IP{2, 0, 0, 1},
			"fp":            map[string]string{},
		})
		if err != nil {
			t.Fatalf("eval error: %v", err)
		}
		if out.Equal(types.True) != types.True {
			t.Fatalf("expected true, got %v", out)
		}
	})

	t.Run("fails to register condition when country database not configured", func(t *testing.T) {
		_, err := newTestState(t, nil).RegisterCondition(http_cel.OperatorOr, `remoteAddress.country() == "HU"`)
		if err == nil || !strings.Contains(err.Error(), "country database") {
			t.Fatalf("expected missing country database error, got %v", err)
		}
	})
}
