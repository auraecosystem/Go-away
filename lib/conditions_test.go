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

func createTestMMDB(t *testing.T) *utils.MaxMindDB {
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

	db, err := utils.NewMaxMindDB(f.Name())
	if err != nil {
		t.Fatalf("failed to open test mmdb: %v", err)
	}
	return db
}

func newTestState(t *testing.T, mmdb *utils.MaxMindDB) *State {
	t.Helper()
	state := &State{
		maxMindDB: mmdb,
		networks:  make(map[string]func() networkMatcher),
	}
	if err := state.initConditions(); err != nil {
		t.Fatalf("initConditions: %v", err)
	}
	return state
}

func TestAsnCELFunction(t *testing.T) {
	mmdb := createTestMMDB(t)
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

	t.Run("fails to register condition when maxMind not configured", func(t *testing.T) {
		stateNoMM := newTestState(t, nil)
		_, err := stateNoMM.RegisterCondition(http_cel.OperatorOr, "remoteAddress.asn() == 13335")
		if err == nil {
			t.Fatal("expected error registering condition when maxMind not configured, got nil")
		}
	})
}

func TestAsnCELFunctionLogging(t *testing.T) {
	mmdb := createTestMMDB(t)
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
