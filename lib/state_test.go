package lib

import (
	"net"
	"strings"
	"testing"
)

func TestAsnMatcherLogging(t *testing.T) {
	mmdb := createTestMMDB(t)
	m := &asnMatcher{name: "test-group", asns: []uint{13335}, maxMindDB: mmdb}

	t.Run("logs matched lookup", func(t *testing.T) {
		buf := captureDebugLogs(t)
		ok, err := m.Contains(net.IP{1, 0, 0, 1})
		if err != nil || !ok {
			t.Fatalf("unexpected result: ok=%v err=%v", ok, err)
		}
		out := buf.String()
		if !strings.Contains(out, "maxmind ASN lookup matched") {
			t.Fatalf("expected match debug log, got: %s", out)
		}
		if !strings.Contains(out, "asn-group=test-group") {
			t.Fatalf("expected asn-group in log, got: %s", out)
		}
	})

	t.Run("logs no-match lookup", func(t *testing.T) {
		buf := captureDebugLogs(t)
		ok, err := m.Contains(net.IP{3, 0, 0, 1})
		if err != nil || ok {
			t.Fatalf("unexpected result: ok=%v err=%v", ok, err)
		}
		out := buf.String()
		if !strings.Contains(out, "maxmind ASN lookup no match") {
			t.Fatalf("expected no-match debug log, got: %s", out)
		}
	})

	t.Run("logs failed lookup", func(t *testing.T) {
		buf := captureDebugLogs(t)
		_, err := m.Contains(net.IP{4, 0, 0, 1})
		if err == nil {
			t.Fatal("expected error for unregistered IP")
		}
		out := buf.String()
		if !strings.Contains(out, "maxmind ASN lookup failed") {
			t.Fatalf("expected failure debug log, got: %s", out)
		}
	})
}
