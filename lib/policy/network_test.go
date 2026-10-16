package policy

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNetworkFetchPrefixes(t *testing.T) {
	client := &http.Client{}

	t.Run("prefixes-only network", func(t *testing.T) {
		n := Network{Prefixes: []string{"10.0.0.0/8"}}
		prefixes, err := n.FetchPrefixes(client, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(prefixes) != 1 {
			t.Fatalf("expected 1 prefix, got %d", len(prefixes))
		}
		if prefixes[0].String() != "10.0.0.0/8" {
			t.Fatalf("expected 10.0.0.0/8, got %s", prefixes[0].String())
		}
	})
}

func TestNetworkFetchPrefixesInvalidEntry(t *testing.T) {
	file := filepath.Join(t.TempDir(), "networks.txt")
	if err := os.WriteFile(file, []byte("10.0.0.0/8\n172.16.0.0/12\n999.1.1.1/8\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	regex := `(?m)^(?P<prefix>[0-9./]+)$`
	prefixes, err := Network{File: &file, Regex: &regex}.FetchPrefixes(&http.Client{}, nil)
	if err == nil || prefixes != nil {
		t.Fatalf("expected the list to be rejected, got %v, %v", prefixes, err)
	}
	if !strings.Contains(err.Error(), "line 3:") {
		t.Fatalf("expected line 3 in error, got %v", err)
	}

	jqPath := ".[]"
	if err := os.WriteFile(file, []byte(`["10.0.0.0/8", 5]`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := (Network{File: &file, JqPath: &jqPath}).FetchPrefixes(&http.Client{}, nil); err == nil || !strings.Contains(err.Error(), "jq-path output 2:") {
		t.Fatalf("expected jq-path output 2 in error, got %v", err)
	}
}
