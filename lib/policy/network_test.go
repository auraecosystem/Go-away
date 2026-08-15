package policy

import (
	"net/http"
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
