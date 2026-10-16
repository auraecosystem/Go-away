package policy

import (
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func ptr[T any](v T) *T {
	return &v
}

// x4bnetRegex parses lists like https://github.com/X4BNet/lists_vpn/blob/main/input/datacenter/ASN.txt
const x4bnetRegex = `(?im)^[ \t]*(?:AS)?(?P<asn>[0-9]+)[ \t]*(?:#[ \t]*(?P<comment>[^\r\n]*))?`

func TestParseASNList(t *testing.T) {
	t.Run("regex with comments", func(t *testing.T) {
		data := "AS45090 # Tencent cloud computing, they dont really monitor their network\r\n" +
			"  as3223#VOXILITY, RO\n" +
			"6939\n" +
			"# full line comment\n" +
			"\n" +
			"AS7203 # LEASEWEB-USA-SFO-12 - Leaseweb USA, Inc., US   \n"
		records, err := ParseASNList([]byte(data), nil, ptr(x4bnetRegex))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := []ASNRecord{
			{ASN: 45090, Comment: "Tencent cloud computing, they dont really monitor their network"},
			{ASN: 3223, Comment: "VOXILITY, RO"},
			{ASN: 6939},
			{ASN: 7203, Comment: "LEASEWEB-USA-SFO-12 - Leaseweb USA, Inc., US"},
		}
		if !reflect.DeepEqual(records, expected) {
			t.Fatalf("expected %+v, got %+v", expected, records)
		}
	})

	t.Run("custom regex", func(t *testing.T) {
		data := "13335,Cloudflare\n15169,Google\n"
		records, err := ParseASNList([]byte(data), nil, ptr(`(?m)^(?P<asn>[0-9]+),(?P<comment>.*)$`))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := []ASNRecord{{ASN: 13335, Comment: "Cloudflare"}, {ASN: 15169, Comment: "Google"}}
		if !reflect.DeepEqual(records, expected) {
			t.Fatalf("expected %+v, got %+v", expected, records)
		}
	})

	t.Run("custom regex without comment group", func(t *testing.T) {
		records, err := ParseASNList([]byte("13335 15169"), nil, ptr(`(?P<asn>[0-9]+)`))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := []ASNRecord{{ASN: 13335}, {ASN: 15169}}
		if !reflect.DeepEqual(records, expected) {
			t.Fatalf("expected %+v, got %+v", expected, records)
		}
	})

	t.Run("no regex or jq-path", func(t *testing.T) {
		if _, err := ParseASNList([]byte("13335"), nil, nil); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("regex without asn group", func(t *testing.T) {
		_, err := ParseASNList([]byte("13335"), nil, ptr(`[0-9]+`))
		if err == nil || !strings.Contains(err.Error(), "asn named match") {
			t.Fatalf("expected missing group error, got %v", err)
		}
	})

	t.Run("jq numbers and strings", func(t *testing.T) {
		data := `{"asns": [13335, "AS15169", "32934"]}`
		records, err := ParseASNList([]byte(data), ptr(".asns[]"), nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := []ASNRecord{{ASN: 13335}, {ASN: 15169}, {ASN: 32934}}
		if !reflect.DeepEqual(records, expected) {
			t.Fatalf("expected %+v, got %+v", expected, records)
		}
	})

	t.Run("jq objects with comments", func(t *testing.T) {
		data := `[{"number": 13335, "name": "Cloudflare"}, {"number": 15169, "name": null}]`
		records, err := ParseASNList([]byte(data), ptr(".[] | {asn: .number, comment: .name}"), nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := []ASNRecord{{ASN: 13335, Comment: "Cloudflare"}, {ASN: 15169}}
		if !reflect.DeepEqual(records, expected) {
			t.Fatalf("expected %+v, got %+v", expected, records)
		}
	})

	t.Run("one invalid line rejects the list and names the line", func(t *testing.T) {
		data := "AS13335 # Cloudflare\n# comment\n\nAS0 # typo\nAS15169\n"
		records, err := ParseASNList([]byte(data), nil, ptr(x4bnetRegex))
		if err == nil || records != nil {
			t.Fatalf("expected the list to be rejected, got %+v, %v", records, err)
		}
		if !strings.Contains(err.Error(), "line 4:") {
			t.Fatalf("expected line 4 in error, got %v", err)
		}
	})

	t.Run("anchored regex skips commented out lines", func(t *testing.T) {
		data := "# AS45090 removed\n  // AS3223\nAS13335\n"
		unanchored, err := ParseASNList([]byte(data), nil, ptr(`AS(?P<asn>[0-9]+)`))
		if err != nil || len(unanchored) != 3 {
			t.Fatalf("expected the unanchored regex to match commented out lines, got %+v, %v", unanchored, err)
		}
		anchored, err := ParseASNList([]byte(data), nil, ptr(`(?m)^[ \t]*AS(?P<asn>[0-9]+)`))
		if err != nil || !reflect.DeepEqual(anchored, []ASNRecord{{ASN: 13335}}) {
			t.Fatalf("expected only AS13335, got %+v, %v", anchored, err)
		}
	})

	t.Run("invalid jq output names its position", func(t *testing.T) {
		_, err := ParseASNList([]byte(`[13335, 15169, "ASx"]`), ptr(".[]"), nil)
		if err == nil || !strings.Contains(err.Error(), "jq-path output 3:") {
			t.Fatalf("expected jq-path output 3 in error, got %v", err)
		}
	})

	t.Run("jq invalid values", func(t *testing.T) {
		for _, data := range []string{`[1.5]`, `[true]`, `[0]`, `[4294967296]`, `["ASfoo"]`, `[{"asn": 1, "comment": 2}]`} {
			if _, err := ParseASNList([]byte(data), ptr(".[]"), nil); err == nil {
				t.Errorf("expected error for %s", data)
			}
		}
	})
}

func TestASNEntryValidate(t *testing.T) {
	valid := []ASNEntry{
		{ASN: ptr(13335)},
		{ASN: ptr(13335), Comment: "Cloudflare", LookupMethod: LookupMethodMaxMind},
		{Url: ptr("https://example.com/asn.txt"), Regex: ptr(x4bnetRegex), LookupMethod: LookupMethodMaxMind},
		{File: ptr("/tmp/asn.json"), JqPath: ptr(".[]"), LookupMethod: LookupMethodMaxMind},
		{Url: ptr("https://example.com/asn.txt"), Regex: ptr(x4bnetRegex), Refresh: MinRefresh, LookupMethod: LookupMethodMaxMind},
		{Url: ptr("https://example.com/asn.txt"), Regex: ptr(x4bnetRegex), Refresh: time.Hour, RefreshJitter: ptr(time.Duration(0)), LookupMethod: LookupMethodMaxMind},
		{Url: ptr("https://example.com/asn.txt"), Regex: ptr(x4bnetRegex), Refresh: time.Hour, RefreshJitter: ptr(30 * time.Minute), LookupMethod: LookupMethodMaxMind},
	}
	for _, e := range valid {
		if err := e.Validate(); err != nil {
			t.Errorf("%s: unexpected error: %v", e.Source(), err)
		}
	}

	invalid := map[string]ASNEntry{
		"no source":              {},
		"multiple sources":       {ASN: ptr(1), Url: ptr("https://example.com")},
		"unknown method":         {ASN: ptr(1), LookupMethod: "maxmnd"},
		"asn out of range":       {ASN: ptr(0)},
		"regex on single asn":    {ASN: ptr(1), Regex: ptr("(?P<asn>.*)")},
		"list via radb":          {Url: ptr("https://example.com"), Regex: ptr(x4bnetRegex)},
		"list with comment":      {File: ptr("/tmp/asn.txt"), Regex: ptr(x4bnetRegex), Comment: "x", LookupMethod: LookupMethodMaxMind},
		"list without filter":    {File: ptr("/tmp/asn.txt"), LookupMethod: LookupMethodMaxMind},
		"refresh on file":        {File: ptr("/tmp/asn.txt"), Regex: ptr(x4bnetRegex), Refresh: time.Hour, LookupMethod: LookupMethodMaxMind},
		"refresh on asn":         {ASN: ptr(1), Refresh: time.Hour},
		"refresh too short":      {Url: ptr("https://example.com"), Regex: ptr(x4bnetRegex), Refresh: MinRefresh - time.Second, LookupMethod: LookupMethodMaxMind},
		"jitter without refresh": {Url: ptr("https://example.com"), Regex: ptr(x4bnetRegex), RefreshJitter: ptr(time.Minute), LookupMethod: LookupMethodMaxMind},
		"jitter over half":       {Url: ptr("https://example.com"), Regex: ptr(x4bnetRegex), Refresh: time.Hour, RefreshJitter: ptr(31 * time.Minute), LookupMethod: LookupMethodMaxMind},
		"negative jitter":        {Url: ptr("https://example.com"), Regex: ptr(x4bnetRegex), Refresh: time.Hour, RefreshJitter: ptr(-time.Minute), LookupMethod: LookupMethodMaxMind},
		"jq and regex":           {File: ptr("/tmp/asn.txt"), JqPath: ptr("."), Regex: ptr("(?P<asn>.*)"), LookupMethod: LookupMethodMaxMind},
	}
	for name, e := range invalid {
		if err := e.Validate(); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestNetworkValidate(t *testing.T) {
	valid := []Network{
		{Prefixes: []string{"10.0.0.0/8"}},
		{File: ptr("/tmp/networks.txt"), Regex: ptr("(?P<prefix>.*)")},
		{Url: ptr("https://example.com"), Regex: ptr("(?P<prefix>.*)"), Refresh: time.Hour},
	}
	for i, n := range valid {
		if err := n.Validate(); err != nil {
			t.Errorf("valid network %d: unexpected error: %v", i, err)
		}
	}

	invalid := map[string]Network{
		"refresh on file":     {File: ptr("/tmp/networks.txt"), Regex: ptr("(?P<prefix>.*)"), Refresh: time.Hour},
		"refresh on prefixes": {Prefixes: []string{"10.0.0.0/8"}, Refresh: time.Hour},
		"refresh too short":   {Url: ptr("https://example.com"), Regex: ptr("(?P<prefix>.*)"), Refresh: time.Minute},
		"jitter over half":    {Url: ptr("https://example.com"), Regex: ptr("(?P<prefix>.*)"), Refresh: time.Hour, RefreshJitter: ptr(time.Hour)},
	}
	for name, n := range invalid {
		if err := n.Validate(); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestPolicyListEntriesYAML(t *testing.T) {
	data := `
networks:
  googlebot:
    - url: https://developers.google.com/static/search/apis/ipranges/googlebot.json
      jq-path: '.prefixes[].ipv4Prefix'
      refresh: 6h
      refresh-jitter: 0s
asns:
  datacenters:
    - url: https://raw.githubusercontent.com/X4BNet/lists_vpn/refs/heads/main/input/datacenter/ASN.txt
      regex: '(?im)^[ \t]*(?:AS)?(?P<asn>[0-9]+)'
      refresh: 12h
      refresh-jitter: 1h
      lookup_method: maxmind
    - file: /etc/go-away/asns.json
      jq-path: '.[] | {asn: .number, comment: .name}'
      lookup_method: maxmind
    - asn: 136907
      comment: Huawei Cloud
`
	p, err := NewPolicy(strings.NewReader(data))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	network := p.Networks["googlebot"][0]
	if network.Refresh != 6*time.Hour || network.RefreshJitter == nil || *network.RefreshJitter != 0 || network.Validate() != nil {
		t.Fatalf("unexpected network %+v", network)
	}

	entries := p.ASNs["datacenters"]
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	for i, e := range entries {
		if err := e.Validate(); err != nil {
			t.Errorf("entry %d: unexpected error: %v", i, err)
		}
	}
	if entries[0].Refresh != 12*time.Hour || EffectiveRefreshJitter(entries[0].Refresh, entries[0].RefreshJitter) != time.Hour || entries[0].Regex == nil {
		t.Errorf("unexpected url entry %+v", entries[0])
	}
	if entries[1].File == nil || entries[1].JqPath == nil || entries[1].Refresh != 0 {
		t.Errorf("unexpected file entry %+v", entries[1])
	}
	if entries[2].ASN == nil || *entries[2].ASN != 136907 || entries[2].Comment != "Huawei Cloud" || entries[2].LookupMethod != LookupMethodRADb {
		t.Errorf("unexpected asn entry %+v", entries[2])
	}
}

func TestEffectiveRefreshJitter(t *testing.T) {
	zero, custom := time.Duration(0), 20*time.Minute
	for _, c := range []struct {
		jitter   *time.Duration
		expected time.Duration
	}{{nil, 6 * time.Minute}, {&zero, 0}, {&custom, custom}} {
		if got := EffectiveRefreshJitter(time.Hour, c.jitter); got != c.expected {
			t.Errorf("expected jitter %s, got %s", c.expected, got)
		}
	}
}

func TestASNEntryResolve(t *testing.T) {
	t.Run("single asn", func(t *testing.T) {
		records, err := ASNEntry{ASN: ptr(13335), Comment: "Cloudflare"}.Resolve(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := []ASNRecord{{ASN: 13335, Comment: "Cloudflare"}}
		if !reflect.DeepEqual(records, expected) {
			t.Fatalf("expected %+v, got %+v", expected, records)
		}
	})

	t.Run("file", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "asn.txt")
		if err := os.WriteFile(file, []byte("AS13335 # Cloudflare\nAS15169\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		records, err := ASNEntry{File: &file, Regex: ptr(x4bnetRegex), LookupMethod: LookupMethodMaxMind}.Resolve(&http.Client{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := []ASNRecord{{ASN: 13335, Comment: "Cloudflare"}, {ASN: 15169}}
		if !reflect.DeepEqual(records, expected) {
			t.Fatalf("expected %+v, got %+v", expected, records)
		}
	})

	t.Run("missing file", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "missing.txt")
		if _, err := (ASNEntry{File: &file, Regex: ptr(x4bnetRegex), LookupMethod: LookupMethodMaxMind}).Resolve(&http.Client{}); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestASNEntryResolveGarbage(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	binary := make([]byte, 64*1024)
	for i := range binary {
		binary[i] = byte(rng.UintN(256))
	}
	html := []byte("<!DOCTYPE html><html><body><h1>502 Bad Gateway</h1><p>cloudflare</p></body></html>")

	cases := []struct {
		name    string
		body    []byte
		jqPath  *string
		regex   *string
		wantErr bool
	}{
		{name: "html page via regex", body: html, regex: ptr(x4bnetRegex)},
		{name: "html page via jq", body: html, jqPath: ptr(".[]"), wantErr: true},
		{name: "binary via jq", body: binary, jqPath: ptr(".[]"), wantErr: true},
		{name: "empty via regex", body: nil, regex: ptr(x4bnetRegex)},
		{name: "empty via jq", body: nil, jqPath: ptr(".[]"), wantErr: true},
		{name: "truncated json", body: []byte(`[13335, 151`), jqPath: ptr(".[]"), wantErr: true},
		{name: "json of wrong shape", body: []byte(`{"foo": "bar"}`), jqPath: ptr(".asns[]"), wantErr: true},
		{name: "json objects without asn", body: []byte(`[{"name": "x"}]`), jqPath: ptr(".[]"), wantErr: true},
		{name: "asn overflow via regex", body: []byte("AS99999999999999999999\n"), regex: ptr(x4bnetRegex), wantErr: true},
		{name: "asn zero via regex", body: []byte("AS0\n"), regex: ptr(x4bnetRegex), wantErr: true},
	}

	check := func(t *testing.T, records []ASNRecord, err error, wantErr bool) {
		t.Helper()
		if wantErr {
			if err == nil {
				t.Fatalf("expected error, got %+v", records)
			}
			if records != nil {
				t.Fatalf("expected no records on error, got %+v", records)
			}
			return
		}
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(records) != 0 {
			t.Fatalf("expected no records, got %+v", records)
		}
	}

	for _, c := range cases {
		t.Run("file "+c.name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "list")
			if err := os.WriteFile(file, c.body, 0o644); err != nil {
				t.Fatal(err)
			}
			records, err := ASNEntry{File: &file, JqPath: c.jqPath, Regex: c.regex, LookupMethod: LookupMethodMaxMind}.Resolve(&http.Client{})
			check(t, records, err, c.wantErr)
		})

		t.Run("url "+c.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write(c.body)
			}))
			defer server.Close()
			records, err := ASNEntry{Url: &server.URL, JqPath: c.jqPath, Regex: c.regex, LookupMethod: LookupMethodMaxMind}.Resolve(server.Client())
			check(t, records, err, c.wantErr)
		})
	}

	t.Run("binary via regex", func(t *testing.T) {
		// random bytes can contain lines that look like ASNs, all that matters is no panic and only valid ASNs
		records, err := ParseASNList(binary, nil, ptr(`(?m)^(?P<asn>[0-9]{1,9})$`))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		for _, r := range records {
			if r.ASN == 0 {
				t.Fatalf("invalid record %+v", r)
			}
		}
	})

	for _, status := range []int{http.StatusNotFound, http.StatusInternalServerError, http.StatusFound} {
		t.Run("url status "+http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "/elsewhere")
				w.WriteHeader(status)
				_, _ = w.Write([]byte("AS13335\n"))
			}))
			defer server.Close()
			// a client that does not follow redirects hands the 3xx response itself to readSource
			client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			}}
			_, err := ASNEntry{Url: &server.URL, Regex: ptr(x4bnetRegex), LookupMethod: LookupMethodMaxMind}.Resolve(client)
			if err == nil || !strings.Contains(err.Error(), "unexpected status code") {
				t.Fatalf("expected status code error, got %v", err)
			}
		})
	}

	t.Run("oversized list", func(t *testing.T) {
		big := make([]byte, MaxListSize+1)
		for i := range big {
			big[i] = '\n'
		}
		file := filepath.Join(t.TempDir(), "big.txt")
		if err := os.WriteFile(file, big, 0o644); err != nil {
			t.Fatal(err)
		}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(big)
		}))
		defer server.Close()

		for _, e := range []ASNEntry{
			{File: &file, Regex: ptr(x4bnetRegex), LookupMethod: LookupMethodMaxMind},
			{Url: &server.URL, Regex: ptr(x4bnetRegex), LookupMethod: LookupMethodMaxMind},
		} {
			if _, err := e.Resolve(server.Client()); err == nil || !strings.Contains(err.Error(), "larger than") {
				t.Fatalf("%s: expected size error, got %v", e.Source(), err)
			}
		}
	})

	t.Run("list at size limit", func(t *testing.T) {
		data := make([]byte, MaxListSize)
		copy(data, "AS13335\n")
		for i := len("AS13335\n"); i < len(data); i++ {
			data[i] = '\n'
		}
		file := filepath.Join(t.TempDir(), "max.txt")
		if err := os.WriteFile(file, data, 0o644); err != nil {
			t.Fatal(err)
		}
		records, err := ASNEntry{File: &file, Regex: ptr(x4bnetRegex), LookupMethod: LookupMethodMaxMind}.Resolve(&http.Client{})
		if err != nil || len(records) != 1 {
			t.Fatalf("expected 1 record, got %+v, %v", records, err)
		}
	})

	t.Run("unreachable url", func(t *testing.T) {
		server := httptest.NewServer(http.NotFoundHandler())
		url := server.URL
		server.Close()
		if _, err := (ASNEntry{Url: &url, Regex: ptr(x4bnetRegex), LookupMethod: LookupMethodMaxMind}).Resolve(&http.Client{}); err == nil {
			t.Fatal("expected error")
		}
	})
}

func FuzzParseASNList(f *testing.F) {
	f.Add([]byte("AS45090 # Tencent\nAS3223\n"))
	f.Add([]byte(`[13335, "AS15169", {"asn": 1, "comment": "x"}]`))
	f.Add([]byte("\x00\xff<html>"))
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, parse := range []func() ([]ASNRecord, error){
			func() ([]ASNRecord, error) { return ParseASNList(data, nil, ptr(x4bnetRegex)) },
			func() ([]ASNRecord, error) { return ParseASNList(data, ptr(".[]"), nil) },
		} {
			records, err := parse()
			if err != nil {
				continue
			}
			for _, r := range records {
				if r.ASN == 0 || r.ASN > 4294967295 {
					t.Fatalf("invalid record %+v", r)
				}
			}
		}
	})
}
