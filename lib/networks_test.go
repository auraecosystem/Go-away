package lib

import (
	"bytes"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"git.gammaspectra.live/git/go-away/lib/policy"
	"git.gammaspectra.live/git/go-away/utils"
)

func TestAsnMatcherLogging(t *testing.T) {
	mmdb := createTestASNMMDB(t)
	m := &asnMatcher{name: "test-group", asns: map[uint]string{13335: "Cloudflare"}, maxMindASNDB: mmdb}

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
		if !strings.Contains(out, "asn-comment=Cloudflare") {
			t.Fatalf("expected asn-comment in log, got: %s", out)
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

// syncBuffer is a log sink that is safe to read while watcher goroutines write to it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func captureLogs(t *testing.T) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return buf
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func newTestNetworkState(t *testing.T) *State {
	t.Helper()
	state := &State{listClient: newListClient(listFetchTimeout), maxMindASNDB: createTestASNMMDB(t), close: make(chan struct{})}
	t.Cleanup(func() { close(state.close) })
	return state
}

func loadNetwork(t *testing.T, state *State, p policy.Policy, name string) networkMatcher {
	t.Helper()
	if err := state.initNetworks(p); err != nil {
		t.Fatalf("initNetworks: %v", err)
	}
	return state.networks[name]()
}

func asnsOf(t *testing.T, m networkMatcher) map[uint]string {
	t.Helper()
	g, ok := m.(*listGroup[policy.ASNRecord])
	if !ok {
		t.Fatalf("expected an ASN list group, got %T", m)
	}
	return g.current.Load().networkMatcher.(*asnMatcher).asns
}

func writeFile(t *testing.T, file, content string, modTime time.Time) {
	t.Helper()
	if err := os.WriteFile(file, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(file, modTime, modTime); err != nil {
		t.Fatal(err)
	}
}

func setFileWatchInterval(t *testing.T, interval time.Duration) {
	prev := fileWatchInterval
	fileWatchInterval = interval
	t.Cleanup(func() { fileWatchInterval = prev })
}

const testASNRegex = `(?m)^AS(?P<asn>[0-9]+)(?: # (?P<comment>.*))?$`
const testPrefixRegex = `(?m)^(?P<prefix>[0-9./]+)$`

func TestInitNetworksASNGroups(t *testing.T) {
	regex := testASNRegex
	asnPolicy := func(entries ...policy.ASNEntry) policy.Policy {
		return policy.Policy{ASNs: map[string][]policy.ASNEntry{"test-group": entries}}
	}

	t.Run("file list and single asn", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "asn.txt")
		writeFile(t, file, "AS15169 # Google\nAS13335\n", time.Now())
		asn := 13335
		m := loadNetwork(t, newTestNetworkState(t), asnPolicy(
			policy.ASNEntry{File: &file, Regex: &regex, LookupMethod: policy.LookupMethodMaxMind},
			policy.ASNEntry{ASN: &asn, Comment: "Cloudflare", LookupMethod: policy.LookupMethodMaxMind},
		), "test-group")

		expected := map[uint]string{15169: "Google", 13335: "Cloudflare"}
		if got := asnsOf(t, m); !reflect.DeepEqual(got, expected) {
			t.Fatalf("expected %v, got %v", expected, got)
		}
		for _, ip := range []net.IP{{1, 0, 0, 1}, {3, 0, 0, 1}} {
			if ok, err := m.Contains(ip); err != nil || !ok {
				t.Fatalf("expected %s to match: ok=%v err=%v", ip, ok, err)
			}
		}
	})

	t.Run("garbage list does not affect other entries", func(t *testing.T) {
		buf := captureLogs(t)
		file := filepath.Join(t.TempDir(), "asn.json")
		writeFile(t, file, "<html>502 Bad Gateway</html>", time.Now())
		jqPath := ".[]"
		asn := 13335
		m := loadNetwork(t, newTestNetworkState(t), asnPolicy(
			policy.ASNEntry{File: &file, JqPath: &jqPath, LookupMethod: policy.LookupMethodMaxMind},
			policy.ASNEntry{ASN: &asn, LookupMethod: policy.LookupMethodMaxMind},
		), "test-group")

		if got := asnsOf(t, m); !reflect.DeepEqual(got, map[uint]string{13335: ""}) {
			t.Fatalf("expected only AS13335, got %v", got)
		}
		if !strings.Contains(buf.String(), "FAILED TO LOAD LIST") {
			t.Fatalf("expected load failure error, got: %s", buf.String())
		}
	})

	t.Run("list without matches warns", func(t *testing.T) {
		buf := captureLogs(t)
		file := filepath.Join(t.TempDir(), "asn.txt")
		writeFile(t, file, "<html>502 Bad Gateway</html>", time.Now())
		loadNetwork(t, newTestNetworkState(t), asnPolicy(
			policy.ASNEntry{File: &file, Regex: &regex, LookupMethod: policy.LookupMethodMaxMind},
		), "test-group")

		out := buf.String()
		if !strings.Contains(out, "list has no entries") || !strings.Contains(out, "ASN GROUP HAS NO ASNS LOADED") {
			t.Fatalf("expected empty list warnings, got: %s", out)
		}
	})

	t.Run("invalid line rejects the list loudly", func(t *testing.T) {
		buf := captureLogs(t)
		file := filepath.Join(t.TempDir(), "asn.txt")
		writeFile(t, file, "AS13335\nAS0\n", time.Now())
		m := loadNetwork(t, newTestNetworkState(t), asnPolicy(
			policy.ASNEntry{File: &file, Regex: &regex, LookupMethod: policy.LookupMethodMaxMind},
		), "test-group")

		if got := asnsOf(t, m); len(got) != 0 {
			t.Fatalf("expected no ASNs, got %v", got)
		}
		out := buf.String()
		if !strings.Contains(out, "FAILED TO LOAD LIST") || !strings.Contains(out, "line 2: ASN 0 out of range") {
			t.Fatalf("expected load failure naming the line, got: %s", out)
		}
	})

	t.Run("missing file logs loudly", func(t *testing.T) {
		buf := captureLogs(t)
		file := filepath.Join(t.TempDir(), "missing.txt")
		m := loadNetwork(t, newTestNetworkState(t), asnPolicy(
			policy.ASNEntry{File: &file, Regex: &regex, LookupMethod: policy.LookupMethodMaxMind},
		), "test-group")

		if got := asnsOf(t, m); len(got) != 0 {
			t.Fatalf("expected no ASNs, got %v", got)
		}
		out := buf.String()
		if !strings.Contains(out, "FAILED TO LOAD LIST") || !strings.Contains(out, "ASN GROUP HAS NO ASNS LOADED") {
			t.Fatalf("expected load failure errors, got: %s", out)
		}
	})

	t.Run("invalid entries fail at startup", func(t *testing.T) {
		file := "/tmp/asn.txt"
		url := "https://example.com/asn.txt"
		asn := 13335
		invalid := map[string]policy.Policy{
			"refresh on file":   asnPolicy(policy.ASNEntry{File: &file, Regex: &regex, Refresh: time.Hour, LookupMethod: policy.LookupMethodMaxMind}),
			"refresh too short": asnPolicy(policy.ASNEntry{Url: &url, Regex: &regex, Refresh: time.Minute, LookupMethod: policy.LookupMethodMaxMind}),
			"refresh on asn":    asnPolicy(policy.ASNEntry{ASN: &asn, Refresh: time.Hour}),
			"network refresh on file": {Networks: map[string][]policy.Network{
				"test-network": {{File: &file, Regex: &regex, Refresh: time.Hour}},
			}},
		}
		for name, p := range invalid {
			if err := newTestNetworkState(t).initNetworks(p); err == nil {
				t.Errorf("%s: expected error", name)
			}
		}

		state := newTestNetworkState(t)
		state.maxMindASNDB = nil
		if err := state.initNetworks(asnPolicy(policy.ASNEntry{ASN: &asn, LookupMethod: policy.LookupMethodMaxMind})); err == nil || !strings.Contains(err.Error(), "requires MaxMind ASN database") {
			t.Errorf("expected missing MaxMind ASN database error, got %v", err)
		}
	})
}

func TestASNComment(t *testing.T) {
	regex := testASNRegex
	file := filepath.Join(t.TempDir(), "asn.txt")
	writeFile(t, file, "AS15169 # Google\nAS64496 # From list\n", time.Now())
	cloudflare, example := 13335, 64496

	state := newTestNetworkState(t)
	err := state.initNetworks(policy.Policy{ASNs: map[string][]policy.ASNEntry{
		// RADb entries are never loaded here, their comments come from the policy itself
		"b-radb": {{ASN: &cloudflare, Comment: "Cloudflare B"}, {ASN: &example}},
		"a-radb": {{ASN: &cloudflare, Comment: "Cloudflare A"}},
		"c-list": {{File: &file, Regex: &regex, LookupMethod: policy.LookupMethodMaxMind}},
	}})
	if err != nil {
		t.Fatalf("initNetworks: %v", err)
	}

	check := func(asn uint, want string) {
		t.Helper()
		if got := state.ASNComment(asn); got != want {
			t.Fatalf("AS%d: comment %q, want %q", asn, got, want)
		}
	}

	check(13335, "Cloudflare A")
	// lists only count once their group is loaded
	check(15169, "")
	state.networks["c-list"]()
	check(15169, "Google")
	// an empty comment in an earlier group does not hide a later one
	check(64496, "From list")
	check(1, "")
}

// valuesMatcher exposes the values a test listGroup was built from.
type valuesMatcher []string

func (valuesMatcher) Contains(net.IP) (bool, error) {
	return false, nil
}

var stringCodec = listCodec[string]{
	encode: func(s string) string { return s },
	decode: func(s string) (string, error) { return s, nil },
}

func newTestGroup(t *testing.T, sources ...*listSource[string]) (*listGroup[string], string) {
	t.Helper()
	dir := t.TempDir()
	cache, err := utils.CacheDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	return &listGroup[string]{
		kind:    "network",
		name:    "test",
		sources: sources,
		cache:   cache,
		codec:   stringCodec,
		build:   func(values []string) networkMatcher { return valuesMatcher(values) },
	}, dir
}

func (g *listGroup[T]) values() valuesMatcher {
	return g.current.Load().networkMatcher.(valuesMatcher)
}

func fetched(values ...string) func() ([]string, error) {
	return func() ([]string, error) { return values, nil }
}

func failing() ([]string, error) {
	return nil, errors.New("fetch failed")
}

func ageFile(t *testing.T, file string, age time.Duration) {
	t.Helper()
	old := time.Now().Add(-age)
	if err := os.Chtimes(file, old, old); err != nil {
		t.Fatal(err)
	}
}

func TestListGroupCache(t *testing.T) {
	t.Run("initial load uses fresh cache without fetching", func(t *testing.T) {
		s := &listSource[string]{name: "src", cacheKey: "key", fetch: fetched("a", "b")}
		g, _ := newTestGroup(t, s)
		if _, err := g.load(s, true); err != nil {
			t.Fatal(err)
		}
		s.fetch = failing
		values, err := g.load(s, true)
		if err != nil || !reflect.DeepEqual(values, []string{"a", "b"}) {
			t.Fatalf("expected fresh cached values, got %v, %v", values, err)
		}
	})

	t.Run("initial load refetches expired cache", func(t *testing.T) {
		s := &listSource[string]{name: "src", cacheKey: "key", fetch: fetched("old")}
		g, dir := newTestGroup(t, s)
		if _, err := g.load(s, true); err != nil {
			t.Fatal(err)
		}
		ageFile(t, filepath.Join(dir, "key"), 27*time.Hour)
		s.fetch = fetched("new")
		values, err := g.load(s, true)
		if err != nil || !reflect.DeepEqual(values, []string{"new"}) {
			t.Fatalf("expected refetched values, got %v, %v", values, err)
		}
	})

	t.Run("cache younger than the jittered max age is fresh", func(t *testing.T) {
		s := &listSource[string]{name: "src", cacheKey: "key", fetch: fetched("cached")}
		g, dir := newTestGroup(t, s)
		if _, err := g.load(s, true); err != nil {
			t.Fatal(err)
		}
		ageFile(t, filepath.Join(dir, "key"), 21*time.Hour)
		s.fetch = failing
		values, err := g.load(s, true)
		if err != nil || !reflect.DeepEqual(values, []string{"cached"}) {
			t.Fatalf("expected fresh cached values, got %v, %v", values, err)
		}
	})

	t.Run("cache expires after the refresh interval if shorter", func(t *testing.T) {
		s := &listSource[string]{name: "src", cacheKey: "key", interval: time.Hour, fetch: fetched("old")}
		g, dir := newTestGroup(t, s)
		if _, err := g.load(s, true); err != nil {
			t.Fatal(err)
		}
		ageFile(t, filepath.Join(dir, "key"), 2*time.Hour)
		s.fetch = fetched("new")
		values, err := g.load(s, true)
		if err != nil || !reflect.DeepEqual(values, []string{"new"}) {
			t.Fatalf("expected refetched values, got %v, %v", values, err)
		}
	})

	t.Run("stale cache fallback logs loudly", func(t *testing.T) {
		buf := captureLogs(t)
		s := &listSource[string]{name: "src", cacheKey: "key", fetch: fetched("stale")}
		g, dir := newTestGroup(t, s)
		if _, err := g.load(s, true); err != nil {
			t.Fatal(err)
		}
		ageFile(t, filepath.Join(dir, "key"), 27*time.Hour)
		s.fetch = failing
		g.start(nil)
		if got := g.values(); !reflect.DeepEqual(got, valuesMatcher{"stale"}) {
			t.Fatalf("expected stale values, got %v", got)
		}
		if !strings.Contains(buf.String(), "FAILED TO FETCH LIST, USING STALE CACHED COPY") {
			t.Fatalf("expected stale fallback error, got: %s", buf.String())
		}
	})

	t.Run("initial load returns stale cache on fetch failure", func(t *testing.T) {
		s := &listSource[string]{name: "src", cacheKey: "key", fetch: fetched("stale")}
		g, dir := newTestGroup(t, s)
		if _, err := g.load(s, true); err != nil {
			t.Fatal(err)
		}
		ageFile(t, filepath.Join(dir, "key"), 27*time.Hour)
		s.fetch = failing
		values, err := g.load(s, true)
		if err == nil || !reflect.DeepEqual(values, []string{"stale"}) {
			t.Fatalf("expected stale values with error, got %v, %v", values, err)
		}
	})

	t.Run("refresh ignores fresh cache and rewrites it", func(t *testing.T) {
		s := &listSource[string]{name: "src", cacheKey: "key", fetch: fetched("old")}
		g, dir := newTestGroup(t, s)
		if _, err := g.load(s, true); err != nil {
			t.Fatal(err)
		}
		s.fetch = fetched("new")
		values, err := g.load(s, false)
		if err != nil || !reflect.DeepEqual(values, []string{"new"}) {
			t.Fatalf("expected refreshed values, got %v, %v", values, err)
		}
		data, err := os.ReadFile(filepath.Join(dir, "key"))
		if err != nil || string(data) != `["new"]` {
			t.Fatalf("expected rewritten cache, got %s, %v", data, err)
		}
	})

	t.Run("failed refresh keeps cache", func(t *testing.T) {
		s := &listSource[string]{name: "src", cacheKey: "key", fetch: fetched("old")}
		g, dir := newTestGroup(t, s)
		if _, err := g.load(s, true); err != nil {
			t.Fatal(err)
		}
		s.fetch = failing
		if values, err := g.load(s, false); err == nil || values != nil {
			t.Fatalf("expected error without values, got %v, %v", values, err)
		}
		data, err := os.ReadFile(filepath.Join(dir, "key"))
		if err != nil || string(data) != `["old"]` {
			t.Fatalf("expected untouched cache, got %s, %v", data, err)
		}
	})

	t.Run("empty key skips cache", func(t *testing.T) {
		s := &listSource[string]{name: "src", fetch: fetched("a")}
		g, dir := newTestGroup(t, s)
		if _, err := g.load(s, true); err != nil {
			t.Fatal(err)
		}
		if entries, _ := os.ReadDir(dir); len(entries) != 0 {
			t.Fatalf("expected empty cache, got %d entries", len(entries))
		}
	})
}

func TestListGroupReload(t *testing.T) {
	t.Run("url refresh swaps values and rewrites cache", func(t *testing.T) {
		var mu sync.Mutex
		current := []string{"v1"}
		s := &listSource[string]{name: "src", cacheKey: "key", interval: 10 * time.Millisecond, fetch: func() ([]string, error) {
			mu.Lock()
			defer mu.Unlock()
			return current, nil
		}}
		g, dir := newTestGroup(t, s)
		closed := make(chan struct{})
		g.start(closed)
		defer func() { close(closed); g.watchers.Wait() }()

		if got := g.values(); !reflect.DeepEqual(got, valuesMatcher{"v1"}) {
			t.Fatalf("expected v1, got %v", got)
		}
		mu.Lock()
		current = []string{"v2", "v3"}
		mu.Unlock()
		waitFor(t, "refreshed values", func() bool { return reflect.DeepEqual(g.values(), valuesMatcher{"v2", "v3"}) })
		waitFor(t, "rewritten cache", func() bool {
			data, _ := os.ReadFile(filepath.Join(dir, "key"))
			return string(data) == `["v2","v3"]`
		})
	})

	t.Run("failed refresh keeps previous values and logs loudly", func(t *testing.T) {
		buf := captureLogs(t)
		var calls atomic.Int32
		s := &listSource[string]{name: "src", interval: 10 * time.Millisecond, fetch: func() ([]string, error) {
			if calls.Add(1) == 1 {
				return []string{"good"}, nil
			}
			return nil, errors.New("upstream down")
		}}
		static := &listSource[string]{name: "static", fetch: fetched("static")}
		g, _ := newTestGroup(t, s, static)
		closed := make(chan struct{})
		g.start(closed)

		waitFor(t, "failed refreshes", func() bool { return calls.Load() >= 3 })
		close(closed)
		g.watchers.Wait()

		if got := g.values(); !reflect.DeepEqual(got, valuesMatcher{"good", "static"}) {
			t.Fatalf("expected previous values, got %v", got)
		}
		if out := buf.String(); !strings.Contains(out, "FAILED TO RELOAD LIST, KEEPING ITS PREVIOUS ENTRIES") || !strings.Contains(out, "upstream down") {
			t.Fatalf("expected reload failure error, got: %s", out)
		}
	})

	t.Run("close stops watchers", func(t *testing.T) {
		var calls atomic.Int32
		s := &listSource[string]{name: "src", interval: 5 * time.Millisecond, fetch: func() ([]string, error) {
			calls.Add(1)
			return []string{"a"}, nil
		}}
		g, _ := newTestGroup(t, s)
		closed := make(chan struct{})
		g.start(closed)
		waitFor(t, "a refresh", func() bool { return calls.Load() >= 2 })
		close(closed)
		g.watchers.Wait()

		after := calls.Load()
		time.Sleep(50 * time.Millisecond)
		if calls.Load() != after {
			t.Fatal("source refreshed after close")
		}
	})
}

func TestNetworkFileWatch(t *testing.T) {
	setFileWatchInterval(t, 10*time.Millisecond)

	t.Run("network file", func(t *testing.T) {
		regex := testPrefixRegex
		file := filepath.Join(t.TempDir(), "networks.txt")
		start := time.Now().Add(-time.Hour)
		writeFile(t, file, "10.0.0.0/8\n", start)
		m := loadNetwork(t, newTestNetworkState(t), policy.Policy{Networks: map[string][]policy.Network{
			"test-network": {{File: &file, Regex: &regex}},
		}}, "test-network")

		contains := func(ip net.IP) bool {
			ok, err := m.Contains(ip)
			return err == nil && ok
		}
		if !contains(net.IP{10, 1, 2, 3}) || contains(net.IP{192, 168, 1, 1}) {
			t.Fatal("unexpected initial matches")
		}

		writeFile(t, file, "192.168.0.0/16\n", start.Add(time.Minute))
		waitFor(t, "reloaded network file", func() bool { return contains(net.IP{192, 168, 1, 1}) && !contains(net.IP{10, 1, 2, 3}) })
	})

	t.Run("asn file", func(t *testing.T) {
		buf := captureLogs(t)
		regex := testASNRegex
		file := filepath.Join(t.TempDir(), "asn.txt")
		start := time.Now().Add(-time.Hour)
		writeFile(t, file, "AS13335 # Cloudflare\n", start)
		m := loadNetwork(t, newTestNetworkState(t), policy.Policy{ASNs: map[string][]policy.ASNEntry{
			"test-group": {{File: &file, Regex: &regex, LookupMethod: policy.LookupMethodMaxMind}},
		}}, "test-group")

		writeFile(t, file, "AS15169 # Google\n", start.Add(time.Minute))
		waitFor(t, "reloaded asn file", func() bool {
			return reflect.DeepEqual(asnsOf(t, m), map[uint]string{15169: "Google"})
		})

		// a deleted file keeps the previous entries, and is picked up again once it is back
		if err := os.Remove(file); err != nil {
			t.Fatal(err)
		}
		waitFor(t, "reload failure", func() bool { return strings.Contains(buf.String(), "FAILED TO RELOAD LIST") })
		if got := asnsOf(t, m); !reflect.DeepEqual(got, map[uint]string{15169: "Google"}) {
			t.Fatalf("expected previous ASNs, got %v", got)
		}
		writeFile(t, file, "AS13335 # Cloudflare\n", start.Add(2*time.Minute))
		waitFor(t, "restored asn file", func() bool {
			return reflect.DeepEqual(asnsOf(t, m), map[uint]string{13335: "Cloudflare"})
		})
	})

	t.Run("unchanged file is not reloaded", func(t *testing.T) {
		var calls atomic.Int32
		file := filepath.Join(t.TempDir(), "list.txt")
		writeFile(t, file, "a", time.Now())
		s := &listSource[string]{name: file, file: file, interval: 5 * time.Millisecond, fetch: func() ([]string, error) {
			calls.Add(1)
			return []string{"a"}, nil
		}}
		g, _ := newTestGroup(t, s)
		closed := make(chan struct{})
		g.start(closed)
		time.Sleep(50 * time.Millisecond)
		close(closed)
		g.watchers.Wait()
		if n := calls.Load(); n != 1 {
			t.Fatalf("expected only the initial load, got %d loads", n)
		}
	})
}

func TestASNRecordCacheEncoding(t *testing.T) {
	for _, record := range []policy.ASNRecord{{ASN: 13335}, {ASN: 45090, Comment: "Tencent cloud, they dont monitor"}} {
		decoded, err := decodeASNRecord(encodeASNRecord(record))
		if err != nil || decoded != record {
			t.Fatalf("round trip of %+v gave %+v, %v", record, decoded, err)
		}
	}
	if _, err := decodeASNRecord("0"); err == nil {
		t.Fatal("expected error for ASN 0")
	}
}

func TestListClientTimeout(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// accept the request, then never answer
		<-release
	}))
	defer server.Close()
	defer close(release)

	jqPath := ".[]"
	start := time.Now()
	_, err := policy.ASNEntry{Url: &server.URL, JqPath: &jqPath, LookupMethod: policy.LookupMethodMaxMind}.Resolve(newListClient(100 * time.Millisecond))
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("timeout took too long: %s", elapsed)
	}
}

func TestListClientRedirects(t *testing.T) {
	jqPath := ".[]"
	resolve := func(client *http.Client, url string) ([]policy.ASNRecord, error) {
		return policy.ASNEntry{Url: &url, JqPath: &jqPath, LookupMethod: policy.LookupMethodMaxMind}.Resolve(client)
	}

	t.Run("follows redirects", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.Handle("/a", http.RedirectHandler("/b", http.StatusMovedPermanently))
		mux.Handle("/b", http.RedirectHandler("/list", http.StatusFound))
		mux.HandleFunc("/list", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`[13335]`))
		})
		server := httptest.NewServer(mux)
		defer server.Close()

		records, err := resolve(newListClient(listFetchTimeout), server.URL+"/a")
		if err != nil || len(records) != 1 || records[0].ASN != 13335 {
			t.Fatalf("expected AS13335, got %+v, %v", records, err)
		}
	})

	t.Run("stops after too many redirects", func(t *testing.T) {
		var hits int
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits++
			http.Redirect(w, r, "/loop", http.StatusFound)
		}))
		defer server.Close()

		_, err := resolve(newListClient(listFetchTimeout), server.URL)
		if err == nil || !strings.Contains(err.Error(), "stopped after 5 redirects") {
			t.Fatalf("expected redirect limit error, got %v", err)
		}
		if hits != listMaxRedirects {
			t.Fatalf("expected %d requests, got %d", listMaxRedirects, hits)
		}
	})

	t.Run("refuses https to http downgrade", func(t *testing.T) {
		var plainHit bool
		plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			plainHit = true
			_, _ = w.Write([]byte(`[13335]`))
		}))
		defer plain.Close()
		secure := httptest.NewTLSServer(http.RedirectHandler(plain.URL, http.StatusFound))
		defer secure.Close()

		client := newListClient(listFetchTimeout)
		client.Transport = secure.Client().Transport
		_, err := resolve(client, secure.URL)
		if err == nil || !strings.Contains(err.Error(), "insecure") {
			t.Fatalf("expected downgrade error, got %v", err)
		}
		if plainHit {
			t.Fatal("insecure target must not be requested")
		}
	})

	t.Run("allows http to https upgrade", func(t *testing.T) {
		secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`[13335]`))
		}))
		defer secure.Close()
		plain := httptest.NewServer(http.RedirectHandler(secure.URL, http.StatusFound))
		defer plain.Close()

		client := newListClient(listFetchTimeout)
		client.Transport = secure.Client().Transport
		if _, err := resolve(client, plain.URL); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestJitter(t *testing.T) {
	if got := jitter(time.Hour, 0); got != time.Hour {
		t.Errorf("jitter without spread = %s, expected unchanged", got)
	}

	d, spread := 6*time.Hour, 30*time.Minute
	seen := make(map[time.Duration]bool)
	for range 1000 {
		got := jitter(d, spread)
		if got < d-spread || got > d+spread {
			t.Fatalf("jitter(%s, %s) = %s, out of range", d, spread, got)
		}
		seen[got] = true
	}
	if len(seen) < 900 {
		t.Fatalf("expected spread values, got only %d distinct", len(seen))
	}
}
