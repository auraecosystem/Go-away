package lib

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"git.gammaspectra.live/git/go-away/lib/policy"
	"git.gammaspectra.live/git/go-away/utils"
	"github.com/yl2chen/cidranger"
)

type networkMatcher interface {
	Contains(ip net.IP) (bool, error)
}

type emptyMatcher struct{}

func (emptyMatcher) Contains(ip net.IP) (bool, error) {
	return false, nil
}

type asnMatcher struct {
	name      string
	asns      map[uint]string
	maxMindDB *utils.MaxMindDB
}

func (m *asnMatcher) Contains(ip net.IP) (bool, error) {
	asn, err := m.maxMindDB.GetASN(ip)
	if err != nil {
		slog.Debug("maxmind ASN lookup failed", "asn-group", m.name, "remoteAddress", ip.String(), "error", err)
		return false, err
	}
	if comment, ok := m.asns[asn]; ok {
		slog.Debug("maxmind ASN lookup matched", "asn-group", m.name, "remoteAddress", ip.String(), "asn", asn, "asn-comment", comment)
		return true, nil
	}
	slog.Debug("maxmind ASN lookup no match", "asn-group", m.name, "remoteAddress", ip.String(), "asn", asn)
	return false, nil
}

// anyMatcher matches if any of its matchers does, checked in order.
type anyMatcher []networkMatcher

func (m anyMatcher) Contains(ip net.IP) (bool, error) {
	for _, matcher := range m {
		ok, err := matcher.Contains(ip)
		if err != nil || ok {
			return ok, err
		}
	}
	return false, nil
}

const (
	// listFetchTimeout bounds a whole list download, including redirects, so a hanging server can't block startup forever
	listFetchTimeout = time.Minute
	listMaxRedirects = 5
	listCacheMaxAge  = 24 * time.Hour
)

// fileWatchInterval is how often watched list files are checked for changes.
var fileWatchInterval = time.Minute

func newListClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= listMaxRedirects {
				return fmt.Errorf("stopped after %d redirects", listMaxRedirects)
			}
			if prev := via[len(via)-1].URL; prev.Scheme == "https" && req.URL.Scheme != "https" {
				return fmt.Errorf("refusing redirect from %s to insecure %s", prev.Redacted(), req.URL.Redacted())
			}
			return nil
		},
	}
}

// initNetworks registers the network and ASN groups. Each group loads on first use, then keeps its refreshing sources up to date until the state is closed.
func (state *State) initNetworks(p policy.Policy) error {
	state.networks = make(map[string]func() networkMatcher)
	cache := utils.CachePrefix(state.Settings().Cache, "networks/")

	for k, network := range p.Networks {
		g := &listGroup[net.IPNet]{
			kind:  "network",
			name:  k,
			cache: cache,
			codec: prefixCodec,
			build: buildPrefixMatcher("network", k, "loaded network prefixes"),
		}
		for i, e := range network {
			if err := e.Validate(); err != nil {
				return fmt.Errorf("network %q entry %d: %w", k, i, err)
			}
			s := &listSource[net.IPNet]{interval: e.Refresh, jitter: policy.EffectiveRefreshJitter(e.Refresh, e.RefreshJitter)}
			switch {
			case e.Url != nil:
				s.name = *e.Url
				sum := sha256.Sum256([]byte(*e.Url))
				s.cacheKey = fmt.Sprintf("%s-%d-%s", k, i, hex.EncodeToString(sum[:4]))
			case e.ASN != nil:
				s.name = "AS" + strconv.Itoa(*e.ASN)
				s.cacheKey = fmt.Sprintf("%s-%d-%d", k, i, *e.ASN)
			case e.File != nil:
				s.name = *e.File
				s.file = *e.File
				s.interval = fileWatchInterval
			default:
				s.name = "prefixes"
			}
			s.fetch = func() ([]net.IPNet, error) {
				slog.Debug("loading network list", "network", k, "source", s.name)
				return e.FetchPrefixes(state.listClient, state.radb)
			}
			g.sources = append(g.sources, s)
		}
		state.networks[k] = sync.OnceValue[networkMatcher](func() networkMatcher {
			return g.start(state.close)
		})
	}

	for k, asnGroup := range p.ASNs {
		if len(asnGroup) == 0 {
			slog.Warn("asn group has no entries", "asn-group", k)
			state.networks[k] = func() networkMatcher { return emptyMatcher{} }
			continue
		}

		radb := &listGroup[net.IPNet]{
			kind:  "asn-group",
			name:  k,
			cache: cache,
			codec: prefixCodec,
			build: buildPrefixMatcher("asn-group", k, "loaded ASN prefixes via RADb"),
		}
		maxmind := &listGroup[policy.ASNRecord]{
			kind:  "asn-group",
			name:  k,
			cache: cache,
			codec: asnRecordCodec,
			build: state.buildASNMatcher(k),
		}
		for i, e := range asnGroup {
			if err := e.Validate(); err != nil {
				return fmt.Errorf("asn group %q entry %d (%s): %w", k, i, e.Source(), err)
			}

			if e.LookupMethod != policy.LookupMethodMaxMind {
				radb.sources = append(radb.sources, &listSource[net.IPNet]{
					name:     e.Source(),
					cacheKey: fmt.Sprintf("asn-%s-%d", k, *e.ASN),
					fetch: func() ([]net.IPNet, error) {
						slog.Debug("loading ASN via RADb", "asn-group", k, "asn", *e.ASN, "asn-comment", e.Comment)
						return e.FetchPrefixes(state.radb)
					},
				})
				continue
			}

			if state.maxMindDB == nil {
				return fmt.Errorf("asn group %q entry %s requires MaxMind database but none is configured", k, e.Source())
			}
			s := &listSource[policy.ASNRecord]{
				name:     e.Source(),
				interval: e.Refresh,
				jitter:   policy.EffectiveRefreshJitter(e.Refresh, e.RefreshJitter),
				fetch: func() ([]policy.ASNRecord, error) {
					if e.IsList() {
						slog.Debug("loading ASN list", "asn-group", k, "source", e.Source())
					}
					return e.Resolve(state.listClient)
				},
			}
			if e.Url != nil {
				sum := sha256.Sum256([]byte(*e.Url))
				s.cacheKey = fmt.Sprintf("asn-list-%s-%s", k, hex.EncodeToString(sum[:4]))
			} else if e.File != nil {
				s.file = *e.File
				s.interval = fileWatchInterval
			}
			maxmind.sources = append(maxmind.sources, s)
		}

		state.networks[k] = sync.OnceValue[networkMatcher](func() networkMatcher {
			// RADb prefixes are checked first, as they need no per-request lookup
			var matchers anyMatcher
			if len(radb.sources) > 0 {
				matchers = append(matchers, radb.start(state.close))
			}
			if len(maxmind.sources) > 0 {
				matchers = append(matchers, maxmind.start(state.close))
			}
			if len(matchers) == 1 {
				return matchers[0]
			}
			return matchers
		})
	}
	return nil
}

func buildPrefixMatcher(kind, name, message string) func([]net.IPNet) networkMatcher {
	return func(prefixes []net.IPNet) networkMatcher {
		ranger := cidranger.NewPCTrieRanger()
		for _, prefix := range prefixes {
			err := ranger.Insert(cidranger.NewBasicRangerEntry(prefix))
			if err != nil {
				slog.Error("error inserting prefix", kind, name, "prefix", prefix.String(), "error", err)
			}
		}
		slog.Warn(message, kind, name, "count", ranger.Len())
		return ranger
	}
}

func (state *State) buildASNMatcher(name string) func([]policy.ASNRecord) networkMatcher {
	return func(records []policy.ASNRecord) networkMatcher {
		m := &asnMatcher{name: name, asns: make(map[uint]string, len(records)), maxMindDB: state.maxMindDB}
		for _, record := range records {
			// keep the first non-empty comment for duplicated ASNs
			if comment, ok := m.asns[record.ASN]; !ok || comment == "" {
				m.asns[record.ASN] = record.Comment
			}
		}
		if len(m.asns) == 0 {
			slog.Error("!!! ASN GROUP HAS NO ASNS LOADED, IT WILL NOT MATCH ANY REQUEST !!!", "asn-group", name)
		} else {
			slog.Warn("loaded ASNs for MaxMind lookup", "asn-group", name, "count", len(m.asns))
		}
		return m
	}
}

// listSource is one entry of a network or ASN group.
type listSource[T any] struct {
	name     string        // shown in logs
	cacheKey string        // empty disables the disk cache
	file     string        // watched for changes
	interval time.Duration // how often to re-fetch a url or check a file for changes, 0 disables
	jitter   time.Duration // random ± spread of each url refresh
	fetch    func() ([]T, error)

	// last successfully loaded values, only written by the goroutine owning the source
	values  []T
	modTime time.Time
}

type listCodec[T any] struct {
	encode func(T) string
	decode func(string) (T, error)
}

var prefixCodec = listCodec[net.IPNet]{encode: encodePrefix, decode: decodePrefix}
var asnRecordCodec = listCodec[policy.ASNRecord]{encode: encodeASNRecord, decode: decodeASNRecord}

type matcherHolder struct {
	networkMatcher
}

// listGroup matches against the combined values of its sources, and is rebuilt whenever one of them reloads.
type listGroup[T any] struct {
	kind    string // log attribute, "network" or "asn-group"
	name    string
	sources []*listSource[T]
	cache   utils.Cache
	codec   listCodec[T]
	build   func(values []T) networkMatcher

	mu       sync.Mutex
	current  atomic.Pointer[matcherHolder]
	watchers sync.WaitGroup
}

func (g *listGroup[T]) Contains(ip net.IP) (bool, error) {
	return g.current.Load().Contains(ip)
}

// start loads all sources, then keeps the ones with an interval up to date until closed is closed by State.Close.
func (g *listGroup[T]) start(closed <-chan struct{}) *listGroup[T] {
	g.mu.Lock()
	for _, s := range g.sources {
		if s.file != "" {
			// before loading, so a change during the load is picked up later
			s.modTime = fileModTime(s.file)
		}
		values, err := g.load(s, true)
		switch {
		case err != nil && len(values) > 0:
			slog.Error("!!! FAILED TO FETCH LIST, USING STALE CACHED COPY !!!", g.kind, g.name, "source", s.name, "count", len(values), "error", err)
		case err != nil:
			slog.Error("!!! FAILED TO LOAD LIST, NONE OF ITS ENTRIES WILL BE MATCHED !!!", g.kind, g.name, "source", s.name, "error", err)
		case len(values) == 0:
			slog.Warn("list has no entries, check its regex or jq-path", g.kind, g.name, "source", s.name)
		}
		s.values = values
	}
	g.rebuild()
	g.mu.Unlock()

	for _, s := range g.sources {
		if s.interval > 0 {
			g.watchers.Add(1)
			go g.watch(s, closed)
		}
	}
	return g
}

func (g *listGroup[T]) watch(s *listSource[T], closed <-chan struct{}) {
	defer g.watchers.Done()

	next := func() time.Duration {
		if s.file != "" {
			return s.interval
		}
		return jitter(s.interval, s.jitter)
	}
	timer := time.NewTimer(next())
	defer timer.Stop()

	for {
		select {
		case <-closed:
			return
		case <-timer.C:
			timer.Reset(next())
		}

		if s.file != "" {
			modTime := fileModTime(s.file)
			if modTime.Equal(s.modTime) {
				continue
			}
			s.modTime = modTime
		}

		values, err := g.load(s, false)
		if err != nil {
			slog.Error("!!! FAILED TO RELOAD LIST, KEEPING ITS PREVIOUS ENTRIES !!!", g.kind, g.name, "source", s.name, "count", len(s.values), "error", err)
			continue
		}
		if len(values) == 0 {
			slog.Warn("reloaded list has no entries, check its regex or jq-path", g.kind, g.name, "source", s.name)
		}

		g.mu.Lock()
		s.values = values
		g.rebuild()
		g.mu.Unlock()
		slog.Warn("reloaded list", g.kind, g.name, "source", s.name, "count", len(values))
	}
}

// rebuild swaps in a matcher built from all sources' values. Must be called with mu held.
func (g *listGroup[T]) rebuild() {
	var values []T
	for _, s := range g.sources {
		values = append(values, s.values...)
	}
	g.current.Store(&matcherHolder{g.build(values)})
}

// load fetches the source's values, writing them to the disk cache on success.
// On the initial load, a fresh disk cache is used without fetching, and a stale one is returned along with the error if fetching fails.
func (g *listGroup[T]) load(s *listSource[T], initial bool) ([]T, error) {
	useCache := g.cache != nil && s.cacheKey != ""

	var cached []T
	if useCache && initial {
		// expire the cache like a refresh would, so it isn't older than the refresh interval
		maxAge, spread := listCacheMaxAge, policy.DefaultRefreshJitter(listCacheMaxAge)
		if s.interval > 0 && s.interval < maxAge {
			maxAge, spread = s.interval, s.jitter
		}
		maxAge = jitter(maxAge, spread)
		var fresh bool
		cached, fresh = g.readCache(s.cacheKey, maxAge)
		if fresh {
			return cached, nil
		}
	}

	values, err := s.fetch()
	if err != nil {
		return cached, err
	}
	if useCache {
		g.writeCache(s.cacheKey, values)
	}
	return values, nil
}

func (g *listGroup[T]) readCache(key string, maxAge time.Duration) (values []T, fresh bool) {
	data, err := g.cache.Get(key, maxAge)
	var l []string
	if json.Unmarshal(data, &l) != nil {
		return nil, false
	}
	for _, s := range l {
		if v, err := g.codec.decode(s); err == nil {
			values = append(values, v)
		}
	}
	return values, err == nil
}

func (g *listGroup[T]) writeCache(key string, values []T) {
	l := make([]string, 0, len(values))
	for _, v := range values {
		l = append(l, g.codec.encode(v))
	}
	data, err := json.Marshal(l)
	if err == nil {
		err = g.cache.Set(key, data)
	}
	if err != nil {
		slog.Warn("failed to write list cache", g.kind, g.name, "key", key, "error", err)
	}
}

// jitter randomly moves d by up to ±spread, so instances started together don't fetch the same lists in lockstep.
func jitter(d, spread time.Duration) time.Duration {
	if spread <= 0 {
		return d
	}
	return d - spread + time.Duration(rand.Int64N(int64(2*spread+1)))
}

func fileModTime(file string) time.Time {
	stat, err := os.Stat(file)
	if err != nil {
		return time.Time{}
	}
	return stat.ModTime()
}

func encodePrefix(n net.IPNet) string {
	return n.String()
}

func decodePrefix(s string) (net.IPNet, error) {
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		return net.IPNet{}, err
	}
	return *ipNet, nil
}

func encodeASNRecord(record policy.ASNRecord) string {
	return strings.TrimSpace(strconv.FormatUint(uint64(record.ASN), 10) + " " + record.Comment)
}

func decodeASNRecord(s string) (policy.ASNRecord, error) {
	number, comment, _ := strings.Cut(s, " ")
	n, err := strconv.ParseUint(number, 10, 32)
	if err != nil || n == 0 {
		return policy.ASNRecord{}, fmt.Errorf("invalid cached ASN %q", s)
	}
	return policy.ASNRecord{ASN: uint(n), Comment: comment}, nil
}
