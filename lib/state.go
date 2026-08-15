package lib

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	http_cel "codeberg.org/gone/http-cel"
	"git.gammaspectra.live/git/go-away/lib/challenge"
	"git.gammaspectra.live/git/go-away/lib/policy"
	"git.gammaspectra.live/git/go-away/lib/settings"
	"git.gammaspectra.live/git/go-away/utils"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/yl2chen/cidranger"
	"golang.org/x/net/html"
)

type State struct {
	client    *http.Client
	radb      *utils.RADb
	maxMindDB *utils.MaxMindDB
	urlPath   string

	programEnv *cel.Env

	publicKey             ed25519.PublicKey
	privateKey            ed25519.PrivateKey
	privateKeyFingerprint []byte

	opt      settings.Settings
	settings policy.StateSettings

	networks map[string]func() networkMatcher

	challenges challenge.Register

	rules []RuleState

	close chan struct{}

	tagCache *utils.DecayMap[string, []html.Node]

	templates map[string]*template.Template

	Mux *http.ServeMux
}

type networkMatcher interface {
	Contains(ip net.IP) (bool, error)
}

type emptyMatcher struct{}

func (emptyMatcher) Contains(ip net.IP) (bool, error) {
	return false, nil
}

type asnMatcher struct {
	name      string
	asns      []uint
	maxMindDB *utils.MaxMindDB
}

func (m *asnMatcher) Contains(ip net.IP) (bool, error) {
	asn, err := m.maxMindDB.GetASN(ip)
	if err != nil {
		slog.Debug("maxmind ASN lookup failed", "asn-group", m.name, "remoteAddress", ip.String(), "error", err)
		return false, err
	}
	for _, expected := range m.asns {
		if asn == expected {
			slog.Debug("maxmind ASN lookup matched", "asn-group", m.name, "remoteAddress", ip.String(), "asn", asn)
			return true, nil
		}
	}
	slog.Debug("maxmind ASN lookup no match", "asn-group", m.name, "remoteAddress", ip.String(), "asn", asn)
	return false, nil
}

// combinedASNMatcher handles ASN groups with mixed lookup methods.
// radbFn is a sync.OnceValue that builds the prefix ranger from RADb;
// maxmind performs per-request ASN lookup.
type combinedASNMatcher struct {
	radbFn  func() networkMatcher
	maxmind *asnMatcher
}

func (m *combinedASNMatcher) Contains(ip net.IP) (bool, error) {
	ok, err := m.radbFn().Contains(ip)
	if err != nil || ok {
		return ok, err
	}
	return m.maxmind.Contains(ip)
}

func NewState(p policy.Policy, opt settings.Settings, settings policy.StateSettings) (state *State, err error) {
	state = new(State)
	state.close = make(chan struct{})
	state.settings = settings
	state.opt = opt
	metrics.Reset()
	state.client = &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	state.radb, err = utils.NewRADb()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize RADb client: %w", err)
	}

	if opt.MaxMindDatabase != "" {
		state.maxMindDB, err = utils.NewMaxMindDB(opt.MaxMindDatabase)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize MaxMind database: %w", err)
		}
	}

	state.urlPath = state.Settings().BasePath

	// set a reasonable configuration for default http proxy if there is none
	for _, backend := range state.Settings().Backends {
		if proxy, ok := backend.(*httputil.ReverseProxy); ok {
			if proxy.ErrorHandler == nil {
				proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
					state.Logger(r).Error(err.Error())
					state.ErrorPage(w, r, http.StatusBadGateway, err, "")
				}
			}
		}
	}

	if len(state.Settings().PrivateKeySeed) > 0 {
		if len(state.Settings().PrivateKeySeed) != ed25519.SeedSize {
			return nil, fmt.Errorf("invalid private key seed length: %d", len(state.Settings().PrivateKeySeed))
		}

		state.privateKey = ed25519.NewKeyFromSeed(state.Settings().PrivateKeySeed)
		state.publicKey = state.privateKey.Public().(ed25519.PublicKey)

		clear(state.settings.PrivateKeySeed)

	} else {
		state.publicKey, state.privateKey, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
	}

	fp := sha256.Sum256(state.privateKey)
	state.privateKeyFingerprint = fp[:]

	state.templates = make(map[string]*template.Template)
	maps.Copy(state.templates, globalTemplates)

	if state.templates["challenge-"+state.opt.ChallengeTemplate+".gohtml"] == nil {

		if data, err := os.ReadFile(state.opt.ChallengeTemplate); err == nil && len(data) > 0 {
			name := path.Base(state.opt.ChallengeTemplate)
			err := initTemplate(state.templates, name, string(data))
			if err != nil {
				return nil, fmt.Errorf("error loading template %s: %w", state.opt.ChallengeTemplate, err)
			}
			state.opt.ChallengeTemplate = name
		} else {
			return nil, fmt.Errorf("no template defined for %s", state.opt.ChallengeTemplate)
		}
	} else {
		state.opt.ChallengeTemplate = "challenge-" + state.opt.ChallengeTemplate + ".gohtml"
	}

	state.networks = make(map[string]func() networkMatcher)

	networkCache := utils.CachePrefix(state.Settings().Cache, "networks/")

	for k, network := range p.Networks {
		state.networks[k] = sync.OnceValue[networkMatcher](func() networkMatcher {
			ranger := cidranger.NewPCTrieRanger()
			for i, e := range network {
				prefixes, err := func() ([]net.IPNet, error) {
					var useCache bool

					cacheKey := fmt.Sprintf("%s-%d-", k, i)
					if e.Url != nil {
						slog.Debug("loading network url list", "network", k, "url", *e.Url)
						useCache = true
						sum := sha256.Sum256([]byte(*e.Url))
						cacheKey += hex.EncodeToString(sum[:4])
					} else if e.ASN != nil {
						slog.Debug("loading ASN", "network", k, "asn", *e.ASN)
						useCache = true
						cacheKey += strconv.FormatInt(int64(*e.ASN), 10)
					}

					var cached []net.IPNet
					if useCache && networkCache != nil {
						//TODO: add randomness
						cachedData, err := networkCache.Get(cacheKey, time.Hour*24)
						var l []string
						_ = json.Unmarshal(cachedData, &l)
						for _, n := range l {
							_, ipNet, err := net.ParseCIDR(n)
							if err == nil {
								cached = append(cached, *ipNet)
							}
						}
						if err == nil {
							// use
							return cached, nil
						}
					}

					prefixes, err := e.FetchPrefixes(state.client, state.radb)
					if err != nil {
						if len(cached) > 0 {
							// use cached meanwhile
							return cached, err
						}
						return nil, err
					}
					if useCache && networkCache != nil {
						var l []string
						for _, n := range prefixes {
							l = append(l, n.String())
						}
						cachedData, err := json.Marshal(l)
						if err == nil {
							_ = networkCache.Set(cacheKey, cachedData)
						}
					}
					return prefixes, nil
				}()
				if err != nil {
					if e.Url != nil {
						slog.Error("error loading network list", "network", k, "url", *e.Url, "error", err)
					} else if e.ASN != nil {
						slog.Error("error loading ASN", "network", k, "asn", *e.ASN, "error", err)
					} else {
						slog.Error("error loading list", "network", k, "error", err)
					}
					continue
				}
				for _, prefix := range prefixes {
					err = ranger.Insert(cidranger.NewBasicRangerEntry(prefix))
					if err != nil {
						slog.Error("error inserting prefix", "network", k, "prefix", prefix.String(), "error", err)
					}
				}
			}

			slog.Warn("loaded network prefixes", "network", k, "count", ranger.Len())
			return ranger
		})
	}

	for k, asnGroup := range p.ASNs {
		var radbEntries []policy.ASNEntry
		var maxmindASNs []uint
		for _, e := range asnGroup {
			if e.LookupMethod == "maxmind" {
				if state.maxMindDB == nil {
					return nil, fmt.Errorf("asn group %q entry ASN %d requires MaxMind database but none is configured", k, e.ASN)
				}
				maxmindASNs = append(maxmindASNs, uint(e.ASN))
			} else {
				radbEntries = append(radbEntries, e)
			}
		}

		var radbFn func() networkMatcher
		if len(radbEntries) > 0 {
			entries := radbEntries
			groupKey := k
			radbFn = sync.OnceValue[networkMatcher](func() networkMatcher {
				ranger := cidranger.NewPCTrieRanger()
				for _, e := range entries {
					prefixes, err := func() ([]net.IPNet, error) {
						cacheKey := fmt.Sprintf("asn-%s-%d", groupKey, e.ASN)

						var cached []net.IPNet
						if networkCache != nil {
							//TODO: add randomness
							cachedData, err := networkCache.Get(cacheKey, time.Hour*24)
							var l []string
							_ = json.Unmarshal(cachedData, &l)
							for _, n := range l {
								_, ipNet, err := net.ParseCIDR(n)
								if err == nil {
									cached = append(cached, *ipNet)
								}
							}
							if err == nil {
								return cached, nil
							}
						}

						slog.Debug("loading ASN via RADb", "asn-group", groupKey, "asn", e.ASN)
						prefixes, err := e.FetchPrefixes(state.radb)
						if err != nil {
							if len(cached) > 0 {
								return cached, err
							}
							return nil, err
						}
						if networkCache != nil {
							var l []string
							for _, n := range prefixes {
								l = append(l, n.String())
							}
							cachedData, err := json.Marshal(l)
							if err == nil {
								_ = networkCache.Set(cacheKey, cachedData)
							}
						}
						return prefixes, nil
					}()
					if err != nil {
						slog.Error("error loading ASN via RADb", "asn-group", groupKey, "asn", e.ASN, "error", err)
						continue
					}
					for _, prefix := range prefixes {
						err = ranger.Insert(cidranger.NewBasicRangerEntry(prefix))
						if err != nil {
							slog.Error("error inserting prefix", "asn-group", groupKey, "asn", e.ASN, "prefix", prefix.String(), "error", err)
						}
					}
				}
				slog.Warn("loaded ASN prefixes via RADb", "asn-group", groupKey, "count", ranger.Len())
				return ranger
			})
		}

		switch {
		case len(maxmindASNs) > 0 && radbFn != nil:
			combined := &combinedASNMatcher{radbFn: radbFn, maxmind: &asnMatcher{name: k, asns: maxmindASNs, maxMindDB: state.maxMindDB}}
			state.networks[k] = sync.OnceValue[networkMatcher](func() networkMatcher {
				combined.radbFn() // preload radb prefixes
				return combined
			})
		case len(maxmindASNs) > 0:
			mm := &asnMatcher{name: k, asns: maxmindASNs, maxMindDB: state.maxMindDB}
			state.networks[k] = func() networkMatcher { return mm }
		case radbFn != nil:
			state.networks[k] = radbFn
		default:
			slog.Warn("asn group has no entries", "asn-group", k)
			state.networks[k] = func() networkMatcher { return emptyMatcher{} }
		}
	}

	err = state.initConditions()
	if err != nil {
		return nil, err
	}

	var replacements []string
	for k, entries := range p.Conditions {
		ast, err := http_cel.NewAst(state.programEnv, http_cel.OperatorOr, entries...)
		if err != nil {
			return nil, fmt.Errorf("conditions %s: error compiling conditions: %v", k, err)
		}

		if out := ast.OutputType(); out == nil {
			return nil, fmt.Errorf("conditions %s: error compiling conditions: no output", k)
		} else if out != types.BoolType {
			return nil, fmt.Errorf("conditions %s: error compiling conditions: output type is not bool", k)
		}

		cond, err := cel.AstToString(ast)
		if err != nil {
			return nil, fmt.Errorf("conditions %s: error printing condition: %v", k, err)
		}

		replacements = append(replacements, fmt.Sprintf("($%s)", k))
		replacements = append(replacements, "("+cond+")")
	}
	conditionReplacer := strings.NewReplacer(replacements...)

	state.challenges = make(challenge.Register)

	//TODO: move this to self-contained challenge files
	for challengeName, pol := range p.Challenges {
		_, _, err := state.challenges.Create(state, challengeName, pol, conditionReplacer)
		if err != nil {
			return nil, fmt.Errorf("challenge %s: %w", challengeName, err)
		}
	}

	for _, r := range p.Rules {
		rule, err := NewRuleState(state, r, conditionReplacer, nil)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", r.Name, err)
		}

		slog.Warn("loaded rule", "rule", rule.Name, "hash", rule.Hash, "action", rule.Action, "children", len(rule.Children))

		state.rules = append(state.rules, rule)
	}

	state.Mux = http.NewServeMux()

	if err = state.setupRoutes(); err != nil {
		return nil, err
	}

	state.tagCache = utils.NewDecayMap[string, []html.Node]()

	go func() {
		ticker := time.NewTicker(time.Minute * 37)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				state.tagCache.Decay()
			case <-state.close:
				return
			}
		}
	}()

	return state, nil
}

func (state *State) Close() error {
	select {
	case <-state.close:
	default:
		close(state.close)
		if state.maxMindDB != nil {
			state.maxMindDB.Close()
		}
		for _, c := range state.challenges {
			if c.Object != nil {
				err := c.Object.Close()
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}
