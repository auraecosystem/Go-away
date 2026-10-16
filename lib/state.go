package lib

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"html/template"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httputil"
	"os"
	"path"
	"strings"
	"time"

	http_cel "codeberg.org/gone/http-cel"
	"git.gammaspectra.live/git/go-away/lib/challenge"
	"git.gammaspectra.live/git/go-away/lib/policy"
	"git.gammaspectra.live/git/go-away/lib/settings"
	"git.gammaspectra.live/git/go-away/utils"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"golang.org/x/net/html"
)

type State struct {
	client *http.Client
	// listClient downloads network and ASN lists, separate from client so it can have its own timeout
	listClient   *http.Client
	radb         *utils.RADb
	maxMindASNDB *utils.MaxMindDB
	// maxMindCountryDB is a separate GeoLite2-Country/City database, the ASN database has no country data
	maxMindCountryDB *utils.MaxMindDB
	urlPath          string

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
	state.listClient = newListClient(listFetchTimeout)
	state.radb, err = utils.NewRADb()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize RADb client: %w", err)
	}

	if opt.MaxMindASNDatabase != "" {
		state.maxMindASNDB, err = utils.NewMaxMindDB(opt.MaxMindASNDatabase)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize MaxMind ASN database: %w", err)
		}
	}

	if opt.MaxMindCountryDatabase != "" {
		state.maxMindCountryDB, err = utils.NewMaxMindDB(opt.MaxMindCountryDatabase)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize MaxMind country database: %w", err)
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

	err = state.initNetworks(p)
	if err != nil {
		return nil, err
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
		if state.maxMindASNDB != nil {
			state.maxMindASNDB.Close()
		}
		if state.maxMindCountryDB != nil {
			state.maxMindCountryDB.Close()
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
