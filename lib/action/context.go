package action

import (
	"git.gammaspectra.live/git/go-away/lib/challenge"
	"git.gammaspectra.live/git/go-away/lib/policy"
	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"log/slog"
	"net/http"
	"net/textproto"
)

func init() {
	Register[policy.RuleActionCONTEXT] = func(state challenge.StateInterface, ruleName, ruleHash string, settings ast.Node) (Handler, error) {
		params := ContextDefaultSettings

		if settings != nil {
			ymlData, err := settings.MarshalYAML()
			if err != nil {
				return nil, err
			}
			err = yaml.UnmarshalWithOptions(ymlData, &params, yaml.Strict())
			if err != nil {
				return nil, err
			}
		}

		return Context{
			opts: params,
		}, nil
	}
}

var ContextDefaultSettings = ContextSettings{}

type ContextSettings struct {
	ContextSet      map[string]string   `yaml:"context-set"`
	ResponseHeaders map[string][]string `yaml:"response-headers"`
	RequestHeaders  map[string][]string `yaml:"request-headers"`
}

type Context struct {
	opts ContextSettings
}

func (a Context) Handle(logger *slog.Logger, w http.ResponseWriter, r *http.Request, done func() (backend http.Handler)) (next bool, err error) {
	data := challenge.RequestDataFromContext(r.Context())
	for k, v := range a.opts.ContextSet {
		data.SetOpt(k, v)
	}

	for k, v := range a.opts.ResponseHeaders {
		// do this to allow unsetting values that are sent automatically
		w.Header()[textproto.CanonicalMIMEHeaderKey(k)] = nil
		for _, val := range v {
			w.Header().Add(k, val)
		}
	}

	for k, v := range a.opts.RequestHeaders {
		// do this to allow unsetting values that are sent automatically
		r.Header[textproto.CanonicalMIMEHeaderKey(k)] = nil
		for _, val := range v {
			r.Header.Add(k, val)
		}
	}

	return true, nil
}
