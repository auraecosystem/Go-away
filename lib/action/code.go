package action

import (
	"bytes"
	"errors"
	"git.gammaspectra.live/git/go-away/lib/challenge"
	"git.gammaspectra.live/git/go-away/lib/policy"
	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"log/slog"
	"net/http"
	"text/template"
)

func init() {
	Register[policy.RuleActionCODE] = func(state challenge.StateInterface, ruleName, ruleHash string, settings ast.Node) (Handler, error) {
		params := CodeDefaultSettings

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

		if params.Code == 0 {
			return nil, errors.New("http-code not set")
		}

		c := Code{code: params.Code}

		if params.Body != "" {
			tmpl, err := parseTemplate(state, "body", params.Body)
			if err != nil {
				return nil, err
			}
			c.body = tmpl
		}

		headers, err := parseHeaderTemplates(state, params.Headers)
		if err != nil {
			return nil, err
		}
		c.headers = headers

		return c, nil
	}
}

var CodeDefaultSettings = CodeSettings{}

// CodeSettings holds the configuration for the CODE action.
//
// Example policy rule:
//
//	rules:
//	  - name: my-rule
//	    action: code
//	    settings:
//	      # HTTP status code to return. Required.
//	      http-code: 418
//
//	      # Optional map of response headers to set.
//	      # Each value is a Go text/template string with access to the following fields:
//	      #   .Host          — request Host header (e.g. "example.com")
//	      #   .Method        — HTTP method (e.g. "GET")
//	      #   .Path          — URL path (e.g. "/foo/bar")
//	      #   .RawQuery      — raw query string without leading "?" (e.g. "a=1&b=2")
//	      #   .RequestURI    — path and query combined (e.g. "/foo/bar?a=1&b=2")
//	      #   .Proto         — HTTP protocol (e.g. "HTTP/1.1")
//	      #   .RemoteAddress — client IP address (e.g. "192.0.2.1")
//	      #   .ASN           — client ASN, 0 when unknown (e.g. 13335)
//	      #   .ASNOrg        — ASN organization name from MaxMind (e.g. "CLOUDFLARENET")
//	      #   .ASNComment    — ASN comment from the first ASN group in name order that has one
//	      #   .Country       — client ISO 3166-1 alpha-2 country code, empty when unknown (e.g. "HU")
//	      #   The ASN fields require a MaxMind ASN database, .Country a MaxMind country database.
//	      headers:
//	        X-Original-Url: "https://{{.Host}}{{.RequestURI}}"
//	        X-Original-Method: "{{.Method}}"
//	        X-Client-Network: "{{or .ASNComment .ASNOrg}}"
//	        X-Client-Country: "{{.Country}}"
//
//	      # Optional response body. Go text/template string with the same fields as headers.
//	      body: "Access denied for {{.Host}}"
type CodeSettings struct {
	Code    int               `yaml:"http-code"`
	Headers map[string]string `yaml:"headers"`
	Body    string            `yaml:"body"`
}

type Code struct {
	code    int
	headers headerTemplates
	body    *template.Template
}

func (a Code) Handle(logger *slog.Logger, w http.ResponseWriter, r *http.Request, done func() (backend http.Handler)) (next bool, err error) {
	data := challenge.RequestDataFromContext(r.Context())

	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	tmplData := newRequestTemplateData(r)
	a.headers.render(logger, tmplData, w.Header())

	data.ResponseHeaders(w)
	w.WriteHeader(a.code)

	if a.body != nil {
		var buf bytes.Buffer
		if err := a.body.Execute(&buf, tmplData); err != nil {
			logger.Error("body template error", "error", err)
		} else {
			_, _ = w.Write(buf.Bytes())
		}
	}

	return false, nil
}
