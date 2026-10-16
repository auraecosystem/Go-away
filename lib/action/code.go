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
			err = yaml.Unmarshal(ymlData, &params)
			if err != nil {
				return nil, err
			}
		}

		if params.Code == 0 {
			return nil, errors.New("http-code not set")
		}

		c := Code{code: params.Code}

		if params.Body != "" {
			tmpl, err := template.New("body").Parse(params.Body)
			if err != nil {
				return nil, errors.New("body: invalid template: " + err.Error())
			}
			c.body = tmpl
		}

		for name, value := range params.Headers {
			tmpl, err := template.New(name).Parse(value)
			if err != nil {
				return nil, errors.New("headers." + name + ": invalid template: " + err.Error())
			}
			c.headers = append(c.headers, codeHeader{name: name, value: tmpl})
		}

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
//	      #   .Host       — request Host header (e.g. "example.com")
//	      #   .Method     — HTTP method (e.g. "GET")
//	      #   .Path       — URL path (e.g. "/foo/bar")
//	      #   .RawQuery   — raw query string without leading "?" (e.g. "a=1&b=2")
//	      #   .RequestURI — path and query combined (e.g. "/foo/bar?a=1&b=2")
//	      #   .Proto      — HTTP protocol (e.g. "HTTP/1.1")
//	      headers:
//	        X-Original-Url: "https://{{.Host}}{{.RequestURI}}"
//	        X-Original-Method: "{{.Method}}"
//
//	      # Optional response body. Go text/template string with the same fields as headers.
//	      body: "Access denied for {{.Host}}"
type CodeSettings struct {
	Code    int               `yaml:"http-code"`
	Headers map[string]string `yaml:"headers"`
	Body    string            `yaml:"body"`
}

type codeTemplateData struct {
	Host       string
	Method     string
	Path       string
	RawQuery   string
	RequestURI string
	Proto      string
}

type codeHeader struct {
	name  string
	value *template.Template
}

type Code struct {
	code    int
	headers []codeHeader
	body    *template.Template
}

func (a Code) Handle(logger *slog.Logger, w http.ResponseWriter, r *http.Request, done func() (backend http.Handler)) (next bool, err error) {
	data := challenge.RequestDataFromContext(r.Context())

	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	if len(a.headers) > 0 || a.body != nil {
		tmplData := codeTemplateData{
			Host:       r.Host,
			Method:     r.Method,
			Path:       r.URL.Path,
			RawQuery:   r.URL.RawQuery,
			RequestURI: r.URL.RequestURI(),
			Proto:      r.Proto,
		}
		var buf bytes.Buffer
		for _, h := range a.headers {
			buf.Reset()
			if err := h.value.Execute(&buf, tmplData); err != nil {
				logger.Error("headers template error", "header", h.name, "error", err)
				continue
			}
			w.Header().Set(h.name, buf.String())
		}

		data.ResponseHeaders(w)
		w.WriteHeader(a.code)

		if a.body != nil {
			buf.Reset()
			if err := a.body.Execute(&buf, tmplData); err != nil {
				logger.Error("body template error", "error", err)
			} else {
				_, _ = w.Write(buf.Bytes())
			}
		}
	} else {
		data.ResponseHeaders(w)
		w.WriteHeader(a.code)
	}

	return false, nil
}
