package action

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"text/template"
)

// requestTemplateData holds the request fields available to header and body templates
type requestTemplateData struct {
	Host       string
	Method     string
	Path       string
	RawQuery   string
	RequestURI string
	Proto      string
}

func newRequestTemplateData(r *http.Request) requestTemplateData {
	return requestTemplateData{
		Host:       r.Host,
		Method:     r.Method,
		Path:       r.URL.Path,
		RawQuery:   r.URL.RawQuery,
		RequestURI: r.URL.RequestURI(),
		Proto:      r.Proto,
	}
}

type headerTemplate struct {
	name  string
	value *template.Template
}

type headerTemplates []headerTemplate

func parseHeaderTemplates(headers map[string]string) (headerTemplates, error) {
	var result headerTemplates
	for name, value := range headers {
		tmpl, err := template.New(name).Parse(value)
		if err != nil {
			return nil, errors.New("headers." + name + ": invalid template: " + err.Error())
		}
		result = append(result, headerTemplate{name: name, value: tmpl})
	}
	return result, nil
}

// render executes every template and sets the result on dst, skipping (and logging) headers whose template fails
func (h headerTemplates) render(logger *slog.Logger, data requestTemplateData, dst http.Header) {
	var buf bytes.Buffer
	for _, t := range h {
		buf.Reset()
		if err := t.value.Execute(&buf, data); err != nil {
			logger.Error("headers template error", "header", t.name, "error", err)
			continue
		}
		dst.Set(t.name, buf.String())
	}
}
