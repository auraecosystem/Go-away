package action

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"slices"
	"text/template"
	"text/template/parse"

	"git.gammaspectra.live/git/go-away/lib/challenge"
)

// requestTemplateData holds the request fields available to header and body templates.
// The ASN fields are methods, so the MaxMind lookup only runs for templates that use them.
type requestTemplateData struct {
	Host          string
	Method        string
	Path          string
	RawQuery      string
	RequestURI    string
	Proto         string
	RemoteAddress string

	state challenge.StateInterface
	addr  netip.Addr

	asnLooked bool
	asn       uint
	asnOrg    string
}

func newRequestTemplateData(r *http.Request) *requestTemplateData {
	data := challenge.RequestDataFromContext(r.Context())
	addr := data.RemoteAddress.Addr().Unmap()
	return &requestTemplateData{
		Host:          r.Host,
		Method:        r.Method,
		Path:          r.URL.Path,
		RawQuery:      r.URL.RawQuery,
		RequestURI:    r.URL.RequestURI(),
		Proto:         r.Proto,
		RemoteAddress: addr.String(),
		state:         data.State,
		addr:          addr,
	}
}

func (d *requestTemplateData) lookupASN() {
	if d.asnLooked {
		return
	}
	d.asnLooked = true
	// an address missing from the database leaves the ASN fields empty
	d.asn, d.asnOrg, _ = d.state.LookupASN(d.addr.AsSlice())
}

// ASN returns the client ASN, 0 when unknown
func (d *requestTemplateData) ASN() uint {
	d.lookupASN()
	return d.asn
}

// ASNOrg returns the organization name of the client ASN from the MaxMind database
func (d *requestTemplateData) ASNOrg() string {
	d.lookupASN()
	return d.asnOrg
}

// ASNComment returns the policy comment of the client ASN, from the first ASN group in name order that has one
func (d *requestTemplateData) ASNComment() string {
	if asn := d.ASN(); asn != 0 {
		return d.state.ASNComment(asn)
	}
	return ""
}

var asnTemplateFields = []string{"ASN", "ASNOrg", "ASNComment"}

// usesASN reports whether the template tree references any of the ASN fields
func usesASN(node parse.Node) bool {
	isASNField := func(ident []string) bool {
		return slices.ContainsFunc(ident, func(s string) bool { return slices.Contains(asnTemplateFields, s) })
	}
	switch n := node.(type) {
	case *parse.ListNode:
		return n != nil && slices.ContainsFunc(n.Nodes, usesASN)
	case *parse.ActionNode:
		return usesASN(n.Pipe)
	case *parse.PipeNode:
		return n != nil && slices.ContainsFunc(n.Cmds, func(c *parse.CommandNode) bool { return usesASN(c) })
	case *parse.CommandNode:
		return slices.ContainsFunc(n.Args, usesASN)
	case *parse.FieldNode:
		return isASNField(n.Ident)
	case *parse.VariableNode:
		return isASNField(n.Ident)
	case *parse.ChainNode:
		return usesASN(n.Node) || isASNField(n.Field)
	case *parse.IfNode:
		return usesASN(n.Pipe) || usesASN(n.List) || usesASN(n.ElseList)
	case *parse.RangeNode:
		return usesASN(n.Pipe) || usesASN(n.List) || usesASN(n.ElseList)
	case *parse.WithNode:
		return usesASN(n.Pipe) || usesASN(n.List) || usesASN(n.ElseList)
	case *parse.TemplateNode:
		return usesASN(n.Pipe)
	}
	return false
}

// parseTemplate parses a header or body template, rejecting ASN fields when there is no database to look them up in
func parseTemplate(state challenge.StateInterface, name, text string) (*template.Template, error) {
	tmpl, err := template.New(name).Parse(text)
	if err != nil {
		return nil, errors.New(name + ": invalid template: " + err.Error())
	}
	// {{define}} blocks are separate templates, so check all of them
	if !state.HasASNDatabase() && slices.ContainsFunc(tmpl.Templates(), func(t *template.Template) bool { return usesASN(t.Root) }) {
		return nil, errors.New(name + ": template uses ASN fields but no MaxMind ASN database is configured")
	}
	return tmpl, nil
}

type headerTemplate struct {
	name  string
	value *template.Template
}

type headerTemplates []headerTemplate

func parseHeaderTemplates(state challenge.StateInterface, headers map[string]string) (headerTemplates, error) {
	var result headerTemplates
	for name, value := range headers {
		tmpl, err := parseTemplate(state, "headers."+name, value)
		if err != nil {
			return nil, err
		}
		result = append(result, headerTemplate{name: name, value: tmpl})
	}
	return result, nil
}

// render executes every template and sets the result on dst, skipping (and logging) headers whose template fails
func (h headerTemplates) render(logger *slog.Logger, data *requestTemplateData, dst http.Header) {
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
