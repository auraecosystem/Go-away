package lib

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"git.gammaspectra.live/git/go-away/lib/policy"
	"git.gammaspectra.live/git/go-away/lib/settings"
	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

func newTemplateState(t *testing.T, policyYaml, asnDatabase, countryDatabase string) (*State, error) {
	t.Helper()
	p, err := policy.NewPolicy(strings.NewReader(policyYaml))
	if err != nil {
		t.Fatal(err)
	}
	opt := settings.DefaultSettings
	opt.MaxMindASNDatabase = asnDatabase
	opt.MaxMindCountryDatabase = countryDatabase
	state, err := NewState(*p, opt, policy.StateSettings{
		Backends:       map[string]http.Handler{"*": http.NotFoundHandler()},
		ClientIpHeader: "X-Client-Ip",
	})
	if state != nil {
		t.Cleanup(func() { _ = state.Close() })
	}
	return state, err
}

func TestTemplateASNFields(t *testing.T) {
	state, err := newTemplateState(t, `
asns:
  hosters:
    - asn: 13335
      comment: Cloudflare
rules:
  - name: asn
    conditions: ['path == "/asn"']
    action: code
    settings:
      http-code: 200
      headers:
        X-Addr: "{{.RemoteAddress}}"
        X-Asn: "{{.ASN}}"
        X-Org: "{{.ASNOrg}}"
        X-Comment: "{{.ASNComment}}"
        X-Network: "{{or .ASNComment .ASNOrg}}"
`, writeTestASNMMDB(t), "")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		ip                        string
		asn, org, comment, either string
	}{
		{"1.0.0.1", "13335", "CLOUDFLARENET", "Cloudflare", "Cloudflare"},
		{"3.0.0.1", "15169", "GOOGLE", "", "GOOGLE"},
		{"9.9.9.9", "0", "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/asn", nil)
			req.Header.Set("X-Client-Ip", tt.ip)
			rec := httptest.NewRecorder()
			state.ServeHTTP(rec, req)

			want := map[string]string{"X-Addr": tt.ip, "X-Asn": tt.asn, "X-Org": tt.org, "X-Comment": tt.comment, "X-Network": tt.either}
			for name, value := range want {
				if got := rec.Header().Get(name); got != value {
					t.Errorf("%s: %q, want %q", name, got, value)
				}
			}
		})
	}
}

func TestTemplateASNFieldsRequireDatabase(t *testing.T) {
	invalid := map[string]string{
		"code header":      `{action: code, settings: {http-code: 200, headers: {X-Asn: "{{.ASN}}"}}}`,
		"code body":        `{action: code, settings: {http-code: 200, body: "{{if .ASNOrg}}hosted{{end}}"}}`,
		"defined template": `{action: code, settings: {http-code: 200, body: "{{define \"org\"}}{{.ASNOrg}}{{end}}{{template \"org\" .}}"}}`,
		"challenge header": `{action: challenge, settings: {challenges: [refresh], headers: {X-Net: "{{or .ASNComment $.Host}}"}}}`,
	}
	for name, rule := range invalid {
		t.Run(name, func(t *testing.T) {
			_, err := newTemplateState(t, `
challenges:
  refresh: {runtime: refresh, parameters: {refresh-via: header}}
rules:
  - {name: test, conditions: ['true'], `+rule[1:]+`
`, "", "")
			if err == nil || !strings.Contains(err.Error(), "no MaxMind ASN database is configured") {
				t.Fatalf("expected missing database error, got %v", err)
			}
		})
	}

	// templates without ASN fields need no database
	if _, err := newTemplateState(t, `
rules:
  - {name: test, conditions: ['true'], action: code, settings: {http-code: 200, headers: {X-Host: "{{.Host}}"}}}
`, "", ""); err != nil {
		t.Fatal(err)
	}
}

// writeTestCountryMMDB writes a GeoLite2-Country database: 1.0.0.0/24 is HU,
// 2.0.0.0/24 only has registered country US, 3.0.0.0/24 has no country
func writeTestCountryMMDB(t *testing.T) string {
	t.Helper()
	writer, err := mmdbwriter.New(mmdbwriter.Options{DatabaseType: "GeoLite2-Country", DisableIPv4Aliasing: true})
	if err != nil {
		t.Fatal(err)
	}
	isoCode := func(code string) mmdbtype.Map {
		return mmdbtype.Map{"iso_code": mmdbtype.String(code)}
	}
	entries := map[string]mmdbtype.Map{
		"1.0.0.0/24": {"country": isoCode("HU"), "registered_country": isoCode("DE")},
		"2.0.0.0/24": {"registered_country": isoCode("US")},
		"3.0.0.0/24": {},
	}
	for cidr, record := range entries {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatal(err)
		}
		if err := writer.Insert(network, record); err != nil {
			t.Fatal(err)
		}
	}
	path := t.TempDir() + "/country.mmdb"
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := writer.WriteTo(f); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestTemplateCountryField(t *testing.T) {
	state, err := newTemplateState(t, `
rules:
  - name: country
    conditions: ['path == "/country"']
    action: code
    settings:
      http-code: 200
      headers:
        X-Country: "{{.Country}}"
      body: "{{with .Country}}from {{.}}{{else}}unknown{{end}}"
`, "", writeTestCountryMMDB(t))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		ip, country, body string
	}{
		{"1.0.0.1", "HU", "from HU"},
		{"2.0.0.1", "US", "from US"},
		{"3.0.0.1", "", "unknown"},
		{"9.9.9.9", "", "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/country", nil)
			req.Header.Set("X-Client-Ip", tt.ip)
			rec := httptest.NewRecorder()
			state.ServeHTTP(rec, req)

			if got := rec.Header().Get("X-Country"); got != tt.country {
				t.Errorf("X-Country: %q, want %q", got, tt.country)
			}
			if got := rec.Body.String(); got != tt.body {
				t.Errorf("body: %q, want %q", got, tt.body)
			}
		})
	}
}

func TestTemplateCountryFieldRequiresDatabase(t *testing.T) {
	invalid := map[string]string{
		"code header":      `{action: code, settings: {http-code: 200, headers: {X-Country: "{{.Country}}"}}}`,
		"code body":        `{action: code, settings: {http-code: 200, body: "{{if eq .Country \"HU\"}}hi{{end}}"}}`,
		"challenge header": `{action: challenge, settings: {challenges: [refresh], headers: {X-Country: "{{$.Country}}"}}}`,
	}
	for name, rule := range invalid {
		t.Run(name, func(t *testing.T) {
			// an ASN database alone is not enough
			_, err := newTemplateState(t, `
challenges:
  refresh: {runtime: refresh, parameters: {refresh-via: header}}
rules:
  - {name: test, conditions: ['true'], `+rule[1:]+`
`, writeTestASNMMDB(t), "")
			if err == nil || !strings.Contains(err.Error(), "no MaxMind country database is configured") {
				t.Fatalf("expected missing database error, got %v", err)
			}
		})
	}
}
