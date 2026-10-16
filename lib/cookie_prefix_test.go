package lib

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"git.gammaspectra.live/git/go-away/lib/policy"
	"git.gammaspectra.live/git/go-away/lib/settings"
	"git.gammaspectra.live/git/go-away/utils"
)

func newCookiePrefixState(t *testing.T, prefix string, backend http.Handler) (*State, error) {
	t.Helper()
	p, err := policy.NewPolicy(strings.NewReader("rules: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	state, err := NewState(*p, settings.DefaultSettings, policy.StateSettings{
		Backends:     map[string]http.Handler{"example.com": backend},
		CookiePrefix: prefix,
	})
	if state != nil {
		t.Cleanup(func() { _ = state.Close() })
	}
	return state, err
}

func TestNewStateCookiePrefix(t *testing.T) {
	tests := []struct {
		name    string
		prefix  string
		want    string
		wantErr bool
	}{
		{"empty uses default", "", utils.DefaultCookiePrefix, false},
		{"custom", "__x-", "__x-", false},
		{"invalid character", "bad;prefix", "", true},
		{"space", "bad prefix", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state, err := newCookiePrefixState(t, tt.prefix, http.NotFoundHandler())
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := state.Settings().CookiePrefix; got != tt.want {
				t.Errorf("cookie prefix = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCookiePrefixStrippedBeforeBackend(t *testing.T) {
	var backendCookies []*http.Cookie
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCookies = r.Cookies()
	})

	state, err := newCookiePrefixState(t, "__x-", backend)
	if err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest(http.MethodGet, "http://example.com/page", nil)
	r.AddCookie(&http.Cookie{Name: "__x-0123456789ab-state", Value: "junk"})
	r.AddCookie(&http.Cookie{Name: "app_session", Value: "keepme"})
	// only the configured prefix is stripped, not the default one
	r.AddCookie(&http.Cookie{Name: utils.DefaultCookiePrefix + "other", Value: "1"})

	state.ServeHTTP(httptest.NewRecorder(), r)

	got := make(map[string]string)
	for _, c := range backendCookies {
		got[c.Name] = c.Value
	}
	if _, ok := got["__x-0123456789ab-state"]; ok {
		t.Error("go-away cookie was passed to backend")
	}
	if got["app_session"] != "keepme" {
		t.Errorf("app_session = %q, want keepme", got["app_session"])
	}
	if got[utils.DefaultCookiePrefix+"other"] != "1" {
		t.Errorf("%sother cookie was stripped", utils.DefaultCookiePrefix)
	}
}
