package challenge

import (
	"crypto/ed25519"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"git.gammaspectra.live/git/go-away/lib/policy"
	"git.gammaspectra.live/git/go-away/utils"
)

// testState implements only what the verify handler needs, anything else panics on the nil embedded interface
type testState struct {
	StateInterface
	privateKey   ed25519.PrivateKey
	cookiePrefix string
	errorCode    int
}

func newTestState() *testState {
	_, privateKey, _ := ed25519.GenerateKey(nil)
	return &testState{privateKey: privateKey, cookiePrefix: utils.DefaultCookiePrefix}
}

func (s *testState) Settings() policy.StateSettings {
	return policy.StateSettings{CookiePrefix: s.cookiePrefix}
}
func (s *testState) GetChallenges() Register                                                   { return Register{} }
func (s *testState) PrivateKey() ed25519.PrivateKey                                            { return s.privateKey }
func (s *testState) PublicKey() ed25519.PublicKey                                              { return s.privateKey.Public().(ed25519.PublicKey) }
func (s *testState) PrivateKeyFingerprint() []byte                                             { return s.PublicKey() }
func (s *testState) Logger(r *http.Request) *slog.Logger                                       { return slog.Default() }
func (s *testState) ChallengeFailed(*http.Request, *Registration, error, string, *slog.Logger) {}
func (s *testState) ChallengePassed(*http.Request, *Registration, string, *slog.Logger)        {}

func (s *testState) ErrorPage(w http.ResponseWriter, r *http.Request, status int, err error, redirect string) {
	s.errorCode = status
	w.WriteHeader(status)
}

const testRequestId = "00112233445566778899aabbccddeeff"

func verifyQuery(challengeName, token string) url.Values {
	q := url.Values{}
	q.Set(QueryArgChallenge, challengeName)
	q.Set(QueryArgRequestId, testRequestId)
	q.Set(QueryArgRedirect, "/page?a=1")
	if token != "" {
		q.Set(QueryArgToken, token)
	}
	return q
}

func TestGetVerifyInformation(t *testing.T) {
	reg := &Registration{Name: "test"}

	t.Run("GET query", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/verify?"+verifyQuery("test", "query-token").Encode(), nil)
		requestId, redirect, token, err := GetVerifyInformation(r, reg)
		if err != nil {
			t.Fatal(err)
		}
		if requestId.String() != testRequestId {
			t.Errorf("request id = %s", requestId)
		}
		if redirect != "/page?a=1" {
			t.Errorf("redirect = %q", redirect)
		}
		if token != "query-token" {
			t.Errorf("token = %q", token)
		}
	})

	t.Run("POST body takes precedence over query", func(t *testing.T) {
		body := url.Values{QueryArgToken: {"body-token"}}.Encode()
		r := httptest.NewRequest(http.MethodPost, "/verify?"+verifyQuery("test", "query-token").Encode(), strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		_, _, token, err := GetVerifyInformation(r, reg)
		if err != nil {
			t.Fatal(err)
		}
		if token != "body-token" {
			t.Errorf("token = %q", token)
		}
	})

	t.Run("wrong challenge", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/verify?"+verifyQuery("other", "x").Encode(), nil)
		if _, _, _, err := GetVerifyInformation(r, reg); err == nil {
			t.Error("expected error")
		}
	})

	t.Run("open redirect is stripped", func(t *testing.T) {
		q := verifyQuery("test", "x")
		q.Set(QueryArgRedirect, "https://evil.example/page")
		r := httptest.NewRequest(http.MethodGet, "/verify?"+q.Encode(), nil)
		_, redirect, _, err := GetVerifyInformation(r, reg)
		if err != nil {
			t.Fatal(err)
		}
		if redirect != "/page" {
			t.Errorf("redirect = %q", redirect)
		}
	})
}

func TestVerifyHandlerFunc(t *testing.T) {
	verifyGood := func(key Key, token []byte, r *http.Request) (VerifyResult, error) {
		if string(token) == "good" {
			return VerifyResultOK, nil
		}
		return VerifyResultFail, nil
	}

	tests := []struct {
		name         string
		method       string
		queryToken   string
		bodyToken    string
		regVerify    VerifyFunc
		wantCode     int
		wantLocation string
		wantResult   string
		wantStored   bool
	}{
		{"GET pass", http.MethodGet, "good", "", verifyGood, http.StatusTemporaryRedirect, "/page?a=1", "good", true},
		{"GET fail", http.MethodGet, "bad", "", verifyGood, http.StatusForbidden, "", "", false},
		{"POST pass uses body token", http.MethodPost, "bad", "good", verifyGood, http.StatusSeeOther, "/page?a=1", "good", true},
		{"POST fail", http.MethodPost, "", "bad", verifyGood, http.StatusForbidden, "", "", false},
		{"no reg.Verify stores no result", http.MethodPost, "", "good", nil, http.StatusSeeOther, "/page?a=1", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := newTestState()
			reg := &Registration{
				Name:       "test",
				Path:       "/challenge/test",
				Duration:   time.Hour,
				KeyHeaders: DefaultKeyHeaders,
				Verify:     tt.regVerify,
			}

			var body *strings.Reader
			if tt.bodyToken != "" {
				body = strings.NewReader(url.Values{QueryArgToken: {tt.bodyToken}}.Encode())
			} else {
				body = strings.NewReader("")
			}
			r := httptest.NewRequest(tt.method, reg.Path+VerifyChallengeUrlSuffix+"?"+verifyQuery("test", tt.queryToken).Encode(), body)
			if tt.method == http.MethodPost {
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}

			r, data := CreateRequestData(r, state)
			data.ChallengeMap = make(TokenChallengeMap)

			w := httptest.NewRecorder()
			VerifyHandlerFunc(state, reg, verifyGood, nil)(w, r)

			if w.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d", w.Code, tt.wantCode)
			}
			if location := w.Header().Get("Location"); location != tt.wantLocation {
				t.Errorf("location = %q, want %q", location, tt.wantLocation)
			}

			token, ok := data.ChallengeMap[reg.Name]
			if ok != tt.wantStored {
				t.Fatalf("token stored = %v, want %v", ok, tt.wantStored)
			}
			if !ok {
				return
			}
			if !token.Ok {
				t.Error("stored token not ok")
			}
			if string(token.Result) != tt.wantResult {
				t.Errorf("stored result = %q, want %q", token.Result, tt.wantResult)
			}
			if data.ChallengeVerify[reg.Id()] != VerifyResultOK {
				t.Errorf("challenge verify = %s", data.ChallengeVerify[reg.Id()])
			}
			if w.Header().Get("Set-Cookie") == "" {
				t.Error("expected state cookie")
			}
		})
	}
}

func TestStateCookieUsesPrefix(t *testing.T) {
	state := newTestState()
	state.cookiePrefix = "__x-"
	reg := &Registration{Name: "test", Path: "/challenge/test", Duration: time.Hour, KeyHeaders: DefaultKeyHeaders}
	verify := func(key Key, token []byte, r *http.Request) (VerifyResult, error) {
		return VerifyResultOK, nil
	}

	r := httptest.NewRequest(http.MethodGet, reg.Path+VerifyChallengeUrlSuffix+"?"+verifyQuery("test", "x").Encode(), nil)
	r, data := CreateRequestData(r, state)
	data.ChallengeMap = make(TokenChallengeMap)

	w := httptest.NewRecorder()
	VerifyHandlerFunc(state, reg, verify, nil)(w, r)

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("got %d cookies, want 1", len(cookies))
	}
	if name := cookies[0].Name; !strings.HasPrefix(name, "__x-") || !strings.HasSuffix(name, "-state") {
		t.Errorf("cookie name = %q, want __x-<hash>-state", name)
	}
}
