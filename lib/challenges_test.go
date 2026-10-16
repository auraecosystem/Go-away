package lib

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/http/httptrace"
	"net/textproto"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"

	"git.gammaspectra.live/git/go-away/internal/dnstest"
	"git.gammaspectra.live/git/go-away/lib/policy"
	"git.gammaspectra.live/git/go-away/lib/settings"
	"golang.org/x/net/html"
)

// These tests drive every challenge runtime end to end through a real HTTP server, the way a client would:
// parse the served challenge page, follow what it asks for, and expect the backend to be reached afterward.
// They only rely on the semantic markup of the pages (meta, link, script, form tags), not on their layout,
// so they must keep passing when templates are redesigned.

const backendBody = "backend-ok"

const testHCaptchaSecret = "test-secret"
const testHCaptchaToken = "test-hcaptcha-token"

// testRuleHttpCode is set as http-code on the /code/ rules, to differ from the global 418
const testRuleHttpCode = http.StatusTooManyRequests

var challengeTemplates = []string{"anubis", "forgejo"}

type challengeEnv struct {
	server *httptest.Server
	state  *State
}

// newChallengeEnv starts go-away with one rule per challenge, served on /c/<challenge name>
func newChallengeEnv(t *testing.T, template string, http2 bool) *challengeEnv {
	t.Helper()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// echo what go-away tells the backend, so tests can check which challenge let the request through
		for k, v := range r.Header {
			if strings.HasPrefix(k, "X-Away-") {
				w.Header()["Echo-"+k] = v
			}
		}
		_, _ = io.WriteString(w, backendBody)
	}))
	t.Cleanup(upstream.Close)

	// a reverse proxy as configured in production, which passes challenge results as X-Away-* headers
	backend, err := settings.Backend{URL: upstream.URL}.Create()
	if err != nil {
		t.Fatal(err)
	}

	// backend for the http challenge
	httpCheck := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(httpCheck.Close)

	// hCaptcha api.js and siteverify mock
	hcaptcha := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api.js":
			w.Header().Set("Content-Type", "text/javascript")
		case "/siteverify":
			_ = r.ParseForm()
			ok := r.PostForm.Get("secret") == testHCaptchaSecret && r.PostForm.Get("response") == testHCaptchaToken
			_ = json.NewEncoder(w).Encode(map[string]any{"success": ok})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(hcaptcha.Close)

	// the test client connects from 127.0.0.1, which is only listed on listed.test
	dns := dnstest.NewServer(t, map[string]net.IP{
		"1.0.0.127.listed.test": net.IPv4(127, 0, 0, 2),
	})

	challenges := map[string]string{
		"cookie":         `{runtime: cookie}`,
		"header-refresh": `{runtime: refresh, parameters: {refresh-via: header}}`,
		"meta-refresh":   `{runtime: refresh, parameters: {refresh-via: meta}}`,
		"js-refresh":     `{runtime: refresh, parameters: {refresh-via: javascript}}`,
		"resource-load":  `{runtime: resource-load}`,
		"preload-link":   `{runtime: preload-link}`,
		"dnsbl":          fmt.Sprintf(`{runtime: dnsbl, parameters: {dnsbl-host: clean.test, dnsbl-resolver: %q}}`, dns),
		"dnsbl-listed":   fmt.Sprintf(`{runtime: dnsbl, parameters: {dnsbl-host: listed.test, dnsbl-resolver: %q}}`, dns),
		"http":           fmt.Sprintf(`{runtime: http, parameters: {http-url: %q}}`, httpCheck.URL),
		"js-pow-sha256":  `{runtime: js, parameters: {path: js-pow-sha256, js-loader: load.mjs, wasm-runtime: runtime.wasm, wasm-runtime-settings: {difficulty: "8"}}}`,
		"hcaptcha": fmt.Sprintf(`{runtime: hcaptcha, parameters: {site-key: test-site-key, secret: %q, script-url: %q, siteverify-url: %q}}`,
			testHCaptchaSecret, hcaptcha.URL+"/api.js", hcaptcha.URL+"/siteverify"),
	}

	var policyYaml strings.Builder
	policyYaml.WriteString("challenges:\n")
	for name, def := range challenges {
		fmt.Fprintf(&policyYaml, "  %s: %s\n", name, def)
	}
	policyYaml.WriteString("rules:\n")
	for name := range challenges {
		fmt.Fprintf(&policyYaml, "  - {name: %s, conditions: ['path == \"/c/%s\"'], action: challenge, settings: {challenges: [%s]}}\n", name, name, name)
		fmt.Fprintf(&policyYaml, "  - {name: %s-code, conditions: ['path == \"/code/%s\"'], action: challenge, settings: {http-code: %d, challenges: [%s]}}\n", name, name, testRuleHttpCode, name)
	}

	p, err := policy.NewPolicy(strings.NewReader(policyYaml.String()))
	if err != nil {
		t.Fatalf("policy: %v\n%s", err, policyYaml.String())
	}

	opt := settings.DefaultSettings
	opt.ChallengeTemplate = template

	state, err := NewState(*p, opt, policy.StateSettings{
		Backends:              map[string]http.Handler{"*": backend},
		BasePath:              opt.BasePath,
		ChallengeResponseCode: http.StatusTeapot,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })

	server := httptest.NewUnstartedServer(state)
	if http2 {
		server.EnableHTTP2 = true
		server.StartTLS()
	} else {
		server.Start()
	}
	t.Cleanup(server.Close)

	return &challengeEnv{server: server, state: state}
}

// browserTransport sends the same browser-like headers on every request, as challenge keys are bound to them
type browserTransport struct {
	base http.RoundTripper
}

func (b browserTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("User-Agent", "Mozilla/5.0 (go-away test)")
	r.Header.Set("Accept-Language", "en")
	return b.base.RoundTrip(r)
}

func (env *challengeEnv) client(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	base := env.server.Client()
	return &http.Client{
		Transport: browserTransport{base: base.Transport},
		Jar:       jar,
	}
}

func (env *challengeEnv) url(path string) string {
	return env.server.URL + path
}

type response struct {
	code   int
	header http.Header
	body   string
	url    *url.URL
}

func do(t *testing.T, client *http.Client, method, target string, body io.Reader, contentType string) response {
	t.Helper()
	req, err := http.NewRequest(method, target, body)
	if err != nil {
		t.Fatal(err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	defer res.Body.Close()
	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response{code: res.StatusCode, header: res.Header, body: string(data), url: res.Request.URL}
}

func get(t *testing.T, client *http.Client, target string) response {
	t.Helper()
	return do(t, client, http.MethodGet, target, nil, "")
}

// resolve makes a link found on a page absolute against the page URL
func resolve(t *testing.T, base *url.URL, ref string) string {
	t.Helper()
	u, err := base.Parse(ref)
	if err != nil {
		t.Fatalf("bad link %q: %v", ref, err)
	}
	return u.String()
}

func parseHTML(t *testing.T, body string) *html.Node {
	t.Helper()
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

// findElements returns the elements with the tag name, or any element when tag is empty, that match
func findElements(n *html.Node, tag string, match func(n *html.Node) bool) (out []*html.Node) {
	if n.Type == html.ElementNode && (tag == "" || n.Data == tag) && (match == nil || match(n)) {
		out = append(out, n)
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		out = append(out, findElements(c, tag, match)...)
	}
	return out
}

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, key) {
			return a.Val
		}
	}
	return ""
}

func textContent(n *html.Node) string {
	var sb strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.TextNode {
			sb.WriteString(n.Data)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return sb.String()
}

// refreshTarget parses "0; url=..." as used in Refresh headers and meta tags
func refreshTarget(t *testing.T, value string) string {
	t.Helper()
	_, target, ok := strings.Cut(value, "url=")
	if !ok {
		t.Fatalf("no url in refresh %q", value)
	}
	return target
}

// challengePage requests a protected path, and checks a challenge page was served instead of the backend
func challengePage(t *testing.T, env *challengeEnv, client *http.Client, path string) (response, *html.Node) {
	t.Helper()
	res := get(t, client, env.url(path))
	if res.code != http.StatusTeapot {
		t.Fatalf("GET %s: status %d, want challenge page %d\n%s", path, res.code, http.StatusTeapot, res.body)
	}
	if res.body == backendBody {
		t.Fatalf("GET %s: backend reached without challenge", path)
	}
	doc := parseHTML(t, res.body)
	checkPageAssets(t, client, res.url, doc)
	return res, doc
}

// checkPageAssets loads go-away's own assets referenced by a page, so a template cannot point to missing files
func checkPageAssets(t *testing.T, client *http.Client, base *url.URL, doc *html.Node) {
	t.Helper()
	var refs []string
	for _, n := range findElements(doc, "link", nil) {
		refs = append(refs, attr(n, "href"))
	}
	for _, tag := range []string{"img", "script"} {
		for _, n := range findElements(doc, tag, nil) {
			refs = append(refs, attr(n, "src"))
		}
	}
	for _, ref := range refs {
		if !strings.Contains(ref, "/assets/") {
			continue
		}
		if res := get(t, client, resolve(t, base, ref)); res.code != http.StatusOK {
			t.Errorf("asset %s: status %d", ref, res.code)
		}
	}
}

// expectBackend checks the backend was reached because the named challenge passed
func expectBackend(t *testing.T, res response, challengeName string) {
	t.Helper()
	if res.code != http.StatusOK || res.body != backendBody {
		t.Fatalf("%s: status %d, want backend\n%s", res.url, res.code, res.body)
	}
	if result := res.header.Get("Echo-X-Away-Challenge-" + challengeName + "-Result"); result != "OK" {
		t.Fatalf("%s: challenge %s result %q, want OK", res.url, challengeName, result)
	}
}

// expectPassed checks that the challenge is remembered and later requests go straight to the backend
func expectPassed(t *testing.T, env *challengeEnv, client *http.Client, name string) {
	t.Helper()
	expectBackend(t, get(t, client, env.url("/c/"+name)), name)
}

func solvePow(t *testing.T, challengeHex string, difficulty int) string {
	t.Helper()
	data, err := hex.DecodeString(challengeHex)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(data)+8)
	copy(buf, data)
	for nonce := uint64(0); nonce < 1<<32; nonce++ {
		for i := range 8 {
			buf[len(data)+i] = byte(nonce >> (8 * i))
		}
		sum := sha256.Sum256(buf)
		zeroes := 0
		for _, b := range sum {
			if b != 0 {
				for mask := byte(0x80); mask != 0 && b&mask == 0; mask >>= 1 {
					zeroes++
				}
				break
			}
			zeroes += 8
		}
		if zeroes >= difficulty {
			return hex.EncodeToString(buf)
		}
	}
	t.Fatal("no proof of work solution found")
	return ""
}

var (
	scriptPathRe = regexp.MustCompile(`Path: "([^"]+)"`)
	scriptIdRe   = regexp.MustCompile(`__goaway_id: "([0-9a-f]+)"`)
	importRe     = regexp.MustCompile(`from "([^"]+)"`)
	jsLocationRe = regexp.MustCompile(`window\.location = ("[^"]*")`)
)

func TestChallengesPass(t *testing.T) {
	for _, template := range challengeTemplates {
		t.Run(template, func(t *testing.T) {
			env := newChallengeEnv(t, template, false)

			t.Run("cookie", func(t *testing.T) {
				client := env.client(t)
				// the redirect is followed automatically, with the cookie set on it
				expectBackend(t, get(t, client, env.url("/c/cookie")), "cookie")
				expectPassed(t, env, client, "cookie")
			})

			t.Run("http", func(t *testing.T) {
				client := env.client(t)
				expectBackend(t, get(t, client, env.url("/c/http")), "http")
				expectPassed(t, env, client, "http")
			})

			t.Run("dnsbl", func(t *testing.T) {
				client := env.client(t)
				expectBackend(t, get(t, client, env.url("/c/dnsbl")), "dnsbl")
				expectPassed(t, env, client, "dnsbl")
			})

			t.Run("dnsbl listed is denied", func(t *testing.T) {
				client := env.client(t)
				for range 2 {
					res := get(t, client, env.url("/c/dnsbl-listed"))
					if res.code != http.StatusForbidden || res.body == backendBody {
						t.Fatalf("status %d, want %d\n%s", res.code, http.StatusForbidden, res.body)
					}
				}
			})

			t.Run("header-refresh", func(t *testing.T) {
				client := env.client(t)
				res, _ := challengePage(t, env, client, "/c/header-refresh")
				target := refreshTarget(t, res.header.Get("Refresh"))
				expectBackend(t, get(t, client, resolve(t, res.url, target)), "header-refresh")
				expectPassed(t, env, client, "header-refresh")
			})

			t.Run("meta-refresh", func(t *testing.T) {
				client := env.client(t)
				res, doc := challengePage(t, env, client, "/c/meta-refresh")
				metas := findElements(doc, "meta", func(n *html.Node) bool {
					return strings.EqualFold(attr(n, "http-equiv"), "refresh")
				})
				if len(metas) != 1 {
					t.Fatalf("found %d refresh meta tags, want 1", len(metas))
				}
				target := refreshTarget(t, attr(metas[0], "content"))
				expectBackend(t, get(t, client, resolve(t, res.url, target)), "meta-refresh")
				expectPassed(t, env, client, "meta-refresh")
			})

			t.Run("js-refresh", func(t *testing.T) {
				client := env.client(t)
				res, doc := challengePage(t, env, client, "/c/js-refresh")
				var target string
				for _, n := range findElements(doc, "script", nil) {
					if m := jsLocationRe.FindStringSubmatch(textContent(n)); m != nil {
						if err := json.Unmarshal([]byte(m[1]), &target); err != nil {
							t.Fatal(err)
						}
					}
				}
				if target == "" {
					t.Fatal("no window.location script found")
				}
				expectBackend(t, get(t, client, resolve(t, res.url, target)), "js-refresh")
				expectPassed(t, env, client, "js-refresh")
			})

			t.Run("resource-load", func(t *testing.T) {
				client := env.client(t)
				res, doc := challengePage(t, env, client, "/c/resource-load")
				links := findElements(doc, "link", func(n *html.Node) bool {
					return attr(n, "rel") == "stylesheet" && strings.Contains(attr(n, "href"), "/verify-challenge")
				})
				if len(links) != 1 {
					t.Fatalf("found %d challenge stylesheet links, want 1", len(links))
				}
				if res := get(t, client, resolve(t, res.url, attr(links[0], "href"))); res.code != http.StatusOK {
					t.Fatalf("challenge stylesheet: status %d", res.code)
				}
				target := refreshTarget(t, res.header.Get("Refresh"))
				expectBackend(t, get(t, client, resolve(t, res.url, target)), "resource-load")
				expectPassed(t, env, client, "resource-load")
			})

			t.Run("js-pow-sha256", func(t *testing.T) {
				client := env.client(t)
				res, doc := challengePage(t, env, client, "/c/js-pow-sha256")
				scripts := findElements(doc, "script", func(n *html.Node) bool {
					return strings.Contains(attr(n, "src"), "/script.mjs")
				})
				if len(scripts) != 1 {
					t.Fatalf("found %d challenge scripts, want 1", len(scripts))
				}
				script := get(t, client, resolve(t, res.url, attr(scripts[0], "src")))
				if script.code != http.StatusOK {
					t.Fatalf("challenge script: status %d", script.code)
				}
				path, id, loader := scriptPathRe.FindStringSubmatch(script.body), scriptIdRe.FindStringSubmatch(script.body), importRe.FindStringSubmatch(script.body)
				if path == nil || id == nil || loader == nil {
					t.Fatalf("challenge script is missing path, id or loader:\n%s", script.body)
				}
				if res := get(t, client, resolve(t, res.url, loader[1])); res.code != http.StatusOK {
					t.Fatalf("challenge loader: status %d", res.code)
				}

				made := do(t, client, http.MethodPost, resolve(t, res.url, path[1]+"/make-challenge"), nil, "")
				var params struct {
					Challenge  string `json:"challenge"`
					Difficulty int    `json:"difficulty"`
				}
				if err := json.Unmarshal([]byte(made.body), &params); err != nil {
					t.Fatalf("make-challenge: %v\n%s", err, made.body)
				}

				q := url.Values{}
				q.Set("__goaway_token", solvePow(t, params.Challenge, params.Difficulty))
				q.Set("__goaway_challenge", "js-pow-sha256")
				q.Set("__goaway_redirect", res.url.String())
				q.Set("__goaway_id", id[1])
				expectBackend(t, get(t, client, resolve(t, res.url, path[1]+"/verify-challenge?"+q.Encode())), "js-pow-sha256")
				expectPassed(t, env, client, "js-pow-sha256")
			})

			t.Run("hcaptcha", func(t *testing.T) {
				client := env.client(t)
				res, doc := challengePage(t, env, client, "/c/hcaptcha")
				if len(findElements(doc, "div", func(n *html.Node) bool { return strings.Contains(attr(n, "class"), "h-captcha") })) != 1 {
					t.Fatal("hCaptcha widget not found")
				}
				if len(findElements(doc, "script", func(n *html.Node) bool { return strings.HasSuffix(attr(n, "src"), "/api.js") })) != 1 {
					t.Fatal("hCaptcha api.js script not found")
				}
				forms := findElements(doc, "form", func(n *html.Node) bool { return strings.EqualFold(attr(n, "method"), "post") })
				if len(forms) != 1 {
					t.Fatalf("found %d POST forms, want 1", len(forms))
				}
				inputs := findElements(forms[0], "input", func(n *html.Node) bool { return attr(n, "type") == "hidden" })
				if len(inputs) != 1 {
					t.Fatalf("found %d hidden token inputs, want 1", len(inputs))
				}
				// the widget belongs in the page content next to the status, not after the footer
				statuses := findElements(doc, "", func(n *html.Node) bool { return attr(n, "id") == "status" })
				if len(statuses) != 1 {
					t.Fatalf("found %d status elements, want 1", len(statuses))
				}
				if forms[0].Parent != statuses[0].Parent {
					t.Error("hCaptcha form is not next to the status")
				}
				if status := strings.TrimSpace(textContent(statuses[0])); status != string(settings.DefaultStrings.Get("status_solve_captcha")) {
					t.Errorf("status = %q", status)
				}
				action := resolve(t, res.url, attr(forms[0], "action"))

				// what the widget callback does after the captcha is solved
				body := url.Values{attr(inputs[0], "name"): {testHCaptchaToken}}.Encode()
				expectBackend(t, do(t, client, http.MethodPost, action, strings.NewReader(body), "application/x-www-form-urlencoded"), "hcaptcha")
				expectPassed(t, env, client, "hcaptcha")
			})

			t.Run("hcaptcha wrong token shows error page", func(t *testing.T) {
				client := env.client(t)
				res, doc := challengePage(t, env, client, "/c/hcaptcha")
				forms := findElements(doc, "form", nil)
				if len(forms) != 1 {
					t.Fatalf("found %d forms, want 1", len(forms))
				}
				body := url.Values{"__goaway_token": {"wrong"}}.Encode()
				failed := do(t, client, http.MethodPost, resolve(t, res.url, attr(forms[0], "action")), strings.NewReader(body), "application/x-www-form-urlencoded")
				if failed.code != http.StatusForbidden {
					t.Fatalf("status %d, want %d", failed.code, http.StatusForbidden)
				}
				if !strings.Contains(failed.body, "access denied") {
					t.Errorf("error page does not show the error:\n%s", failed.body)
				}
				checkPageAssets(t, client, failed.url, parseHTML(t, failed.body))
				// still challenged afterward
				challengePage(t, env, client, "/c/hcaptcha")
			})
		})
	}
}

// preload-link needs HTTP/2 early hints, so it runs on its own TLS server
func TestPreloadLinkChallengePasses(t *testing.T) {
	env := newChallengeEnv(t, "anubis", true)
	client := env.client(t)

	var wg sync.WaitGroup
	var hintErr error
	trace := &httptrace.ClientTrace{
		Got1xxResponse: func(code int, header textproto.MIMEHeader) error {
			link := header.Get("Link")
			if code != http.StatusEarlyHints || link == "" {
				return nil
			}
			target := strings.TrimPrefix(link[:strings.Index(link, ">")], "<")
			// fetch the hinted resource while the main request is held, as a browser does
			wg.Add(1)
			go func() {
				defer wg.Done()
				res, err := client.Get(target)
				if err != nil {
					hintErr = err
					return
				}
				_ = res.Body.Close()
				if res.StatusCode != http.StatusOK {
					hintErr = fmt.Errorf("hinted resource: status %d", res.StatusCode)
				}
			}()
			return nil
		},
	}

	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(t.Context(), trace), http.MethodGet, env.url("/c/preload-link"), nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	wg.Wait()

	if hintErr != nil {
		t.Fatal(hintErr)
	}
	if res.ProtoMajor != 2 {
		t.Fatalf("protocol %s, want HTTP/2", res.Proto)
	}
	expectBackend(t, response{code: res.StatusCode, header: res.Header, body: string(body), url: res.Request.URL}, "preload-link")
}

func TestChallengeRuleHttpCode(t *testing.T) {
	env := newChallengeEnv(t, "anubis", false)

	// every runtime that serves a challenge page must use the rule http-code
	for _, name := range []string{"header-refresh", "meta-refresh", "js-refresh", "resource-load", "js-pow-sha256", "hcaptcha"} {
		t.Run(name, func(t *testing.T) {
			client := env.client(t)
			if res := get(t, client, env.url("/c/"+name)); res.code != http.StatusTeapot {
				t.Fatalf("global code: status %d, want %d", res.code, http.StatusTeapot)
			}
			if res := get(t, client, env.url("/code/"+name)); res.code != testRuleHttpCode {
				t.Fatalf("rule code: status %d, want %d", res.code, testRuleHttpCode)
			}
		})
	}
}
