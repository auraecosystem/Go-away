package lib

import (
	"codeberg.org/meta/gzipped/v2"
	"fmt"
	"git.gammaspectra.live/git/go-away/embed"
	"git.gammaspectra.live/git/go-away/lib/action"
	"git.gammaspectra.live/git/go-away/lib/challenge"
	"git.gammaspectra.live/git/go-away/lib/policy"
	"git.gammaspectra.live/git/go-away/utils"
	"golang.org/x/net/html"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"
)

func GetLoggerForRequest(r *http.Request) *slog.Logger {
	data := challenge.RequestDataFromContext(r.Context())
	args := []any{
		"request_id", data.Id.String(),
		"remote_address", data.RemoteAddress.Addr().String(),
		"user_agent", r.UserAgent(),
		"host", r.Host,
		"path", r.URL.Path,
		"query", r.URL.RawQuery,
	}

	if fp := utils.GetTLSFingerprint(r); fp != nil {
		if ja3n := fp.JA3N(); ja3n != nil {
			args = append(args, "ja3n", ja3n.String())
		}
		if ja4 := fp.JA4(); ja4 != nil {
			args = append(args, "ja4", ja4.String())
		}
	}
	return slog.With(args...)
}

func (state *State) fetchTags(host string, backend http.Handler, r *http.Request, meta, link bool) []html.Node {
	uri := *r.URL
	q := uri.Query()
	for k := range q {
		if strings.HasPrefix(k, challenge.QueryArgPrefix) {
			q.Del(k)
		}
	}
	uri.RawQuery = q.Encode()

	key := fmt.Sprintf("%s:%s", host, uri.String())

	if v, ok := state.tagCache.Get(key); ok {
		return v
	}

	result := utils.FetchTags(backend, &uri, func() (r []string) {
		if meta {
			r = append(r, "meta")
		} else if link {
			r = append(r, "link")
		}
		return r
	}()...)
	if result == nil {
		return nil
	}

	entries := make([]html.Node, 0, len(result))
	for _, n := range result {
		if n.Namespace != "" {
			continue
		}

		switch n.Data {
		case "link":
			safeAttributes := []string{"rel", "href", "hreflang", "media", "title", "type"}

			var name string
			for _, attr := range n.Attr {
				if attr.Namespace != "" {
					continue
				}
				if attr.Key == "rel" {
					name = attr.Val
					break
				}
			}

			if name == "" {
				continue
			}

			var keep bool
			if name == "icon" || name == "alternate icon" {
				keep = true
			} else if name == "alternate" || name == "canonical" || name == "search" {
				// urls to versions of document
				keep = true
			} else if name == "author" || name == "privacy-policy" || name == "license" || name == "copyright" || name == "terms-of-service" {
				keep = true
			} else if name == "manifest" {
				// web app manifest
				keep = true
			}

			// prevent other arbitrary arguments
			if keep {
				newNode := html.Node{
					Type: html.ElementNode,
					Data: n.Data,
				}
				for _, attr := range n.Attr {
					if attr.Namespace != "" {
						continue
					}
					if slices.Contains(safeAttributes, attr.Key) {
						newNode.Attr = append(newNode.Attr, attr)
					}
				}
				if len(newNode.Attr) == 0 {
					continue
				}
				entries = append(entries, newNode)
			}

		case "meta":

			safeAttributes := []string{"name", "property", "content"}
			var name string
			for _, attr := range n.Attr {
				if attr.Namespace != "" {
					continue
				}
				if attr.Key == "name" {
					name = attr.Val
					break
				}
				if attr.Key == "property" && name == "" {
					name = attr.Val
				}
			}

			if name == "" {
				continue
			}

			// prevent unwanted keys like CSRF and other internal entries to pass through as much as possible

			var keep bool
			if strings.HasPrefix("og:", name) || strings.HasPrefix("fb:", name) || strings.HasPrefix("twitter:", name) || strings.HasPrefix("profile:", name) {
				// social / OpenGraph tags
				keep = true
			} else if name == "vcs" || strings.HasPrefix("vcs:", name) {
				// source tags
				keep = true
			} else if name == "forge" || strings.HasPrefix("forge:", name) {
				// forge tags
				keep = true
			} else if strings.HasPrefix("citation_", name) {
				// citations for Google Scholar
				keep = true
			} else {
				switch name {
				case "theme-color", "color-scheme", "origin-trials":
					// modifies page presentation
					keep = true
				case "application-name", "origin", "author", "creator", "contact", "title", "description", "thumbnail", "rating":
					// standard content tags
					keep = true
				case "license", "license:uri", "rights", "rights-standard":
					// licensing standards
					keep = true
				case "go-import", "go-source":
					// golang tags
					keep = true
				case "apple-itunes-app", "appstore:bundle_id", "appstore:developer_url", "appstore:store_id", "google-play-app":
					// application linking
					keep = true

				case "verify-v1", "google-site-verification", "p:domain_verify", "yandex-verification", "alexaverifyid":
					// site verification
					keep = true

				case "keywords", "robots", "google", "googlebot", "bingbot", "pinterest", "Slurp":
					// scraper and search content directives
					keep = true
				}
			}

			// prevent other arbitrary arguments
			if keep {
				newNode := html.Node{
					Type: html.ElementNode,
					Data: n.Data,
				}
				for _, attr := range n.Attr {
					if attr.Namespace != "" {
						continue
					}
					if slices.Contains(safeAttributes, attr.Key) {
						newNode.Attr = append(newNode.Attr, attr)
					}
				}
				if len(newNode.Attr) == 0 {
					continue
				}
				entries = append(entries, newNode)
			}
		}

	}

	state.tagCache.Set(key, entries, time.Hour*6)
	return entries
}

func (state *State) handleRequest(w http.ResponseWriter, r *http.Request) {
	host := r.Host

	data := challenge.RequestDataFromContext(r.Context())

	lg := state.Logger(r)

	backend := state.GetBackend(host)
	if backend == nil {
		lg.Debug("no backend for host", "host", host)
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}

	getBackend := func() http.Handler {
		if opt := data.GetOpt(challenge.RequestOptBackendHost, ""); opt != "" && opt != host {
			b := state.GetBackend(host)
			if b == nil {
				http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
				// return empty backend
				return http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
			}
			return b
		}
		return backend
	}

	cleanupRequest := func(r *http.Request, fromChallenge bool, ruleName string, ruleAction policy.RuleAction) {
		if fromChallenge {
			r.Header.Del("Referer")
		}

		q := r.URL.Query()
		if ref := q.Get(challenge.QueryArgReferer); ref != "" {
			r.Header.Set("Referer", ref)
		}

		rawQ, _ := utils.ParseRawQuery(r.URL.RawQuery)
		// delete query parameters that were set by go-away
		for k := range rawQ {
			if strings.HasPrefix(k, challenge.QueryArgPrefix) {
				rawQ.Del(k)
			}
		}
		r.URL.RawQuery = utils.EncodeRawQuery(rawQ)

		data.ExtraHeaders.Set("X-Away-Rule", ruleName)
		data.ExtraHeaders.Set("X-Away-Action", string(ruleAction))

		// delete cookies set by go-away to prevent user tracking that way
		cookies := r.Cookies()
		r.Header.Del("Cookie")
		for _, c := range cookies {
			if !strings.HasPrefix(c.Name, state.Settings().CookiePrefix) {
				r.AddCookie(c)
			}
		}

		// set response headers
		data.ResponseHeaders(w)
	}

	for _, rule := range state.rules {
		next, err := rule.Evaluate(lg, w, r, func() http.Handler {
			cleanupRequest(r, true, rule.Name, rule.Action)
			return getBackend()
		})
		if err != nil {
			state.ErrorPage(w, r, http.StatusInternalServerError, err, "")
			panic(err)
			return
		}

		if !next {
			return
		}
	}

	state.RuleHit(r, "DEFAULT", lg)
	data.State.ActionHit(r, policy.RuleActionPASS, lg)

	// default pass
	_, _ = action.Pass{}.Handle(lg, w, r, func() http.Handler {
		cleanupRequest(r, false, "DEFAULT", policy.RuleActionPASS)
		return getBackend()
	})
}

func (state *State) setupRoutes() error {

	state.Mux.HandleFunc("/", state.handleRequest)

	state.Mux.Handle("GET "+state.urlPath+"/assets/", http.StripPrefix(state.UrlPath()+"/assets/", gzipped.FileServer(gzipped.FS(embed.AssetsFs))))

	for _, reg := range state.challenges {

		if reg.Handler != nil {
			state.Mux.Handle(reg.Path+"/", reg.Handler)
		} else if reg.Verify != nil {
			// default verify
			state.Mux.HandleFunc(reg.Path+challenge.VerifyChallengeUrlSuffix, challenge.VerifyHandlerFunc(state, reg, nil, nil))
		}
	}

	return nil
}

func (state *State) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r, data := challenge.CreateRequestData(r, state)

	data.EvaluateChallenges(w, r)

	state.Mux.ServeHTTP(w, r)
}
