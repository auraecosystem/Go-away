package utils

import (
	"net"
	"net/http"
	"strings"
	"time"
)

var DefaultCookiePrefix = ".go-away-"

// getValidHost Gets a valid host for an http.Cookie Domain field
// TODO: bug: does not work with IPv6, see https://github.com/golang/go/issues/65521
func getValidHost(host string) string {
	ipStr, _, err := net.SplitHostPort(host)
	if err != nil {
		return host
	}
	return ipStr
}

func SetCookie(name, value string, expiry time.Time, w http.ResponseWriter, r *http.Request, isSecure bool, httpOnly bool, sameSite string) {
	ss := parseSameSite(sameSite)
	// Enforce Secure when SameSite=None
	if ss == http.SameSiteNoneMode {
		isSecure = true
	}
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Expires:  expiry,
		SameSite: ss,
		Path:     "/",
		Domain:   getValidHost(r.Host),
		Secure:   isSecure,
		HttpOnly: httpOnly,
	})
}

func ClearCookie(name string, w http.ResponseWriter, r *http.Request, isSecure bool, httpOnly bool, sameSite string) {
	ss := parseSameSite(sameSite)
	if ss == http.SameSiteNoneMode {
		isSecure = true
	}
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Expires:  time.Now().Add(-1 * time.Hour),
		MaxAge:   -1,
		SameSite: ss,
		Path:     "/",
		Domain:   getValidHost(r.Host),
		Secure:   isSecure,
		HttpOnly: httpOnly,
	})
}

// Helper function to parse sameSite to http.SameSite
func parseSameSite(value string) http.SameSite {
	switch strings.ToLower(strings.TrimSpace(value)) {
		case "none":
			return http.SameSiteNoneMode
		case "strict":
			return http.SameSiteStrictMode
		case "lax", "":
			fallthrough
		default:
			return http.SameSiteLaxMode
	}
}
