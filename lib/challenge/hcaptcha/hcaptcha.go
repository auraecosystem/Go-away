package hcaptcha

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"git.gammaspectra.live/git/go-away/lib/challenge"
	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func init() {
	challenge.Runtimes[Key] = FillRegistration
}

const Key = "hcaptcha"

type Parameters struct {
	SiteKey    string        `yaml:"site-key"`
	Secret     string        `yaml:"secret"`
	SecretFile string        `yaml:"secret-file"`
	ScriptUrl  string        `yaml:"script-url"`
	VerifyUrl  string        `yaml:"siteverify-url"`
	Timeout    time.Duration `yaml:"timeout"`
}

var DefaultParameters = Parameters{
	ScriptUrl: "https://js.hcaptcha.com/1/api.js",
	VerifyUrl: "https://api.hcaptcha.com/siteverify",
	Timeout:   time.Second * 10,
}

// maxBodySize bounds the verify POST body, hCaptcha tokens are a few KiB at most
const maxBodySize = 64 * 1024

var widgetTemplate = template.Must(template.New("hcaptcha").Parse(`
<form id="goaway-hcaptcha" method="POST" action="{{ .Action }}">
    <input type="hidden" id="goaway-hcaptcha-token" name="{{ .TokenField }}" value=""/>
    <div class="h-captcha" data-sitekey="{{ .SiteKey }}" data-callback="goAwayHCaptchaCallback"></div>
</form>
<script type="text/javascript">
    function goAwayHCaptchaCallback(token) {
        document.getElementById("goaway-hcaptcha-token").value = token;
        document.getElementById("goaway-hcaptcha").submit();
    }
</script>
`))

var scriptTemplate = template.Must(template.New("hcaptcha-script").Parse(`<script src="{{ . }}" async defer></script>`))

type siteVerifyResponse struct {
	Success    bool     `json:"success"`
	ErrorCodes []string `json:"error-codes"`
}

func FillRegistration(state challenge.StateInterface, reg *challenge.Registration, parameters ast.Node) error {
	params := DefaultParameters

	if parameters != nil {
		ymlData, err := parameters.MarshalYAML()
		if err != nil {
			return err
		}
		err = yaml.Unmarshal(ymlData, &params)
		if err != nil {
			return err
		}
	}

	if params.SiteKey == "" {
		return errors.New("empty site-key")
	}

	if params.SecretFile != "" {
		if params.Secret != "" {
			return errors.New("only one of secret or secret-file can be set")
		}
		secret, err := os.ReadFile(params.SecretFile)
		if err != nil {
			return fmt.Errorf("could not read secret-file: %w", err)
		}
		params.Secret = strings.TrimSpace(string(secret))
	}
	if params.Secret == "" {
		return errors.New("empty secret")
	}

	reg.Class = challenge.ClassBlocking

	// hCaptcha tokens are single use, so they are checked once on the verify endpoint.
	// The issued go-away token is bound to the request key, which is enough afterward.
	verify := func(key challenge.Key, token []byte, r *http.Request) (challenge.VerifyResult, error) {
		if len(token) == 0 {
			return challenge.VerifyResultFail, nil
		}

		data := challenge.RequestDataFromContext(r.Context())

		form := url.Values{}
		form.Set("secret", params.Secret)
		form.Set("sitekey", params.SiteKey)
		form.Set("response", string(token))
		form.Set("remoteip", data.RemoteAddress.Addr().Unmap().String())

		ctx, cancel := context.WithTimeout(r.Context(), params.Timeout)
		defer cancel()

		request, err := http.NewRequestWithContext(ctx, http.MethodPost, params.VerifyUrl, strings.NewReader(form.Encode()))
		if err != nil {
			return challenge.VerifyResultFail, err
		}
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		response, err := state.Client().Do(request)
		if err != nil {
			return challenge.VerifyResultFail, fmt.Errorf("hcaptcha siteverify: %w", err)
		}
		defer response.Body.Close()

		if response.StatusCode != http.StatusOK {
			return challenge.VerifyResultFail, fmt.Errorf("hcaptcha siteverify: unexpected status %d", response.StatusCode)
		}

		var result siteVerifyResponse
		if err = json.NewDecoder(io.LimitReader(response.Body, maxBodySize)).Decode(&result); err != nil {
			return challenge.VerifyResultFail, fmt.Errorf("hcaptcha siteverify: %w", err)
		}

		if !result.Success {
			state.Logger(r).Warn("hcaptcha verification failed", "challenge", reg.Name, "error-codes", result.ErrorCodes)
			return challenge.VerifyResultFail, nil
		}
		return challenge.VerifyResultOK, nil
	}

	reg.IssueChallenge = func(w http.ResponseWriter, r *http.Request, key challenge.Key, expiry time.Time) challenge.VerifyResult {
		uri, err := challenge.VerifyUrl(r, reg, "")
		if err != nil {
			return challenge.VerifyResultFail
		}

		var widget bytes.Buffer
		err = widgetTemplate.Execute(&widget, map[string]string{
			"Action":     uri.String(),
			"TokenField": challenge.QueryArgToken,
			"SiteKey":    params.SiteKey,
		})
		if err != nil {
			return challenge.VerifyResultFail
		}

		var script bytes.Buffer
		err = scriptTemplate.Execute(&script, params.ScriptUrl)
		if err != nil {
			return challenge.VerifyResultFail
		}

		state.ChallengePage(w, r, state.Settings().ChallengeResponseCode, reg, map[string]any{
			"HeaderTags": []template.HTML{template.HTML(script.String())},
			"EndTags":    []template.HTML{template.HTML(widget.String())},
		})
		return challenge.VerifyResultNone
	}

	mux := http.NewServeMux()
	verifyHandler := challenge.VerifyHandlerFunc(state, reg, verify, nil)
	mux.HandleFunc("POST "+reg.Path+challenge.VerifyChallengeUrlSuffix, func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
		verifyHandler(w, r)
	})
	reg.Handler = mux

	return nil
}
