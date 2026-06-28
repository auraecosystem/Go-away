package action

import (
	"fmt"
	"log/slog"
	"net/http"

	"git.gammaspectra.live/git/go-away/lib/challenge"
	"git.gammaspectra.live/git/go-away/lib/policy"
	"github.com/goccy/go-yaml/ast"
)

func init() {
	Register[policy.RuleActionGONE] = func(state challenge.StateInterface, ruleName, ruleHash string, settings ast.Node) (Handler, error) {
		return Deny{
			Code:     http.StatusGone,
			RuleHash: ruleHash,
		}, nil
	}
}

type Gone struct {
	Code     int
	RuleHash string
}

func (a Gone) Handle(logger *slog.Logger, w http.ResponseWriter, r *http.Request, done func() (backend http.Handler)) (next bool, err error) {
	logger.Info("request denied")
	data := challenge.RequestDataFromContext(r.Context())

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Connection", "close")

	data.ResponseHeaders(w)
	w.WriteHeader(a.Code)
	_, _ = w.Write([]byte(fmt.Errorf("access denied: denied by administrative rule %s/%s", data.Id.String(), a.RuleHash).Error()))

	return false, nil
}
