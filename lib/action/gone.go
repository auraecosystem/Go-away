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
	data.State.ErrorPage(w, r, a.Code, fmt.Errorf("gone away: this page has gone away permanently %s/%s", data.Id.String(), a.RuleHash), "")
	return false, nil
}
