package lib

import (
	"crypto/ed25519"
	"errors"
	"git.gammaspectra.live/git/go-away/lib/challenge"
	"git.gammaspectra.live/git/go-away/lib/policy"
	"git.gammaspectra.live/git/go-away/utils"
	"github.com/google/cel-go/cel"
	"log/slog"
	"net"
	"net/http"
)

// Defines challenge.StateInterface

var _ challenge.StateInterface

func (state *State) ProgramEnv() *cel.Env {
	return state.programEnv
}

func (state *State) Client() *http.Client {
	return state.client
}

func (state *State) PrivateKey() ed25519.PrivateKey {
	return state.privateKey
}

func (state *State) PrivateKeyFingerprint() []byte {
	return state.privateKeyFingerprint
}

func (state *State) PublicKey() ed25519.PublicKey {
	return state.publicKey
}

func (state *State) HasASNDatabase() bool {
	return state.maxMindASNDB != nil
}

func (state *State) LookupASN(ip net.IP) (uint, string, error) {
	if state.maxMindASNDB == nil {
		return 0, "", errors.New("no MaxMind ASN database configured")
	}
	return state.maxMindASNDB.GetASNOrg(ip)
}

func (state *State) UrlPath() string {
	return state.urlPath
}

func (state *State) ChallengeFailed(r *http.Request, reg *challenge.Registration, err error, redirect string, logger *slog.Logger) {
	if logger == nil {
		logger = state.Logger(r)
	}
	logger.Warn("challenge failed", "challenge", reg.Name, "err", err, "redirect", redirect)

	metrics.Challenge(reg.Name, "fail")
}

func (state *State) ChallengePassed(r *http.Request, reg *challenge.Registration, redirect string, logger *slog.Logger) {
	if logger == nil {
		logger = state.Logger(r)
	}
	logger.Warn("challenge passed", "challenge", reg.Name, "redirect", redirect)

	metrics.Challenge(reg.Name, "pass")
}

func (state *State) ChallengeIssued(r *http.Request, reg *challenge.Registration, redirect string, logger *slog.Logger) {
	if logger == nil {
		logger = state.Logger(r)
	}
	logger.Info("challenge issued", "challenge", reg.Name, "redirect", redirect)

	metrics.Challenge(reg.Name, "issue")
}

func (state *State) ChallengeChecked(r *http.Request, reg *challenge.Registration, redirect string, logger *slog.Logger) {
	metrics.Challenge(reg.Name, "check")
}

func (state *State) RuleHit(r *http.Request, name string, logger *slog.Logger) {
	metrics.Rule(name, "hit")
}

func (state *State) RuleMiss(r *http.Request, name string, logger *slog.Logger) {
	metrics.Rule(name, "miss")
}

func (state *State) ActionHit(r *http.Request, name policy.RuleAction, logger *slog.Logger) {
	metrics.Action(name)
}

func (state *State) Logger(r *http.Request) *slog.Logger {
	return GetLoggerForRequest(r)
}

func (state *State) GetChallenge(id challenge.Id) (*challenge.Registration, bool) {
	reg, ok := state.challenges.Get(id)
	return reg, ok
}

func (state *State) GetChallenges() challenge.Register {
	return state.challenges
}

func (state *State) GetChallengeByName(name string) (*challenge.Registration, bool) {
	reg, _, ok := state.challenges.GetByName(name)
	return reg, ok
}
func (state *State) Settings() policy.StateSettings {
	return state.settings
}

func (state *State) Strings() utils.Strings {
	return state.opt.Strings
}

func (state *State) GetBackend(host string) http.Handler {
	return utils.SelectHTTPHandler(state.Settings().Backends, host)
}
