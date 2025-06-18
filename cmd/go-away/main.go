package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"path"
	"runtime"
	"strings"
	"syscall"

	"git.gammaspectra.live/git/go-away/lib"
	"git.gammaspectra.live/git/go-away/lib/policy"
	"git.gammaspectra.live/git/go-away/lib/settings"
	"git.gammaspectra.live/git/go-away/utils"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func setupKvalue(jwtPrivateKeySeed string) []byte {
	var kValue string
	if kValue = os.Getenv("GOAWAY_JWT_PRIVATE_KEY_SEED"); kValue != "" {
		// prefer first
	} else if kValue = os.Getenv("JWT_PRIVATE_KEY_SEED"); kValue != "" {

	} else if jwtPrivateKeySeed != "" {
		kValue = jwtPrivateKeySeed
	}
	if kValue != "" {
		if strings.ToLower(kValue) == "generate" {
			_, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				utils.Fatal(fmt.Errorf("failed to generate private key: %w", err))
			}
			fmt.Printf("%x\n", priv.Seed())
			os.Exit(0)
		}
		seed, err := hex.DecodeString(kValue)
		if err != nil {
			utils.Fatal(fmt.Errorf("failed to decode seed: %w", err))
		}
		if len(seed) != ed25519.SeedSize {
			utils.Fatal(fmt.Errorf("invalid seed length: %d, expected %d", len(seed), ed25519.SeedSize))
		}
		return seed
	}
	return make([]byte, 0)
}

func main() {
	conf, check := settings.SetupConfiguration()
	settings.SetupLoglevel(conf)
	slog.Info("go-away", "package", settings.InternalMainName, "version", settings.InternalMainVersion, "cmd", settings.InternalCmdName, "go", runtime.Version(), "os", runtime.GOOS, "arch", runtime.GOARCH)
	seed := setupKvalue(conf.GetJwtPrivateKeySeed())

	var cache utils.Cache
	var acmeCache string
	if conf.CachePath != "" {
		err := os.MkdirAll(conf.CachePath, 0755)
		if err != nil {
			utils.Fatal(fmt.Errorf("failed to create cache directory: %w", err))
		}
		for _, n := range []string{"networks", "acme"} {
			err = os.MkdirAll(path.Join(conf.CachePath, n), 0755)
			if err != nil {
				utils.Fatal(fmt.Errorf("failed to create cache sub directory %s: %w", n, err))
			}
		}

		cache, err = utils.CacheDirectory(conf.CachePath)
		if err != nil {
			utils.Fatal(fmt.Errorf("failed to open cache directory: %w", err))
		}

		acmeCache = path.Join(conf.CachePath, "acme")
	}

	loadPolicyState := func() (*lib.State, error) {
		policyData, err := os.ReadFile(conf.Policy)
		if err != nil {
			return nil, fmt.Errorf("failed to read policy file: %w", err)
		}

		p, err := policy.NewPolicy(bytes.NewReader(policyData), *conf.PolicySnippets...)
		if err != nil {
			return nil, fmt.Errorf("failed to parse policy file: %w", err)
		}

		stateSettings := policy.StateSettings{
			Cache:                 cache,
			Backends:              conf.GetCreatedBackends(),
			MainName:              settings.InternalMainName,
			MainVersion:           settings.InternalMainVersion,
			BasePath:              conf.BasePath,
			PrivateKeySeed:        seed,
			ClientIpHeader:        conf.ClientIpHeader,
			BackendIpHeader:       conf.BackendIpHeader,
			ChallengeResponseCode: conf.ChallengeHttpCode,
		}

		state, err := lib.NewState(*p, conf, stateSettings)

		if err != nil {
			return nil, fmt.Errorf("failed to create state: %w", err)
		}
		return state, nil
	}

	if check {
		_, err := loadPolicyState()
		if err != nil {
			utils.Fatal(err)
		}
		slog.Info("load ok")
		os.Exit(0)
	}

	listener, listenUrl := conf.Bind.Listener()
	slog.Warn(
		"listening",
		"url", listenUrl,
	)

	server, swap, err := conf.Bind.Server(conf.GetCreatedBackends(), acmeCache)
	if err != nil {
		utils.Fatal(fmt.Errorf("failed to create server: %w", err))
	}

	server.ErrorLog = slog.NewLogLogger(slog.With("server", "http").Handler(), slog.LevelDebug)

	go func() {
		handler, err := loadPolicyState()
		if err != nil {
			utils.Fatal(fmt.Errorf("failed to load policy state: %w", err))
		}

		swap(handler)
		slog.Warn(
			"handler configuration loaded",
			"key_fingerprint", hex.EncodeToString(handler.PrivateKeyFingerprint()),
		)

		// allow reloading from now on
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGHUP)
		for sig := range c {
			if sig != syscall.SIGHUP {
				continue
			}
			oldHandler := handler
			handler, err = loadPolicyState()
			if err != nil {
				slog.Error("handler configuration reload error", "err", err)
				continue
			}

			swap(handler)
			slog.Warn("handler configuration reloaded")
			if oldHandler != nil {
				_ = oldHandler.Close()
			}
		}
	}()

	if conf.BindDebug != "" {
		go func() {
			mux := http.NewServeMux()
			mux.HandleFunc("/debug/pprof/", pprof.Index)
			mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
			mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
			mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
			debugServer := http.Server{
				Addr:     conf.BindDebug,
				Handler:  mux,
				ErrorLog: slog.NewLogLogger(slog.With("server", "debug").Handler(), slog.LevelDebug),
			}

			slog.Warn(
				"listening debug",
				"bind", conf.BindDebug,
			)
			if err = debugServer.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
				utils.Fatal(err)
			}
		}()
	}

	if conf.BindMetrics != "" {
		go func() {
			mux := http.NewServeMux()
			mux.Handle("/metrics", promhttp.Handler())
			metricsServer := http.Server{
				Addr:     conf.BindMetrics,
				Handler:  mux,
				ErrorLog: slog.NewLogLogger(slog.With("server", "metrics").Handler(), slog.LevelDebug),
			}

			slog.Warn(
				"listening metrics",
				"bind", conf.BindMetrics,
			)
			if err = metricsServer.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
				utils.Fatal(err)
			}
		}()
	}

	if server.TLSConfig != nil {
		if err := server.ServeTLS(listener, "", ""); !errors.Is(err, http.ErrServerClosed) {
			utils.Fatal(err)
		}
	} else {
		if err := server.Serve(listener); !errors.Is(err, http.ErrServerClosed) {
			utils.Fatal(err)
		}
	}

}
