package settings

import (
	"flag"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"os"
	"path"
	"runtime/debug"
	"strings"

	"git.gammaspectra.live/git/go-away/utils"
	"github.com/goccy/go-yaml"
)

type MultiVar []string

func (v *MultiVar) String() string {
	return fmt.Sprintf("%v", *v)
}

func (v *MultiVar) Set(value string) error {
	*v = append(*v, value)
	return nil
}

type Settings struct {
	Bind Bind `yaml:"bind"`

	Backends map[string]Backend `yaml:"backends"`

	BindDebug   string `yaml:"bind-debug"`
	BindMetrics string `yaml:"bind-metrics"`

	Strings utils.Strings `yaml:"strings"`

	// Links to add to challenge/error pages like privacy/impressum.
	Links []Link `yaml:"links"`

	ChallengeHttpCode int `yaml:"challenge-http-code"`

	ChallengeTemplate string `yaml:"challenge-template"`

	// ChallengeTemplateOverrides Key/Value overrides for the current chosen template
	ChallengeTemplateOverrides map[string]string `yaml:"challenge-template-overrides"`
	Policy                     string            `yaml:"policy"`
	PolicySnippets             *MultiVar         `yaml:"policy-snippets"`
	CachePath                  string            `yaml:"cache-path"`
	LogLevel                   string            `yaml:"slog-level"`
	ClientIpHeader             string            `yaml:"client-ip-header"`
	BackendIpHeader            string            `yaml:"backend-ip-header"`
	BasePath                   string            `yaml:"base-path"`

	createdBackends   map[string]http.Handler
	jwtPrivateKeySeed string
}

func (s Settings) GetJwtPrivateKeySeed() string {
	return s.jwtPrivateKeySeed
}

func (s Settings) GetCreatedBackends() map[string]http.Handler {
	return s.createdBackends
}

type Link struct {
	Name string `yaml:"name"`
	URL  string `yaml:"url"`
}

var InternalCmdName = "go-away"
var InternalMainName = "go-away"
var InternalMainVersion = "dev"

func init() {
	buildInfo, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	InternalCmdName = buildInfo.Path
	InternalMainName = buildInfo.Main.Path
	InternalMainVersion = buildInfo.Main.Version
}

var DefaultSettings = Settings{
	Strings:           DefaultStrings,
	ChallengeHttpCode: http.StatusTeapot,
	ChallengeTemplate: "anubis",
	ChallengeTemplateOverrides: func() map[string]string {
		m := make(map[string]string)
		maps.Copy(m, map[string]string{
			"Theme": "",
			"Logo":  "",
		})
		return m
	}(),

	Bind: Bind{
		Address:         ":8080",
		Network:         "tcp",
		SocketMode:      "0770",
		Proxy:           false,
		TLSAcmeAutoCert: "",
	},
	Backends:          make(map[string]Backend),
	Policy:            "",
	PolicySnippets:    &MultiVar{""},
	CachePath:         path.Join(os.TempDir(), "go-away-cache"),
	LogLevel:          "WARN",
	ClientIpHeader:    "",
	BackendIpHeader:   "",
	BasePath:          "/.well-known/." + InternalCmdName,
	createdBackends:   map[string]http.Handler{},
	jwtPrivateKeySeed: "",
}

func SetupLoglevel(settings Settings) {
	var err error
	var programLevel slog.Level
	if err = (&programLevel).UnmarshalText([]byte(settings.LogLevel)); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "invalid log level %s: %v, using info\n", settings.LogLevel, err)
		programLevel = slog.LevelInfo
	}

	leveler := &slog.LevelVar{}
	leveler.Set(programLevel)

	h := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		AddSource: programLevel <= slog.LevelDebug,
		Level:     leveler,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == "source" {
				if src, ok := a.Value.Any().(*slog.Source); ok {
					return slog.String(a.Key, fmt.Sprintf("%s:%d", src.File, src.Line))
				}
			}
			return a
		},
	})
	slog.SetDefault(slog.New(h))
	// set default log logger to slog logger level
	slog.SetLogLoggerLevel(programLevel)
	if err != nil {
		utils.Fatal(fmt.Errorf("failed to setup log level: %w", err))
	}
}

func setupBackends(settings *Settings) {
	for k, v := range settings.Backends {
		if v.IpHeader == "" {
			//set default value
			v.IpHeader = settings.BackendIpHeader
		}
		backend, err := v.Create()
		if err != nil {
			utils.Fatal(fmt.Errorf("backend %s: failed to make reverse proxy: %w", k, err))
		}
		backend.ErrorLog = slog.NewLogLogger(slog.With("backend", k).Handler(), slog.LevelDebug)
		settings.createdBackends[k] = backend
	}
}

// Parse backends specified in the cmdline
func parseCmdbackends(settings *Settings, backends MultiVar) {
	if len(backends) == 0 {
		utils.Fatal(fmt.Errorf("no backends defined in commandline"))
	}
	for _, backend := range backends {
		parts := strings.Split(backend, "=")
		if len(parts) != 2 {
			utils.Fatal(fmt.Errorf("invalid backend definition: %s, expected 2 parts, got %v", backend, parts))
		}
		// make no-settings, default backend
		settings.Backends[parts[0]] = Backend{
			URL:      parts[1],
			IpHeader: settings.BackendIpHeader,
		}
	}
}

// the config file settings have precedence over cmdline settings
func loadYamlconfig(settingsFile *string, cmdSettings *Settings) *Settings {
	settingsData, err := os.ReadFile(*settingsFile)
	if err != nil {
		utils.Fatal(fmt.Errorf("could not read settings file: %w", err))
	}
	cfgSettings := DefaultSettings
	err = yaml.Unmarshal(settingsData, &cfgSettings)
	if err != nil {
		utils.Fatal(fmt.Errorf("could not parse settings file: %w", err))
	}
	if len(cfgSettings.Backends) == 0 {
		utils.Fatal(fmt.Errorf("no backends defined in settings file"))
	}
	return &cfgSettings
}

func SetupConfiguration() (Settings, bool) {
	settings := DefaultSettings

	flag.StringVar(&settings.Bind.Address, "bind", settings.Bind.Address, "network address to bind HTTP/HTTP(s) to")
	flag.StringVar(&settings.Bind.Network, "bind-network", settings.Bind.Network, "network family to bind HTTP to, e.g. unix, tcp")
	flag.BoolVar(&settings.Bind.Proxy, "bind-proxy", settings.Bind.Proxy, "use PROXY protocol in front of the listener")
	flag.StringVar(&settings.Bind.SocketMode, "socket-mode", settings.Bind.SocketMode, "socket mode (permissions) for unix domain sockets.")
	flag.StringVar(&settings.BindMetrics, "metrics-bind", settings.BindMetrics, "network address to bind metrics on")
	flag.StringVar(&settings.BindDebug, "debug-bind", settings.BindDebug, "network address to bind debug on")

	flag.StringVar(&settings.LogLevel, "slog-level", settings.LogLevel, "logging level (see https://pkg.go.dev/log/slog#hdr-Levels)")

	flag.BoolVar(&settings.Bind.Passthrough, "passthrough", settings.Bind.Passthrough, "passthrough mode sends all requests to matching backends until state is loaded")
	check := flag.Bool("check", false, "check configuration and policies, then exit")
	flag.StringVar(&settings.Bind.TLSAcmeAutoCert, "acme-autocert", settings.Bind.TLSAcmeAutoCert, "enables HTTP(s) mode and uses the provided ACME server URL or available service (available: letsencrypt)")

	flag.StringVar(&settings.ClientIpHeader, "client-ip-header", settings.ClientIpHeader, "Client HTTP header to fetch their IP address from (X-Real-Ip, X-Client-Ip, X-Forwarded-For, Cf-Connecting-Ip, etc.)")
	flag.StringVar(&settings.BackendIpHeader, "backend-ip-header", settings.BackendIpHeader, "Backend HTTP header to set the client IP address from, if empty defaults to leaving Client header alone (X-Real-Ip, X-Client-Ip, X-Forwarded-For, Cf-Connecting-Ip, etc.)")

	flag.StringVar(&settings.CachePath, "cache", settings.CachePath, "path to temporary cache directory")

	flag.StringVar(&settings.Policy, "policy", settings.Policy, "path to policy YAML file")

	flag.Var(settings.PolicySnippets, "policy-snippets", "path to YAML snippets folder (can be specified multiple times)")

	flag.IntVar(&settings.ChallengeHttpCode, "challenge-http-code", settings.ChallengeHttpCode, "default http-code to use when serving challenges (defaults to 418, I'm a Teapot)")

	flag.StringVar(&settings.ChallengeTemplate, "challenge-template", settings.ChallengeTemplate, "name or path of the challenge template to use (anubis, forgejo)")

	templateTheme := flag.String("challenge-template-theme", settings.ChallengeTemplateOverrides["Theme"], "override template theme to use (forgejo => [forgejo-auto, forgejo-dark, forgejo-light, gitea...])")
	templateLogo := flag.String("challenge-template-logo", settings.ChallengeTemplateOverrides["Logo"], "override template logo to use")

	flag.StringVar(&settings.BasePath, "path", settings.BasePath, "base path where to expose go-away package onto, challenges will be served from here")

	jwtPrivateKeySeed := flag.String("jwt-private-key-seed", "", "Seed for the jwt private key, or on JWT_PRIVATE_KEY_SEED env. One be generated by passing \"generate\" as a value, follows RFC 8032 private key definition. Defaults to random")

	var backends MultiVar
	flag.Var(&backends, "backend", "backend definition in the form of an.example.com=http://backend:1234 (can be specified multiple times)")

	settingsFile := flag.String("config", "", "path to config override YAML file")

	flag.Parse()

	if *settingsFile != "" {
		settings = *loadYamlconfig(settingsFile, &settings)
	}
	if settings.BackendIpHeader == "" {
		settings.BackendIpHeader = settings.ClientIpHeader
	}
	if *settingsFile == "" {
		// preload missing settings
		settings.ChallengeTemplateOverrides["Theme"] = *templateTheme
		settings.ChallengeTemplateOverrides["Logo"] = *templateLogo
		parseCmdbackends(&settings, backends)
	}
	setupBackends(&settings)
	settings.jwtPrivateKeySeed = *jwtPrivateKeySeed

	return settings, *check
}
