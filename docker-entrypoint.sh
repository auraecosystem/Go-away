#!/bin/sh
set -e

truthy() {
  case "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" in
    1|y|yes|true) return 0 ;;
    *)            return 1 ;;
  esac
}

if [ $# -eq 0 ] || [ "${1#-}" != "$1" ]; then
        set -- /bin/go-away \
                --bind "${GOAWAY_BIND}" --bind-network "${GOAWAY_BIND_NETWORK}" --socket-mode "${GOAWAY_SOCKET_MODE}" \
                --metrics-bind "${GOAWAY_METRICS_BIND}" --debug-bind "${GOAWAY_DEBUG_BIND}" \
                --config "${GOAWAY_CONFIG}" \
                --policy "${GOAWAY_POLICY}" --policy-snippets "/snippets" --policy-snippets "${GOAWAY_POLICY_SNIPPETS}" \
                --client-ip-header "${GOAWAY_CLIENT_IP_HEADER}" --backend-ip-header "${GOAWAY_BACKEND_IP_HEADER}" \
                --cache "${GOAWAY_CACHE}" \
                --challenge-template "${GOAWAY_CHALLENGE_TEMPLATE}" \
                --challenge-template-logo "${GOAWAY_CHALLENGE_TEMPLATE_LOGO}" \
                --challenge-template-theme "${GOAWAY_CHALLENGE_TEMPLATE_THEME}" \
                --slog-level "${GOAWAY_SLOG_LEVEL}" \
                --acme-autocert "${GOAWAY_ACME_AUTOCERT}" \
                --backend "${GOAWAY_BACKEND}" \
                --cookie-samesite "${GOAWAY_COOKIE_SAMESITE}" \
                "$@"
fi

# append conditionally
if truthy "${GOAWAY_COOKIE_SECURE}"; then
	set -- "$@" --cookie-secure
fi
if truthy "${GOAWAY_COOKIE_HTTPONLY}"; then
	set -- "$@" --cookie-httponly
fi

if [ "$1" = "go-away" ]; then
        shift
        set -- /bin/go-away "$@"
fi

exec "$@"
