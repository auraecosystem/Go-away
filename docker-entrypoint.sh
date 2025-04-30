#!/bin/sh
set -e

if [ $# -eq 0 ] || [ "${1#-}" != "$1" ]; then
        set -- /bin/go-away \
                --bind "${GOAWAY_BIND}" --bind-network "${GOAWAY_BIND_NETWORK}" --socket-mode "${GOAWAY_SOCKET_MODE}" \
                --metrics-bind "${GOAWAY_METRICS_BIND}" --debug-bind "${GOAWAY_DEBUG_BIND}" \
                --config "${GOAWAY_CONFIG}" \
                --policy "${GOAWAY_POLICY}" --policy-snippets "/snippets" --policy-snippets "${GOAWAY_POLICY_SNIPPETS}" \
                --client-ip-header "${GOAWAY_CLIENT_IP_HEADER}" --backend-ip-header "${GOAWAY_BACKEND_IP_HEADER}" \
                --cache "${GOAWAY_CACHE}" \
                --challenge-template "${GOAWAY_CHALLENGE_TEMPLATE}" --challenge-template-theme "${GOAWAY_CHALLENGE_TEMPLATE_THEME}" \
                --slog-level "${GOAWAY_SLOG_LEVEL}" \
                --acme-autocert "${GOAWAY_ACME_AUTOCERT}" \
                --backend "${GOAWAY_BACKEND}" \
                "$@"
fi

if [ "$1" = "go-away" ]; then
        shift
        set -- /bin/go-away "$@"
fi

exec "$@"
