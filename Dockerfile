ARG from_builder=docker.io/golang:1.26-alpine3.23
ARG from=docker.io/alpine:3.23

ARG BUILDPLATFORM

FROM --platform=$BUILDPLATFORM ${from_builder} AS build

ARG TARGETARCH
ARG TARGETOS
ARG GOTOOLCHAIN=local

RUN apk update && apk add --no-cache \
    bash \
    git \
    zopfli brotli zstd

ENV GOBIN="/go/bin"

COPY . .

RUN ./build-compress.sh

ENV CGO_ENABLED=0
ENV GOOS=${TARGETOS}
ENV GOARCH=${TARGETARCH}
ENV GOTOOLCHAIN=${GOTOOLCHAIN}
ENV BUILDMODE=pie

# riscv64 requires GCC for pie buildmode
# see https://github.com/golang/go/issues/64875
RUN if [[ "$GOARCH" == "riscv64" ]]; then export BUILDMODE=exe; fi && \
    go build -v \
    -pgo=auto \
    -trimpath -ldflags='-buildid= -bindnow' -buildmode $BUILDMODE \
    -o "${GOBIN}/go-away" ./cmd/go-away

RUN test -e "${GOBIN}/go-away"


FROM ${from}

COPY --from=build /go/bin/go-away /bin/go-away
COPY examples/snippets/ /snippets/
COPY docker-entrypoint.sh /

ENV TZ=UTC

ENV GOAWAY_METRICS_BIND=""
ENV GOAWAY_DEBUG_BIND=""

ENV GOAWAY_BIND=":8080"
ENV GOAWAY_BIND_NETWORK="tcp"
ENV GOAWAY_SOCKET_MODE="0770"
ENV GOAWAY_CONFIG=""
ENV GOAWAY_POLICY="/policy.yml"
ENV GOAWAY_POLICY_SNIPPETS=""
ENV GOAWAY_CHALLENGE_TEMPLATE="anubis"
ENV GOAWAY_CHALLENGE_TEMPLATE_THEME=""
ENV GOAWAY_CHALLENGE_TEMPLATE_LOGO=""
ENV GOAWAY_SLOG_LEVEL="WARN"
ENV GOAWAY_CLIENT_IP_HEADER=""
ENV GOAWAY_BACKEND_IP_HEADER=""
ENV GOAWAY_BACKEND=""
ENV GOAWAY_ACME_AUTOCERT=""
ENV GOAWAY_CACHE="/cache"


EXPOSE 8080/tcp
EXPOSE 8080/udp
EXPOSE 9090/tcp
EXPOSE 6060/tcp

# Use GOAWAY_JWT_PRIVATE_KEY_SEED or JWT_PRIVATE_KEY_SEED secret mount to expose this value to docker

ENTRYPOINT ["/docker-entrypoint.sh"]
