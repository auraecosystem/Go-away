.phony: build vulncheck
vulncheck:
	go mod tidy
	go install golang.org/x/vuln/cmd/govulncheck@latest
	govulncheck -show verbose ./...

build:
	docker build -t go-away .
