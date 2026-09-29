.PHONY: test cover lint fmt generate build

test:
	go test -count=1 ./...

cover:
	go test -count=1 -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -n 1

lint:
	go vet ./...
	gofmt -l .

fmt:
	gofmt -w .

# Regenerate internal/metadata from metadata.yaml.
generate:
	go run go.opentelemetry.io/collector/cmd/mdatagen@v0.160.0 metadata.yaml

# Build a collector that includes this receiver, using the local checkout.
build:
	go run go.opentelemetry.io/collector/cmd/builder@v0.160.0 --config builder-config.yaml
