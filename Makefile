.PHONY: build test fmt clean dist dist-bins controlpanel docker-prep docker docker-source

build:
	go build -o tyd .

controlpanel:
	go build -o controlpanel ./cmd/controlpanel

test:
	go test ./...
	sh -n scripts/install.sh

fmt:
	go fmt ./...

clean:
	rm -rf tyd controlpanel dist bin

# Host arch for linux container binaries (override: DOCKER_GOARCH=arm64).
DOCKER_GOARCH ?= $(shell go env GOARCH)
# Parallelism for in-Docker source builds (1 keeps peak RAM low on 1C/1G).
GOMAXPROCS ?= 1

# Cross-compile linux binaries for distroless COPY (no Go toolchain in Docker).
docker-prep:
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=$(DOCKER_GOARCH) go build -trimpath -ldflags "-s -w" \
		-o bin/controlpanel ./cmd/controlpanel & \
	CGO_ENABLED=0 GOOS=linux GOARCH=$(DOCKER_GOARCH) go build -trimpath -ldflags "-s -w" \
		-o bin/relay ./cmd/relay & \
	wait

# Fast image build: compile on host (uses Go cache), Docker only packs the binary.
docker: docker-prep
	docker compose build

# Slow path: compile inside the golang image (use on hosts without local Go).
docker-source:
	docker build --target runtime-from-source -f Dockerfile.controlpanel \
		--build-arg GOMAXPROCS=$(GOMAXPROCS) -t tyd-controlpanel:local .

# Six cross-compiled tyd binaries, then one tarball per OS.
# Use `make -j$(nproc) dist` (or `make -j dist`) to compile in parallel.
dist: dist-bins
	@for os in linux darwin freebsd; do \
		tar -C dist -czf dist/tyd-$$os.tar.gz $$os; \
	done
	@ls -lh dist/tyd-*.tar.gz

dist-bins: \
	dist/linux/tyd-amd64 dist/linux/tyd-arm64 \
	dist/darwin/tyd-amd64 dist/darwin/tyd-arm64 \
	dist/freebsd/tyd-amd64 dist/freebsd/tyd-arm64

dist/linux/tyd-amd64:
	mkdir -p dist/linux
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o $@ .
dist/linux/tyd-arm64:
	mkdir -p dist/linux
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o $@ .
dist/darwin/tyd-amd64:
	mkdir -p dist/darwin
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o $@ .
dist/darwin/tyd-arm64:
	mkdir -p dist/darwin
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o $@ .
dist/freebsd/tyd-amd64:
	mkdir -p dist/freebsd
	CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o $@ .
dist/freebsd/tyd-arm64:
	mkdir -p dist/freebsd
	CGO_ENABLED=0 GOOS=freebsd GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o $@ .
