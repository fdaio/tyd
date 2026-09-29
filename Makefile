.PHONY: build install test acceptance fmt clean dist dist-relay dist-bins dist-relay-bins \
	controlpanel relay docker-prep docker docker-source relay-prep relay-image

# GNU prefix. The binary lands in $(DESTDIR)$(PREFIX)/bin/tyd.
# Default PREFIX matches scripts/install.sh, which installs to ~/.local/bin.
# DESTDIR is empty for a normal install and set when staging a package.
PREFIX ?= $(HOME)/.local
DESTDIR ?=

build:
	go build -o tyd ./cmd/tyd

# Host install (empty DESTDIR) also starts the per-user daemon, so the peer
# stays on the relay after the shell exits. DESTDIR only stages the binary.
install: build
	install -d "$(DESTDIR)$(PREFIX)/bin"
	install -m 0755 tyd "$(DESTDIR)$(PREFIX)/bin/tyd"
	@if [ -z "$(DESTDIR)" ]; then TYD_BINDIR="$(PREFIX)/bin" sh scripts/install.sh --service; fi

controlpanel:
	go build -o controlpanel ./cmd/controlpanel

# Dedicated relay. Published as its own archive per os+arch (make dist-relay),
# never inside an install tarball, so `tyd up --relay` is deployable without a Go
# toolchain. List several URLs to run a fleet; see docs/operations.md.
relay:
	go build -o tyd-relay ./cmd/relay

test:
	go test ./...
	sh -n scripts/install.sh
	sh scripts/release_plan_test.sh

# Drives a real daemon through send and read. It starts its own daemon in a
# temporary HOME, so it is separate from `test` and runs in CI on its own.
acceptance:
	sh scripts/acceptance_send_read.sh

fmt:
	go fmt ./...

clean:
	rm -rf tyd tyd-relay controlpanel dist bin

# GOPROXY for the in-image `go mod download` (empty = toolchain default). Set it
# only if this host cannot reach proxy.golang.org:
#   make docker-source GOPROXY=https://your-proxy.example,direct
GOPROXY ?=

# Host arch for linux container binaries (override: DOCKER_GOARCH=arm64).
DOCKER_GOARCH ?= $(shell go env GOARCH)
# Parallelism for in-Docker source builds (1 keeps peak RAM low on 1C/1G).
GOMAXPROCS ?= 1

# Cross-compile the linux Control Panel binary for --target runtime (optional
# fast path). Only the Control Panel image is packed from a prebuilt binary; a
# dedicated relay image is built in-Docker via the compose `relay` service.
docker-prep:
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=$(DOCKER_GOARCH) go build -trimpath -ldflags "-s -w" \
		-o bin/controlpanel ./cmd/controlpanel

# Fast image: host Go compile + scratch COPY (separate Dockerfile — classic
# builders run every stage, so prebuilt COPY cannot share the from-source file).
docker: docker-prep
	docker build -f Dockerfile.controlpanel.prebuilt -t tyd-controlpanel:local .
	@echo "built tyd-controlpanel:local (prebuilt). Run: docker compose up -d"

# Same prebuilt path for the relay: no Go toolchain and no module fetch inside
# Docker, so it works on hosts that cannot reach proxy.golang.org. The binary
# can also be lifted from a tyd-relay-<os>-<arch>.tar.gz release asset.
relay-prep:
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=$(DOCKER_GOARCH) go build -trimpath -ldflags "-s -w" \
		-o bin/relay ./cmd/relay

relay-image: relay-prep
	docker build -f Dockerfile.relay.prebuilt -t tyd-relay:local .
	@echo "built tyd-relay:local (prebuilt). Run: docker compose --profile standalone-relay up -d"

# Explicit in-Docker compile (same as default compose Dockerfile).
docker-source:
	docker build -f Dockerfile.controlpanel \
		--build-arg GOMAXPROCS=$(GOMAXPROCS) --build-arg GOPROXY=$(GOPROXY) \
		-t tyd-controlpanel:local .

# One archive per os+arch, each holding only the tyd binary the installer on
# that platform actually runs. install.sh downloads a single file, so a shared
# per-OS tarball made every user pull the other architecture (and the relay)
# for nothing: 12.4MB per install versus 3.7MB now. The os+arch is already in
# the file name, so the archive itself holds a bare tyd.
# The relay is a fleet component nobody installs through install.sh, so it is
# packaged separately by `make dist-relay`.
# Use `make -j$(nproc) dist` (or `make -j dist`) to compile in parallel.
dist: dist-bins
	@for os in linux darwin freebsd; do \
		for arch in amd64 arm64; do \
			tar -C dist/$$os-$$arch -czf dist/tyd-$$os-$$arch.tar.gz tyd; \
		done; \
	done
	@ls -lh dist/tyd-*.tar.gz

# Dedicated relay, one archive per os+arch. Not part of an install; see
# docs/operations.md for running a fleet.
dist-relay: dist-relay-bins
	@for os in linux darwin freebsd; do \
		for arch in amd64 arm64; do \
			tar -C dist/$$os-$$arch -czf dist/tyd-relay-$$os-$$arch.tar.gz tyd-relay; \
		done; \
	done
	@ls -lh dist/tyd-relay-*.tar.gz

dist-bins: \
	dist/linux-amd64/tyd \
	dist/linux-arm64/tyd \
	dist/darwin-amd64/tyd \
	dist/darwin-arm64/tyd \
	dist/freebsd-amd64/tyd \
	dist/freebsd-arm64/tyd

dist-relay-bins: \
	dist/linux-amd64/tyd-relay \
	dist/linux-arm64/tyd-relay \
	dist/darwin-amd64/tyd-relay \
	dist/darwin-arm64/tyd-relay \
	dist/freebsd-amd64/tyd-relay \
	dist/freebsd-arm64/tyd-relay

dist/linux-amd64/tyd:
	mkdir -p dist/linux-amd64
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o $@ ./cmd/tyd
dist/linux-amd64/tyd-relay:
	mkdir -p dist/linux-amd64
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o $@ ./cmd/relay

dist/linux-arm64/tyd:
	mkdir -p dist/linux-arm64
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o $@ ./cmd/tyd
dist/linux-arm64/tyd-relay:
	mkdir -p dist/linux-arm64
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o $@ ./cmd/relay

dist/darwin-amd64/tyd:
	mkdir -p dist/darwin-amd64
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o $@ ./cmd/tyd
dist/darwin-amd64/tyd-relay:
	mkdir -p dist/darwin-amd64
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o $@ ./cmd/relay

dist/darwin-arm64/tyd:
	mkdir -p dist/darwin-arm64
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o $@ ./cmd/tyd
dist/darwin-arm64/tyd-relay:
	mkdir -p dist/darwin-arm64
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o $@ ./cmd/relay

dist/freebsd-amd64/tyd:
	mkdir -p dist/freebsd-amd64
	CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o $@ ./cmd/tyd
dist/freebsd-amd64/tyd-relay:
	mkdir -p dist/freebsd-amd64
	CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o $@ ./cmd/relay

dist/freebsd-arm64/tyd:
	mkdir -p dist/freebsd-arm64
	CGO_ENABLED=0 GOOS=freebsd GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o $@ ./cmd/tyd
dist/freebsd-arm64/tyd-relay:
	mkdir -p dist/freebsd-arm64
	CGO_ENABLED=0 GOOS=freebsd GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o $@ ./cmd/relay
