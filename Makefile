.PHONY: build install test fmt clean dist dist-bins dist-relay-bins controlpanel relay \
	docker-prep docker docker-source relay-prep relay-image

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

# Dedicated relay. Shipped in the release tarballs (see dist-relay-bins) so
# `tyd up --relay` is deployable without a Go toolchain. List several URLs to
# run a fleet; see docs/operations.md.
relay:
	go build -o tyd-relay ./cmd/relay

test:
	go test ./...
	sh -n scripts/install.sh
	sh scripts/release_plan_test.sh

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
# can also be lifted from a release tarball instead of compiled here.
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

# Twelve cross-compiled binaries (tyd + tyd-relay per os/arch), then one
# tarball per OS. install.sh only lifts out $os/tyd-$arch, so the extra relay
# binary rides along without touching the installer.
# Use `make -j$(nproc) dist` (or `make -j dist`) to compile in parallel.
dist: dist-bins dist-relay-bins
	@for os in linux darwin freebsd; do \
		tar -C dist -czf dist/tyd-$$os.tar.gz $$os; \
	done
	@ls -lh dist/tyd-*.tar.gz

dist-bins: \
	dist/linux/tyd-amd64 dist/linux/tyd-arm64 \
	dist/darwin/tyd-amd64 dist/darwin/tyd-arm64 \
	dist/freebsd/tyd-amd64 dist/freebsd/tyd-arm64

# A dedicated relay is the documented way to run a fleet, so the binary is
# published rather than left behind a Go toolchain.
dist-relay-bins: \
	dist/linux/tyd-relay-amd64 dist/linux/tyd-relay-arm64 \
	dist/darwin/tyd-relay-amd64 dist/darwin/tyd-relay-arm64 \
	dist/freebsd/tyd-relay-amd64 dist/freebsd/tyd-relay-arm64

dist/linux/tyd-amd64:
	mkdir -p dist/linux
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o $@ ./cmd/tyd
dist/linux/tyd-arm64:
	mkdir -p dist/linux
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o $@ ./cmd/tyd
dist/darwin/tyd-amd64:
	mkdir -p dist/darwin
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o $@ ./cmd/tyd
dist/darwin/tyd-arm64:
	mkdir -p dist/darwin
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o $@ ./cmd/tyd
dist/freebsd/tyd-amd64:
	mkdir -p dist/freebsd
	CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o $@ ./cmd/tyd
dist/freebsd/tyd-arm64:
	mkdir -p dist/freebsd
	CGO_ENABLED=0 GOOS=freebsd GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o $@ ./cmd/tyd

dist/linux/tyd-relay-amd64:
	mkdir -p dist/linux
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o $@ ./cmd/relay
dist/linux/tyd-relay-arm64:
	mkdir -p dist/linux
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o $@ ./cmd/relay
dist/darwin/tyd-relay-amd64:
	mkdir -p dist/darwin
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o $@ ./cmd/relay
dist/darwin/tyd-relay-arm64:
	mkdir -p dist/darwin
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o $@ ./cmd/relay
dist/freebsd/tyd-relay-amd64:
	mkdir -p dist/freebsd
	CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o $@ ./cmd/relay
dist/freebsd/tyd-relay-arm64:
	mkdir -p dist/freebsd
	CGO_ENABLED=0 GOOS=freebsd GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o $@ ./cmd/relay
