.PHONY: build install test fmt clean dist dist-bins controlpanel docker-prep docker docker-source

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

# Explicit in-Docker compile (same as default compose Dockerfile).
docker-source:
	docker build -f Dockerfile.controlpanel \
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
