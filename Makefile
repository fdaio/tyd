.PHONY: build test fmt clean dist

build:
	go build -o tyd .

test:
	go test ./...

fmt:
	go fmt ./...

clean:
	rm -rf tyd dist

# Three TTY-platform releases (linux, darwin, freebsd), each with amd64 and arm64.
GOOS_LIST := linux darwin freebsd
GOARCH_LIST := amd64 arm64

dist:
	rm -rf dist
	mkdir -p dist
	@for os in $(GOOS_LIST); do \
		mkdir -p dist/$$os; \
		for arch in $(GOARCH_LIST); do \
			echo "==> $$os/$$arch"; \
			CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "-s -w" -o dist/$$os/tyd-$$arch .; \
		done; \
		tar -C dist -czf dist/tyd-$$os.tar.gz $$os; \
	done
