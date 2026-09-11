.PHONY: build test fmt clean

build:
	go build -o tyd .

test:
	go test ./...

fmt:
	go fmt ./...

clean:
	rm -f tyd
