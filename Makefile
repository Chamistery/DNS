BIN := bin/dnsd

.PHONY: build run test clean

build:
	go build -o $(BIN) ./cmd/dnsd

run: build
	./$(BIN) -config dns.conf -listen 127.0.0.1:5300

test:
	go test ./...

clean:
	rm -rf bin
