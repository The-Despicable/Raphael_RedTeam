BIN := bin/broadscan

.PHONY: all build test clean

all: build

build:
	@mkdir -p bin
	go build -trimpath -ldflags="-s -w" -o $(BIN) .

test:
	go vet ./...

clean:
	rm -rf bin
