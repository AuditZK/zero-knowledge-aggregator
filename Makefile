.PHONY: build run test clean

build:
	go build -o bin/enclave ./cmd/enclave

run:
	ENV=development go run ./cmd/enclave

test:
	go test ./... -v

clean:
	rm -rf bin/

lint:
	golangci-lint run ./...

docker-build:
	docker build -t enclave:latest .
