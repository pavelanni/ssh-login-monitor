build:
	go build -o bin/slm cmd/slm/main.go

run:
	go run cmd/slm/main.go -l test/secure.log -d test/fingerprints.db -o log

all: build