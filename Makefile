build:
	go build -o bin/sshlm cmd/sshlm/main.go

run:
	go run cmd/sshlm/main.go -l test/secure.log -d test/fingerprints.db -o log

all: build