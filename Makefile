###############################################
#
# Makefile
#
###############################################

.DEFAULT_GOAL := build

.PHONY: test

VERSION := 0.1.0

ver:
	@sed -i '' 's/^const Version = "[0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}"/const Version = "${VERSION}"/' src/splunk/splunk.go

lint:
	$(shell go env GOPATH)/bin/golint ./src/...

fmt:
	go fmt ./src/...

vet:
	go vet ./src/...

build:
	go build -v ./src/...

clean:
	go clean ...

demo: build
	go build -o demo cmd/demo.go

test: build
	go test -v -count=1 ./src/...

github:
	open "https://github.com/mlavergn/goupdate"

release:
	zip -r gosplunk.zip LICENSE README.md Makefile cmd src
	hub release create -m "${VERSION} - Go Splunk" -a gosplunk.zip -t master "v${VERSION}"
	open "https://github.com/mlavergn/gosplunk/releases"
