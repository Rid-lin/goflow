PWD := $(shell pwd)
VERSION := $(shell git describe --tags)
BUILD := $(shell git rev-parse --short HEAD)
PROJECTNAME := $(shell basename $(PWD))
GOOS := linux
GOARCH := amd64
TAG := $(VERSION)_$(GOOS)_$(GOARCH)
PLATFORMS=darwin linux windows
#ARCHITECTURES=386 amd64
ARCHITECTURES=amd64

# Use linker flags to provide version/build settings
# LDFLAGS=-ldflags "-w -s -X=main.Version=$(VERSION) -X=main.Build=$(BUILD)"
LDFLAGS=-ldflags "-w -s"

.PHONY: build

build: buildwithoutdebug_linux pack

buildfordebug:
	go build -o build/$(PROJECTNAME)_$(TAG).exe -v ./

buildwithoutdebug:
	go build $(LDFLAGS) -o build/$(PROJECTNAME)_$(TAG).exe -v ./

buildwodebug_linux:
	set GOOS=linux&&go build $(LDFLAGS) -o build/$(PROJECTNAME)_$(TAG) -v ./cmd/cnetflow/

buildwithoutdebug_linux:
	@set GOARCH=$(GOARCH)&&set GOOS=$(GOOS)
	@go build $(LDFLAGS) -o build/$(PROJECTNAME)_$(VERSION)_$(GOOS)_$(GOARCH) -v ./cmd/cnetflow/

prebuild_all:
	$(foreach GOOS, $(PLATFORMS),\
	$(foreach GOARCH, $(ARCHITECTURES), $(shell export GOOS=$(GOOS); export GOARCH=$(GOARCH); go build -v $(LDFLAGS) -o build/$(PROJECTNAME)_$(VERSION)_$(GOOS)_$(GOARCH) -v ./cmd/cnetflow/)))

build_all: prebuild_all pack

run: build
	build/$(PROJECTNAME)_$(TAG).exe
	
.DUFAULT_GOAL := build

pack:
	upx --ultra-brute build/$(PROJECTNAME)*

mod:
	go mod tidy
	go mod download
	go mod vendor